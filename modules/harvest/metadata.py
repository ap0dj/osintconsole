import os
import io
import re
import zipfile
import xml.etree.ElementTree as ET

import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from core import http
from core.base_module import BaseModule
from core.utils import print_status
from core.config import Config

# pypdf is OPTIONAL: when present we get structured /Info + XMP metadata from
# modern (compressed-xref) PDFs; when absent we fall back to a raw-byte regex
# scan so the module still degrades gracefully instead of crashing on import.
try:
    import pypdf
    HAS_PYPDF = True
except ImportError:
    HAS_PYPDF = False


# OOXML (Office Open XML) containers: these are ZIP archives whose real author /
# company / timestamps live in docProps/*.xml INSIDE the zip. Legacy binary
# .doc/.xls/.ppt are OLE compound files (not zips) and fall through to the
# generic byte scan.
OFFICE_EXTS = {
    "docx", "docm", "dotx", "dotm",
    "xlsx", "xlsm", "xltx", "xltm", "xlsb",
    "pptx", "pptm", "potx", "potm", "ppsx", "ppsm",
}

# Namespaces used by docProps/core.xml (Dublin Core + OPC core-properties).
_DC = "http://purl.org/dc/elements/1.1/"
_DCTERMS = "http://purl.org/dc/terms/"
_CP = "http://schemas.openxmlformats.org/package/2006/metadata/core-properties"

# Fully-qualified core.xml tag -> friendly field name. Anything not listed is
# still reported, using its local (namespace-stripped) tag name, so we never
# silently drop a field the file actually carries.
_CORE_MAP = {
    f"{{{_DC}}}title": "Title",
    f"{{{_DC}}}subject": "Subject",
    f"{{{_DC}}}creator": "Author",
    f"{{{_DC}}}description": "Description",
    f"{{{_DC}}}language": "Language",
    f"{{{_DC}}}identifier": "Identifier",
    f"{{{_CP}}}keywords": "Keywords",
    f"{{{_CP}}}lastModifiedBy": "LastModifiedBy",
    f"{{{_CP}}}revision": "Revision",
    f"{{{_CP}}}category": "Category",
    f"{{{_CP}}}contentStatus": "ContentStatus",
    f"{{{_DCTERMS}}}created": "Created",
    f"{{{_DCTERMS}}}modified": "Modified",
}


def _coerce(val):
    """Flatten a pypdf XMP value (dict{lang:text} / list / datetime) to text."""
    if val is None:
        return ""
    if isinstance(val, dict):
        val = " ".join(str(v) for v in val.values() if v)
    elif isinstance(val, (list, tuple, set)):
        val = ", ".join(str(v) for v in val if v)
    return str(val).strip()


class Metadata(BaseModule):
    name = "harvest/metadata"
    description = "Metadata extraction from documents found on target domain"
    category = "harvest"
    target_type = "domain/file"

    def _register_options(self):
        self.add_option("TARGET", "", True, "Target domain or local file path")
        self.add_option("FILE_TYPES", "pdf,doc,docx,xls,xlsx,ppt,pptx", False, "File types to search")
        self.add_option("MAX_FILES", "20", False, "Maximum files to download and analyze")

    def _find_documents(self, domain, file_types):
        config = Config()
        docs = set()
        headers = {"User-Agent": config.get("user_agent")}
        extensions = file_types.split(",")

        try:
            resp = http.get(f"https://{domain}", headers=headers,
                            timeout=10)
            soup = BeautifulSoup(resp.text, "html.parser")
            for a in soup.find_all("a", href=True):
                href = a["href"].lower()
                for ext in extensions:
                    if href.endswith(f".{ext.strip()}"):
                        full_url = urljoin(f"https://{domain}", a["href"])
                        docs.add(full_url)
        except Exception:
            pass

        for ext in extensions:
            try:
                search_url = f"https://www.bing.com/search?q=site:{domain}+filetype:{ext.strip()}"
                resp = requests.get(search_url, headers=headers, timeout=10)
                soup = BeautifulSoup(resp.text, "html.parser")
                for a in soup.find_all("a", href=True):
                    href = a["href"]
                    if href.endswith(f".{ext.strip()}") and domain in href:
                        docs.add(href)
            except Exception:
                pass

        return list(docs)

    # ------------------------------------------------------------------ #
    # Dispatch
    # ------------------------------------------------------------------ #
    def _analyze(self, content, filename):
        """Route raw bytes to the best extractor for the file type."""
        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        if ext == "pdf":
            return self._extract_pdf_metadata(content)
        if ext in OFFICE_EXTS:
            meta = self._extract_office_metadata(content, filename)
            if meta is not None:
                return meta
            # Extension said Office but bytes are not a valid zip -> fall back.
        return self._extract_generic_metadata(content, filename)

    # ------------------------------------------------------------------ #
    # Office (OOXML) via stdlib zipfile + ElementTree -- no extra deps.
    # ------------------------------------------------------------------ #
    def _parse_opc_xml(self, raw, tag_map):
        """Parse a docProps/*.xml part into {field: text}.

        Only leaf elements with text are reported; structured app.xml parts
        (HeadingPairs / TitlesOfParts vectors) are skipped rather than dumped.
        """
        out = {}
        try:
            root = ET.fromstring(raw)
        except Exception:
            return out
        for child in root:
            if len(child) > 0:  # has element children -> structured, skip
                continue
            text = (child.text or "").strip()
            if not text:
                continue
            name = tag_map.get(child.tag) or child.tag.rsplit("}", 1)[-1]
            out[name] = text
        return out

    def _extract_office_metadata(self, content, filename):
        """Return every field found in docProps/core.xml + docProps/app.xml.

        Returns None when the bytes are not a valid zip (so the caller can fall
        back), {filename, size_bytes, note} when it is a valid package with no
        metadata parts, and the populated dict otherwise.
        """
        try:
            zf = zipfile.ZipFile(io.BytesIO(content))
        except Exception:
            # BadZipFile or anything else -> not an OOXML package.
            return None

        meta = {"filename": filename, "size_bytes": len(content)}
        try:
            names = set(zf.namelist())
            for part, tmap in (("docProps/core.xml", _CORE_MAP),
                               ("docProps/app.xml", {})):
                if part in names:
                    try:
                        meta.update(self._parse_opc_xml(zf.read(part), tmap))
                    except Exception:
                        pass
        except Exception:
            pass
        finally:
            try:
                zf.close()
            except Exception:
                pass

        if len(meta) <= 2:  # only filename + size_bytes -> nothing real found
            meta["note"] = "valid Office package but no document metadata present"
        return meta

    # ------------------------------------------------------------------ #
    # PDF: pypdf when available, raw-byte regex scan as a fallback.
    # ------------------------------------------------------------------ #
    def _extract_pdf_metadata(self, content):
        """Public entry kept stable for run(); dispatches pypdf -> regex."""
        if HAS_PYPDF:
            meta = self._extract_pdf_pypdf(content)
            if meta is not None:
                return meta
            # pypdf could not parse the file -> last-resort regex scan.
        return self._extract_pdf_regex(content)

    def _extract_pdf_pypdf(self, content):
        """Structured /Info + XMP via pypdf. Returns None if the file won't parse."""
        try:
            reader = pypdf.PdfReader(io.BytesIO(content))
        except Exception:
            return None

        meta = {}
        try:
            info = reader.metadata
            if info:
                field_map = {
                    "/Title": "Title", "/Author": "Author", "/Subject": "Subject",
                    "/Creator": "Creator", "/Producer": "Producer",
                    "/Keywords": "Keywords", "/CreationDate": "CreationDate",
                    "/ModDate": "ModDate", "/Company": "Company",
                    "/Category": "Category", "/Manager": "Manager",
                }
                for key, value in info.items():
                    text = _coerce(value)
                    if not text:
                        continue
                    name = field_map.get(key, str(key).lstrip("/"))
                    meta[name] = text
        except Exception:
            pass

        try:
            meta["Pages"] = str(len(reader.pages))
        except Exception:
            pass

        # XMP (Adobe metadata packet) -- present on many modern PDFs.
        try:
            xmp = reader.xmp_metadata
        except Exception:
            xmp = None
        if xmp is not None:
            for attr, label in (
                ("dc_title", "xmp_title"),
                ("dc_creator", "xmp_creator"),
                ("dc_description", "xmp_description"),
                ("dc_subject", "xmp_subject"),
                ("pdf_producer", "xmp_producer"),
                ("pdf_keywords", "xmp_keywords"),
                ("xmp_creatorTool", "xmp_creatorTool"),
                ("xmp_createDate", "xmp_createDate"),
                ("xmp_modifyDate", "xmp_modifyDate"),
            ):
                try:
                    text = _coerce(getattr(xmp, attr, None))
                except Exception:
                    text = ""
                if text:
                    meta[label] = text

        if not meta:
            meta["note"] = "no metadata present in PDF"
        return meta

    def _extract_pdf_regex(self, content):
        """Fallback: scan raw bytes for /Info dictionary string values."""
        metadata = {}
        try:
            text = content.decode("latin-1", errors="ignore")
            patterns = {
                "Title": r'/Title\s*\((.*?)\)',
                "Author": r'/Author\s*\((.*?)\)',
                "Creator": r'/Creator\s*\((.*?)\)',
                "Producer": r'/Producer\s*\((.*?)\)',
                "CreationDate": r'/CreationDate\s*\((.*?)\)',
                "ModDate": r'/ModDate\s*\((.*?)\)',
                "Subject": r'/Subject\s*\((.*?)\)',
                "Keywords": r'/Keywords\s*\((.*?)\)',
            }
            for key, pattern in patterns.items():
                match = re.search(pattern, text)
                if match:
                    metadata[key] = match.group(1)
        except Exception:
            pass
        if not metadata:
            metadata["note"] = "no metadata found (regex fallback; install pypdf for full parsing)"
        return metadata

    def _extract_generic_metadata(self, content, filename):
        metadata = {"filename": filename, "size_bytes": len(content)}
        text = content[:4096].decode("latin-1", errors="ignore")
        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text)
        if emails:
            metadata["emails_in_metadata"] = list(set(emails))
        paths = re.findall(r'[A-Z]:\\[^\x00-\x1f"<>|*?]+', text)
        paths += re.findall(r'/(?:home|Users)/[^\x00-\x1f"<>|*?]+', text)
        if paths:
            metadata["file_paths"] = list(set(paths))[:10]
        usernames = re.findall(r'(?:author|creator|user)[:\s]+([a-zA-Z0-9._-]+)', text, re.IGNORECASE)
        if usernames:
            metadata["possible_usernames"] = list(set(usernames))
        return metadata

    def run(self):
        if not self.validate():
            return False

        target = self.get_option("TARGET")
        file_types = self.get_option("FILE_TYPES") or "pdf,doc,docx,xls,xlsx"
        max_files = int(self.get_option("MAX_FILES") or 20)
        config = Config()

        if os.path.isfile(target):
            print_status(f"Analyzing local file: {target}", "info")
            try:
                with open(target, "rb") as f:
                    content = f.read()
            except Exception as e:
                note = f"could not read file: {e}"
                print_status(note, "error")
                self.results = {"target": target, "type": "local_file",
                                "error": note, "metadata": {}}
                return True
            meta = self._analyze(content, os.path.basename(target))
            self.results = {"target": target, "type": "local_file", "metadata": meta}
            for k, v in meta.items():
                print_status(f"{k}: {v}", "success")
            return True

        print_status(f"Finding documents on {target}", "info")
        doc_urls = self._find_documents(target, file_types)
        print_status(f"Found {len(doc_urls)} documents", "info")

        all_metadata = []
        headers = {"User-Agent": config.get("user_agent")}

        for url in doc_urls[:max_files]:
            try:
                print_status(f"Downloading: {url}", "info")
                resp = http.get(url, headers=headers, timeout=15,
                                stream=True)
                content = resp.content[:5 * 1024 * 1024]

                filename = url.split("/")[-1].split("?")[0]
                meta = self._analyze(content, filename)

                meta["source_url"] = url
                all_metadata.append(meta)

                for k, v in meta.items():
                    if k != "source_url":
                        print_status(f"  {k}: {v}", "success")
            except Exception as e:
                print_status(f"Failed to analyze {url}: {e}", "warning")

        unique_authors = set()
        unique_emails = set()
        unique_software = set()
        for m in all_metadata:
            if m.get("Author"):
                unique_authors.add(m["Author"])
            if m.get("LastModifiedBy"):
                unique_authors.add(m["LastModifiedBy"])
            if m.get("Creator"):
                unique_software.add(m["Creator"])
            if m.get("Producer"):
                unique_software.add(m["Producer"])
            if m.get("Application"):
                unique_software.add(m["Application"])
            if m.get("emails_in_metadata"):
                unique_emails.update(m["emails_in_metadata"])

        self.results = {
            "target": target,
            "documents_found": len(doc_urls),
            "documents_analyzed": len(all_metadata),
            "metadata": all_metadata,
            "unique_authors": sorted(list(unique_authors)),
            "unique_emails": sorted(list(unique_emails)),
            "unique_software": sorted(list(unique_software)),
        }

        print_status(f"Metadata extraction complete. Analyzed {len(all_metadata)} documents", "info")
        return True

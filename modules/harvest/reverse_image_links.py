"""Reverse-image search aggregator.

Given a local image OR an image URL, generate direct search links for the
major reverse-image engines (TinEye, Google Lens, Yandex, Bing, Baidu,
SauceNAO) and extract local metadata (EXIF + GPS, perceptual hash, dimensions)
that an analyst can cross-reference across those engines.

Engines block scrapers, so this module does NOT parse their results - it
hands the operator a list of clickable URLs.
"""
import io
import os
import hashlib
from urllib.parse import quote_plus

from core.base_module import BaseModule
from core.utils import print_status, Colors
from core import http

try:
    from PIL import Image, ExifTags
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

try:
    import imagehash
    HAS_IMAGEHASH = True
except ImportError:
    HAS_IMAGEHASH = False


MAX_BYTES = 40 * 1024 * 1024
MAGIC_SAMPLE_BYTES = 32 * 1024

ENGINE_IDS = ["tineye", "google", "yandex", "bing", "baidu", "saucenao"]
ENGINE_LABELS = {
    "tineye": "TinEye", "google": "Google Lens", "yandex": "Yandex Images",
    "bing": "Bing Visual", "baidu": "Baidu Images", "saucenao": "SauceNAO",
}

# Magic signatures for common image formats, used when we only have a URL
# and want to sanity-check what the server actually returned.
MAGIC_SIGNATURES = [
    (b"\xff\xd8\xff", "JPEG"), (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"GIF87a", "GIF"), (b"GIF89a", "GIF"), (b"BM", "BMP"),
    (b"RIFF", "WEBP"), (b"II*\x00", "TIFF"), (b"MM\x00*", "TIFF"),
    (b"\x00\x00\x01\x00", "ICO"), (b"<svg", "SVG"), (b"<?xml", "SVG"),
]


def _ratio(value):
    """Convert an EXIF rational (IFDRational, tuple, int, float) to float."""
    try:
        return float(value)
    except (TypeError, ValueError, ZeroDivisionError):
        try:
            return value[0] / value[1]
        except Exception:
            return 0.0


def _clean(value):
    """Normalize an EXIF value to a trimmed string, or None."""
    if value is None:
        return None
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8", "replace")
        except Exception:
            value = repr(value)
    s = str(value).strip().strip("\x00").strip()
    return s or None


def _sniff_magic(sample):
    if not sample:
        return None
    for sig, name in MAGIC_SIGNATURES:
        if sample.startswith(sig):
            if name == "WEBP" and sample[8:12] != b"WEBP":
                continue
            return name
    return None


class ReverseImageLinks(BaseModule):
    """Reverse-image search URL aggregator + local metadata for pivoting."""

    name = "harvest/reverse_image_links"
    description = "Reverse-image search links (TinEye/Google/Yandex/Bing/Baidu/SauceNAO) + pivot metadata"
    category = "harvest"
    target_type = "image"

    def _register_options(self):
        self.add_option("TARGET", "", True, "Local image file path or http(s) image URL")
        self.add_option("ENGINES", "all", False,
                        "Comma list: tineye,google,yandex,bing,baidu,saucenao (or 'all')")
        self.add_option("EXTRACT_EXIF", "true", False, "Extract EXIF metadata (needs Pillow)")
        self.add_option("COMPUTE_PHASH", "true", False, "Compute perceptual hash (needs imagehash)")

    # ---------- input routing ---------------------------------------------

    def _detect_input_type(self, target):
        if target.lower().startswith(("http://", "https://")):
            return "url"
        if os.path.isfile(target):
            return "file"
        return None

    def _selected_engines(self):
        raw = (self.get_option("ENGINES") or "all").strip().lower()
        if raw in ("", "all", "*"):
            return list(ENGINE_IDS)
        wanted = [e.strip() for e in raw.split(",") if e.strip()]
        return [e for e in wanted if e in ENGINE_IDS]

    def _build_search_urls(self, image_url, engines):
        if not image_url:
            return {}
        enc = quote_plus(image_url)
        all_urls = {
            "tineye": f"https://tineye.com/search?url={enc}",
            "google": f"https://lens.google.com/uploadbyurl?url={enc}",
            "yandex": f"https://yandex.com/images/search?rpt=imageview&url={enc}",
            "bing": f"https://www.bing.com/images/search?view=detailv2&iss=sbi&q=imgurl:{enc}",
            "baidu": f"http://image.baidu.com/pcdutu?queryImageUrl={enc}",
            "saucenao": f"https://saucenao.com/search.php?url={enc}",
        }
        return {k: v for k, v in all_urls.items() if k in engines}

    # ---------- byte loaders ----------------------------------------------

    def _load_local(self, path):
        try:
            size = os.path.getsize(path)
        except OSError as e:
            return None, 0, f"could not stat file: {e}"
        if size > MAX_BYTES:
            return None, size, "file too large to process"
        try:
            with open(path, "rb") as f:
                return f.read(), size, ""
        except Exception as e:
            return None, size, f"could not read file: {e}"

    def _probe_remote(self, url):
        """HEAD + partial GET to learn content-type, size, and magic bytes."""
        info = {"size_bytes": None, "content_type": None, "magic": None, "warning": None}
        try:
            h = http.head(url, timeout=15, allow_redirects=True)
            if h is not None and h.status_code < 400:
                info["content_type"] = h.headers.get("Content-Type")
                cl = h.headers.get("Content-Length")
                if cl and cl.isdigit():
                    info["size_bytes"] = int(cl)
        except Exception as e:
            info["warning"] = f"HEAD failed: {e}"
        try:
            resp = http.get(url, timeout=20, stream=True,
                            headers={"Range": f"bytes=0-{MAGIC_SAMPLE_BYTES - 1}"})
            if resp is not None and resp.status_code < 400:
                sample = (resp.raw.read(MAGIC_SAMPLE_BYTES)
                          if hasattr(resp, "raw") else resp.content[:MAGIC_SAMPLE_BYTES])
                info["magic"] = _sniff_magic(sample)
                if not info["content_type"]:
                    info["content_type"] = resp.headers.get("Content-Type")
                if info["size_bytes"] is None:
                    cr = resp.headers.get("Content-Range", "")
                    if "/" in cr and cr.split("/")[-1].isdigit():
                        info["size_bytes"] = int(cr.split("/")[-1])
        except Exception as e:
            info["warning"] = (info["warning"] + "; " if info["warning"] else "") + f"range GET failed: {e}"
        return info

    def _download_full(self, url):
        try:
            resp = http.get(url, timeout=30)
        except Exception as e:
            return None, f"download failed: {e}"
        if resp.status_code != 200:
            return None, f"download returned HTTP {resp.status_code}"
        content = resp.content or b""
        if len(content) > MAX_BYTES:
            return None, "image too large to process"
        return content, ""

    # ---------- hashing + EXIF --------------------------------------------

    def _compute_hashes(self, content, want_phash):
        md5 = hashlib.md5(content).hexdigest() if content else None
        phash = None
        if want_phash and HAS_IMAGEHASH and HAS_PIL and content:
            try:
                with Image.open(io.BytesIO(content)) as im:
                    phash = str(imagehash.phash(im))
            except Exception:
                phash = None
        return md5, phash

    def _dms_to_decimal(self, dms, ref):
        try:
            deg, minute, sec = _ratio(dms[0]), _ratio(dms[1]), _ratio(dms[2])
            dec = deg + minute / 60.0 + sec / 3600.0
            if str(ref).upper().startswith(("S", "W")):
                dec = -dec
            return round(dec, 6)
        except Exception:
            return None

    def _parse_gps(self, gps_raw):
        if not gps_raw or not isinstance(gps_raw, dict):
            return None
        gps = {ExifTags.GPSTAGS.get(k, k): v for k, v in gps_raw.items()}
        lat, lat_ref = gps.get("GPSLatitude"), gps.get("GPSLatitudeRef")
        lon, lon_ref = gps.get("GPSLongitude"), gps.get("GPSLongitudeRef")
        alt, alt_ref = gps.get("GPSAltitude"), gps.get("GPSAltitudeRef")
        if not (lat and lon and lat_ref and lon_ref):
            return None
        lat_dec = self._dms_to_decimal(lat, lat_ref)
        lng_dec = self._dms_to_decimal(lon, lon_ref)
        if lat_dec is None or lng_dec is None:
            return None
        altitude = None
        if alt is not None:
            try:
                altitude = _ratio(alt)
                if alt_ref in (1, b"\x01"):
                    altitude = -altitude
            except Exception:
                altitude = None
        return {"lat": lat_dec, "lng": lng_dec, "altitude": altitude,
                "maps_url": f"https://maps.google.com/?q={lat_dec},{lng_dec}"}

    def _extract_exif_summary(self, img):
        info = {"make": None, "model": None, "lens": None, "software": None,
                "datetime_original": None, "orientation": None, "gps": None}
        gps_raw = None
        try:
            exif = img.getexif()
        except Exception:
            return info
        if not exif:
            return info
        for tag_id, value in exif.items():
            name = ExifTags.TAGS.get(tag_id, str(tag_id))
            if name == "Make":
                info["make"] = _clean(value)
            elif name == "Model":
                info["model"] = _clean(value)
            elif name == "Software":
                info["software"] = _clean(value)
            elif name == "Orientation":
                try:
                    info["orientation"] = int(value)
                except Exception:
                    pass
            elif name in ("DateTime", "DateTimeOriginal"):
                info["datetime_original"] = info["datetime_original"] or _clean(value)
        try:
            sub = exif.get_ifd(ExifTags.IFD.Exif)
            for tag_id, value in sub.items():
                name = ExifTags.TAGS.get(tag_id, str(tag_id))
                if name == "DateTimeOriginal":
                    info["datetime_original"] = _clean(value) or info["datetime_original"]
                elif name == "LensModel":
                    info["lens"] = _clean(value)
                elif name == "LensMake" and not info["lens"]:
                    info["lens"] = _clean(value)
        except Exception:
            pass
        try:
            gifd = exif.get_ifd(ExifTags.IFD.GPSInfo)
            if gifd:
                gps_raw = dict(gifd)
        except Exception:
            try:
                legacy = img._getexif() or {}
                for tag_id, value in legacy.items():
                    if ExifTags.TAGS.get(tag_id) == "GPSInfo" and isinstance(value, dict):
                        gps_raw = value
                        break
            except Exception:
                pass
        info["gps"] = self._parse_gps(gps_raw)
        return info

    def _build_pivot_hints(self, exif):
        quotes = []
        for key in ("software", "lens"):
            v = exif.get(key)
            if v and len(v) > 2:
                quotes.append(v)
        if exif.get("datetime_original"):
            quotes.append(exif["datetime_original"])
        fingerprint = None
        make, model, sw = exif.get("make"), exif.get("model"), exif.get("software")
        if make or model:
            fingerprint = " ".join(x for x in (make, model) if x).strip()
            if sw:
                fingerprint = f"{fingerprint} + {sw}"
        elif sw:
            fingerprint = sw
        return {"search_quotes": quotes, "device_fingerprint": fingerprint}

    # ---------- main ------------------------------------------------------

    def run(self):
        if not self.validate():
            return False

        target = self.get_option("TARGET").strip()
        engines = self._selected_engines()
        want_exif = str(self.get_option("EXTRACT_EXIF")).lower() in ("1", "true", "yes", "y")
        want_phash = str(self.get_option("COMPUTE_PHASH")).lower() in ("1", "true", "yes", "y")

        self.results = {
            "target": target, "input_type": None, "search_urls": {},
            "metadata": {"size_bytes": None, "dimensions": None, "format": None,
                         "md5": None, "phash": None, "exif": None},
            "pivot_hints": {"search_quotes": [], "device_fingerprint": None},
            "warnings": [],
        }
        warnings = self.results["warnings"]

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*58}")
        print(f"  Reverse Image Search")
        print(f"  Target: {target}")
        print(f"{'='*58}{Colors.RESET}\n")

        if not engines:
            print_status("No valid engines selected - defaulting to all", "warning")
            engines = list(ENGINE_IDS)

        input_type = self._detect_input_type(target)
        if input_type is None:
            print_status("TARGET is neither an http(s) URL nor an existing local file", "error")
            warnings.append("invalid target")
            return True
        self.results["input_type"] = input_type

        if input_type == "url":
            self.results["search_urls"] = self._build_search_urls(target, engines)
        else:
            print_status("Local file: engines cannot be auto-queried via URL - upload manually at each site", "warning")
            warnings.append("local file - no auto-search URL possible; links provided for manual upload")
            uploads = {
                "tineye": "https://tineye.com/", "google": "https://lens.google.com/",
                "yandex": "https://yandex.com/images/", "bing": "https://www.bing.com/visualsearch",
                "baidu": "https://image.baidu.com/", "saucenao": "https://saucenao.com/",
            }
            self.results["search_urls"] = {k: v for k, v in uploads.items() if k in engines}

        # ---- metadata extraction ----
        content = None
        meta = self.results["metadata"]

        if input_type == "file":
            content, size, err = self._load_local(target)
            meta["size_bytes"] = size
            if err:
                print_status(err, "error")
                warnings.append(err)
        else:
            probe = self._probe_remote(target)
            if probe.get("warning"):
                warnings.append(probe["warning"])
            meta["size_bytes"] = probe.get("size_bytes")
            if probe.get("content_type"):
                print_status(f"Content-Type: {probe['content_type']}", "info")
            if probe.get("magic"):
                meta["format"] = probe["magic"]
                print_status(f"Magic bytes: {probe['magic']}", "info")
            if want_exif or want_phash:
                content, derr = self._download_full(target)
                if derr:
                    print_status(derr, "warning")
                    warnings.append(derr)

        if content:
            md5, phash = self._compute_hashes(content, want_phash)
            meta["md5"] = md5
            meta["phash"] = phash
            if want_phash and not HAS_IMAGEHASH:
                warnings.append("imagehash not installed - skipping pHash (pip install imagehash)")
            if want_exif and HAS_PIL:
                try:
                    img = Image.open(io.BytesIO(content))
                    img.load()
                    meta["dimensions"] = {"width": img.width, "height": img.height}
                    meta["format"] = img.format or meta["format"]
                    meta["exif"] = self._extract_exif_summary(img)
                    self.results["pivot_hints"] = self._build_pivot_hints(meta["exif"])
                except Exception as e:
                    warnings.append(f"image parse failed: {e}")
            elif want_exif and not HAS_PIL:
                warnings.append("Pillow not installed - skipping EXIF (pip install Pillow)")

        # ---- summary ----
        print()
        print_status(f"Input type: {input_type}", "info")
        if meta["size_bytes"] is not None:
            print_status(f"Size: {meta['size_bytes']} bytes", "info")
        if meta["dimensions"]:
            d = meta["dimensions"]
            print_status(f"Dimensions: {d['width']} x {d['height']}", "info")
        if meta["format"]:
            print_status(f"Format: {meta['format']}", "info")
        if meta["md5"]:
            print_status(f"MD5: {meta['md5']}", "success")
        if meta["phash"]:
            print_status(f"pHash: {meta['phash']}", "success")

        exif = meta["exif"] or {}
        if exif.get("make") or exif.get("model"):
            cam = " ".join(x for x in (exif.get("make"), exif.get("model")) if x)
            print_status(f"Camera: {cam}", "success")
        if exif.get("lens"):
            print_status(f"Lens: {exif['lens']}", "success")
        if exif.get("software"):
            print_status(f"Software: {exif['software']}", "success")
        if exif.get("datetime_original"):
            print_status(f"Captured: {exif['datetime_original']}", "success")
        if exif.get("orientation") is not None:
            print_status(f"Orientation: {exif['orientation']}", "info")
        gps = exif.get("gps")
        if gps:
            print_status(f"GPS: {gps['lat']}, {gps['lng']}", "success")
            if gps.get("altitude") is not None:
                print_status(f"Altitude: {gps['altitude']} m", "info")
            print_status(f"Map: {gps['maps_url']}", "success")

        fp = self.results["pivot_hints"].get("device_fingerprint")
        if fp:
            print_status(f"Device fingerprint: {fp}", "success")

        # Engine URL list.
        print()
        print(f"{Colors.BOLD}{Colors.MAGENTA}  Reverse-search engines ({len(self.results['search_urls'])}):{Colors.RESET}")
        for eid in ENGINE_IDS:
            if eid not in self.results["search_urls"]:
                continue
            label = ENGINE_LABELS[eid]
            url = self.results["search_urls"][eid]
            print(f"   {Colors.CYAN}[{label:<13}]{Colors.RESET} {url}")
        # PimEyes face search is upload-only - always include as a tip.
        print(f"   {Colors.DIM}[PimEyes      ] https://pimeyes.com/en  (face search, upload only){Colors.RESET}")

        if warnings:
            print()
            for w in warnings:
                print_status(w, "warning")

        print()
        return True

import io
import os

from core.base_module import BaseModule
from core.utils import print_status, Colors
from core import http

try:
    from PIL import Image, ExifTags
    HAS_PIL = True
except ImportError:
    HAS_PIL = False


MAX_BYTES = 40 * 1024 * 1024  # don't try to parse absurdly large downloads


def _ratio(value):
    """Convert an EXIF rational (IFDRational, tuple, int, float) to float."""
    try:
        return float(value)
    except (TypeError, ValueError, ZeroDivisionError):
        try:
            return value[0] / value[1]
        except Exception:
            return 0.0


def _jsonable(value):
    """Make an arbitrary EXIF value safe/compact for JSON output."""
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", "replace")[:200]
        except Exception:
            return repr(value)[:200]
    if isinstance(value, str):
        return value[:500]
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in list(value)[:50]]
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in list(value.items())[:50]}
    # IFDRational and any other numeric-ish object
    try:
        return float(value)
    except Exception:
        return str(value)[:200]


class ImageMetadata(BaseModule):
    """Extract EXIF metadata (incl. GPS) from an image URL or local file."""

    name = "harvest/image_metadata"
    description = "Extract EXIF metadata and GPS coordinates from an image (URL or local file)"
    category = "harvest"
    target_type = "url"

    def _register_options(self):
        self.add_option("TARGET", "", True, "Image URL (http/https) or local file path")

    def _load_bytes(self, target):
        """Return (bytes, content_type, error_note)."""
        if target.lower().startswith(("http://", "https://")):
            try:
                resp = http.get(target, timeout=20)
            except Exception as e:
                return None, "", f"download failed: {e}"
            if resp.status_code != 200:
                return None, "", f"download returned HTTP {resp.status_code}"
            content = resp.content or b""
            if len(content) > MAX_BYTES:
                return None, "", "image too large to process"
            return content, resp.headers.get("Content-Type", ""), ""
        if os.path.isfile(target):
            try:
                with open(target, "rb") as f:
                    return f.read(), "", ""
            except Exception as e:
                return None, "", f"could not read file: {e}"
        return None, "", "TARGET is neither a reachable URL nor an existing local file"

    def _dms_to_decimal(self, dms, ref):
        try:
            deg = _ratio(dms[0])
            minute = _ratio(dms[1])
            sec = _ratio(dms[2])
            dec = deg + minute / 60.0 + sec / 3600.0
            if str(ref).upper().startswith(("S", "W")):
                dec = -dec
            return round(dec, 6)
        except Exception:
            return None

    def _parse_gps(self, gps_raw):
        """gps_raw is a dict {gps_tag_id: value}. Returns {lat,lon,maps_url} or None."""
        if not gps_raw or not isinstance(gps_raw, dict):
            return None
        gps = {ExifTags.GPSTAGS.get(k, k): v for k, v in gps_raw.items()}
        lat = gps.get("GPSLatitude")
        lat_ref = gps.get("GPSLatitudeRef")
        lon = gps.get("GPSLongitude")
        lon_ref = gps.get("GPSLongitudeRef")
        if not (lat and lon and lat_ref and lon_ref):
            return None
        lat_dec = self._dms_to_decimal(lat, lat_ref)
        lon_dec = self._dms_to_decimal(lon, lon_ref)
        if lat_dec is None or lon_dec is None:
            return None
        return {
            "lat": lat_dec,
            "lon": lon_dec,
            "maps_url": f"https://maps.google.com/?q={lat_dec},{lon_dec}",
        }

    def _extract_exif(self, img):
        """Return (all_tags_dict, raw_gps_dict_or_None)."""
        tags = {}
        gps_raw = None

        # Legacy flat dict: merges IFD0 + Exif sub-IFD and nests GPSInfo as a dict.
        legacy = None
        try:
            legacy = img._getexif()
        except Exception:
            legacy = None

        if legacy:
            for tag_id, value in legacy.items():
                name = ExifTags.TAGS.get(tag_id, str(tag_id))
                if name == "GPSInfo" and isinstance(value, dict):
                    gps_raw = value
                    tags["GPSInfo"] = {
                        ExifTags.GPSTAGS.get(k, str(k)): _jsonable(v)
                        for k, v in value.items()
                    }
                else:
                    tags[name] = _jsonable(value)
            return tags, gps_raw

        # Modern API fallback (Pillow >= 6).
        try:
            exif = img.getexif()
        except Exception:
            return tags, gps_raw
        if not exif:
            return tags, gps_raw

        for tag_id, value in exif.items():
            name = ExifTags.TAGS.get(tag_id, str(tag_id))
            tags[name] = _jsonable(value)

        # Exif sub-IFD (DateTimeOriginal, etc.)
        try:
            sub = exif.get_ifd(ExifTags.IFD.Exif)
            for tag_id, value in sub.items():
                name = ExifTags.TAGS.get(tag_id, str(tag_id))
                tags[name] = _jsonable(value)
        except Exception:
            pass

        # GPS sub-IFD
        try:
            gifd = exif.get_ifd(ExifTags.IFD.GPSInfo)
            if gifd:
                gps_raw = dict(gifd)
                tags["GPSInfo"] = {
                    ExifTags.GPSTAGS.get(k, str(k)): _jsonable(v)
                    for k, v in gifd.items()
                }
        except Exception:
            pass

        return tags, gps_raw

    def run(self):
        if not self.validate():
            return False

        target = self.get_option("TARGET").strip()

        self.results = {
            "source": target,
            "has_exif": False,
            "gps": None,
            "camera": {"make": None, "model": None},
            "datetime": None,
            "software": None,
            "all_tags": {},
        }

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*58}")
        print(f"  Image Metadata / EXIF")
        print(f"  Target: {target}")
        print(f"{'='*58}{Colors.RESET}\n")

        if not HAS_PIL:
            note = "Pillow (PIL) is not installed - EXIF extraction unavailable. Install with: pip install Pillow"
            print_status(note, "warning")
            self.results["note"] = note
            return True

        content, content_type, err = self._load_bytes(target)
        if content is None:
            print_status(err, "error")
            self.results["note"] = err
            return True
        if content_type:
            print_status(f"Content-Type: {content_type}", "info")

        try:
            img = Image.open(io.BytesIO(content))
            img.load()
        except Exception as e:
            note = f"Not a parseable image / could not open: {e}"
            print_status(note, "warning")
            self.results["note"] = note
            return True

        print_status(f"Image format: {img.format}, size: {img.size}", "info")

        tags, gps_raw = self._extract_exif(img)

        if not tags:
            print_status("No EXIF metadata present in this image", "info")
            self.results["note"] = "no EXIF metadata found"
            return True

        gps = self._parse_gps(gps_raw)
        if gps:
            # Resolve the raw coordinates to a real place (free, keyless).
            from core import geocode
            place = geocode.reverse(gps["lat"], gps["lon"])
            if place:
                gps["location"] = place.get("display_name")
                gps["city"] = place.get("city")
                gps["country"] = place.get("country")
                gps["geocode"] = place

        self.results.update({
            "has_exif": True,
            "gps": gps,
            "camera": {"make": tags.get("Make"), "model": tags.get("Model")},
            "datetime": tags.get("DateTime") or tags.get("DateTimeOriginal"),
            "software": tags.get("Software"),
            "all_tags": tags,
        })

        print_status(f"EXIF tags found: {len(tags)}", "success")
        if self.results["camera"]["make"] or self.results["camera"]["model"]:
            print_status(
                f"Camera: {self.results['camera']['make']} {self.results['camera']['model']}".strip(),
                "success",
            )
        if self.results["datetime"]:
            print_status(f"DateTime: {self.results['datetime']}", "success")
        if self.results["software"]:
            print_status(f"Software: {self.results['software']}", "success")
        if gps:
            print_status(f"GPS: {gps['lat']}, {gps['lon']}", "success")
            if gps.get("location"):
                print_status(f"Location: {gps['location']}", "success")
            print_status(f"Map: {gps['maps_url']}", "success")
        else:
            print_status("No GPS coordinates in EXIF", "info")

        print()
        return True

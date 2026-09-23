import io
import math
import json
import re
import struct
import zipfile
import xml.etree.ElementTree as ET
import openpyxl
import lief
import yara
from PyPDF2 import PdfReader
from typing import Dict, Any, Optional, Tuple
import clamd
from magika import Magika
from langchain_ollama.llms import OllamaLLM

# Initialize Magika for AI-assisted file-type classification
magika = Magika()

# Initialize Ollama model for Tier 3 specialized triage
llm = OllamaLLM(model="qwen2.5-coder:1.5b")

import os
import shutil
import subprocess
import time

# Auto-launch and connect to ClamAV daemon
def ensure_clamd_running() -> bool:
    """Checks if clamd daemon is responding; if not, attempts to auto-launch it."""
    try:
        client = clamd.ClamdNetworkSocket(host="127.0.0.1", port=3310, timeout=2)
        if client.ping() == "PONG":
            return True
    except Exception:
        pass

    # Candidates for clamd.exe
    candidates = [
        shutil.which("clamd"),
        r"C:\Program Files\ClamAV\clamd.exe",
        r"C:\Program Files (x86)\ClamAV\clamd.exe",
        os.path.expanduser(r"~\AppData\Local\Programs\ClamAV\clamd.exe"),
    ]
    exe = next((c for c in candidates if c and os.path.isfile(c)), None)
    if not exe:
        return False

    try:
        flags = (subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS) if os.name == "nt" else 0
        subprocess.Popen(
            [exe],
            cwd=os.path.dirname(exe),
            creationflags=flags,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        for _ in range(10):
            time.sleep(0.5)
            try:
                client = clamd.ClamdNetworkSocket(host="127.0.0.1", port=3310, timeout=2)
                if client.ping() == "PONG":
                    return True
            except Exception:
                continue
    except Exception:
        pass
    return False

def get_clamd_client() -> Optional[clamd.ClamdNetworkSocket]:
    try:
        client = clamd.ClamdNetworkSocket(host="127.0.0.1", port=3310, timeout=10)
        if client.ping() == "PONG":
            return client
    except Exception:
        pass

    # If offline, attempt automatic launch once
    if ensure_clamd_running():
        try:
            return clamd.ClamdNetworkSocket(host="127.0.0.1", port=3310, timeout=10)
        except Exception:
            pass
    return None

def calculate_entropy(data: bytes) -> float:
    """
    Computes Shannon entropy (0.0 to 8.0) of raw bytes.
    Entropy > 7.2 in non-media files often indicates packed/encrypted payloads or obfuscation.
    """
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    byte_counts = [0] * 256
    for b in data:
        byte_counts[b] += 1
    for count in byte_counts:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 3)

def scan_yara(data: bytes) -> list[dict]:
    """
    Scan file contents using YARA rules.
    Returns structured information about matched rules.
    """
    try:
        rules_path = "yara_rules"

        rules = yara.compile(
            filepaths={
                "suspicious_rules": f"{rules_path}/suspicious_scripts.yar"
            }
        )

        matches = rules.match(data=data)

        results = []

        for match in matches:
            severity = "medium"

            if match.rule == "Suspicious_Memory_Injection":
                severity = "high"

            results.append({
                "rule": match.rule,
                "severity": severity
            })

        return results

    except Exception as e:
        print(f"YARA scan error: {e}")
        return []

def analyze_pdf_static(data: bytes) -> dict:
    """Inspect PDF metadata, actions, and URLs without assigning a verdict."""
    result = {
        "available": False,
        "page_count": None,
        "javascript": False,
        "open_action": False,
        "additional_actions": False,
        "embedded_files": False,
        "launch_actions": False,
        "uri_actions": False,
        "acroform": False,
        "urls": [],
        "indicators": [],
    }

    urls = []
    visited = set()

    def add_url(url: str) -> None:
        url = url.strip()
        if url and url not in urls:
            urls.append(url)

    def inspect_text(value: object) -> None:
        try:
            text = str(value)
        except Exception:
            return

        for url in re.findall(
            r"(?:https?|ftp)://[^\s<>\"']+",
            text,
            re.IGNORECASE,
        ):
            add_url(url.rstrip(".,;)]}"))

    def resolve(value: object) -> object:
        seen = set()

        try:
            while hasattr(value, "get_object"):
                object_id = id(value)

                if object_id in seen:
                    return None

                seen.add(object_id)
                value = value.get_object()

        except Exception:
            return None

        return value

    def walk(value: object) -> None:
        try:
            if hasattr(value, "get_object"):
                value = value.get_object()
        except Exception:
            return

        object_id = id(value)
        if object_id in visited:
            return
        visited.add(object_id)

        inspect_text(value)

        if isinstance(value, dict):
            for key, child in value.items():
                key_name = str(key).lower()
                child_name = str(child).lower()

                if key_name in {"/js", "/javascript"}:
                    result["javascript"] = True

                if key_name == "/s" and child_name == "/javascript":
                    result["javascript"] = True

                if key_name == "/openaction":
                    result["open_action"] = True

                if key_name == "/aa":
                    result["additional_actions"] = True

                if key_name in {"/embeddedfiles", "/ef"}:
                    result["embedded_files"] = True

                if key_name == "/s" and child_name == "/launch":
                    result["launch_actions"] = True

                if key_name in {"/uri", "/url"}:
                    result["uri_actions"] = True

                if key_name == "/s" and child_name == "/uri":
                    result["uri_actions"] = True

                if key_name == "/acroform":
                    result["acroform"] = True

                walk(key)
                walk(child)

        elif isinstance(value, (list, tuple)):
            for child in value:
                walk(child)

    try:
        reader = PdfReader(io.BytesIO(data))
        result["available"] = True
        result["page_count"] = len(reader.pages)

        root = reader.trailer.get("/Root")
        walk(root)

        for page in reader.pages:
            page_object = resolve(page)

            if not isinstance(page_object, dict):
                continue

            annotations = resolve(page_object.get("/Annots"))

            if annotations is not None and not isinstance(
                annotations, (list, tuple)
            ):
                annotations = [annotations]

            for annotation_reference in annotations or []:
                annotation = resolve(annotation_reference)

                if not isinstance(annotation, dict):
                    continue

                action = resolve(annotation.get("/A"))

                if not isinstance(action, dict):
                    continue

                action_type = resolve(action.get("/S"))

                if str(action_type).lower() != "/uri":
                    continue

                result["uri_actions"] = True

                uri = resolve(action.get("/URI"))

                if uri is not None:
                    add_url(str(uri))

            walk(page)

    except Exception as e:
        result["reason"] = f"PDF parsing failed: {str(e)}"

    raw_text = data.decode("latin-1", errors="ignore")
    inspect_text(raw_text)

    raw_markers = {
        "javascript": r"/(?:JS|JavaScript)\b",
        "open_action": r"/OpenAction\b",
        "additional_actions": r"/AA\b",
        "embedded_files": r"/(?:EmbeddedFiles|EF)\b",
        "launch_actions": r"/Launch\b",
        "uri_actions": r"/(?:URI|URL)\b",
        "acroform": r"/AcroForm\b",
    }

    for field, pattern in raw_markers.items():
        if re.search(pattern, raw_text, re.IGNORECASE):
            result[field] = True

    result["urls"] = urls[:20]

    evidence = [
        ("javascript", "PDF JavaScript detected"),
        ("open_action", "PDF OpenAction detected"),
        ("additional_actions", "PDF additional actions detected"),
        ("embedded_files", "PDF embedded files detected"),
        ("launch_actions", "PDF Launch action detected"),
        ("uri_actions", "PDF URI action detected"),
        ("acroform", "PDF AcroForm detected"),
    ]

    result["indicators"] = [
        message
        for field, message in evidence
        if result[field]
    ]

    return result

def analyze_docx_static(data: bytes) -> dict:

    result = {
        "available": False,
        "macro": False,
        "embedded_objects": False,
        "external_links": False,
        "dde": False,
        "ole_objects": False,
        "urls": [],
        "indicators": [],
    }

    try:
        with zipfile.ZipFile(io.BytesIO(data), "r") as z:
            names = z.namelist()
            result["available"] = True

            # Macro-enabled Office content
            macro_files = [
                name for name in names
                if name.lower().endswith("vbaproject.bin")
            ]

            if macro_files:
                result["macro"] = True
                result["indicators"].append(
                    "DOCX VBA macro project detected"
                )

            # Embedded files / OLE objects
            embedded_files = [
                name for name in names
                if name.startswith("word/embeddings/")
            ]

            if embedded_files:
                result["embedded_objects"] = True
                result["ole_objects"] = True
                result["indicators"].append(
                    "DOCX embedded objects detected"
                )

            # External relationships
            relationship_files = [
                name for name in names
                if name.lower().endswith(".rels")
            ]

            for rel_file in relationship_files:
                try:
                    content = z.read(rel_file).decode(
                        "utf-8",
                        errors="ignore"
                    )

                    if 'TargetMode="External"' in content:
                        result["external_links"] = True
                        result["indicators"].append(
                            "DOCX external relationship detected"
                        )

                    urls = re.findall(
                        r"https?://[^\s\"'<>]+",
                        content,
                        flags=re.IGNORECASE,
                )

                    for url in urls:
                        if (
                            "schemas.openxmlformats.org" not in url.lower()
                            and "schemas.microsoft.com" not in url.lower()
                            and url not in result["urls"]
                        ):
                            result["urls"].append(url)

                except Exception:
                    continue

            # DDE detection
            #
            # Only inspect actual Word field instruction content.
            # Do not search for the word "dde" throughout all XML,
            # because normal Word XML can contain unrelated text
            # that causes false positives.
            xml_files = [
                name for name in names
                if name.lower().endswith(".xml")
            ]

            for xml_file in xml_files:
                try:
                    content = z.read(xml_file).decode(
                        "utf-8",
                        errors="ignore"
                    )

                    lowered = content.lower()

                    if (
                        "w:instrtext" in lowered
                        and (
                            "ddeauto" in lowered
                            or " dde " in lowered
                        )
                    ):
                        result["dde"] = True
                        result["indicators"].append(
                            "DOCX DDE field detected"
                        )
                        break

                except Exception:
                    continue

            # Remove duplicate indicators
            result["indicators"] = list(
                dict.fromkeys(result["indicators"])
            )

            return result

    except Exception as exc:
        result["reason"] = f"DOCX parsing failed: {exc}"
        return result


def analyze_executable_lief(data: bytes) -> dict:
    """
    Analyze executable files using LIEF.
    Extracts basic structural information without assigning a malware verdict.
    """
    try:
        binary = lief.parse(list(data))

        if binary is None:
            return {
                "available": False,
                "reason": "LIEF could not parse the file"
            }

        result = {
            "available": True,
            "format": str(binary.format),
            "entrypoint": getattr(binary, "entrypoint", None),
            "sections": [],
            "imports": [],
        }

        for section in binary.sections:
            result["sections"].append({
                "name": section.name,
                "size": section.size,
                "virtual_size": section.virtual_size,
            })

        if hasattr(binary, "imports"):
            result["imports"] = []

            for library in binary.imports:
                result["imports"].append({
                    "name": library.name,
                    "functions": [
                        entry.name
                        for entry in library.entries
                        if entry.name
                    ]
                })

        return result

    except Exception as e:
        return {
            "available": False,
            "reason": f"LIEF analysis failed: {str(e)}"
        }

def analyze_zip_static(data: bytes) -> dict:
    """Inspect ZIP metadata and bounded textual content without extraction."""
    result = {
        "available": False,
        "member_count": 0,
        "total_uncompressed_size": 0,
        "total_compressed_size": 0,
        "compression_ratio": None,
        "nested_archives": False,
        "executables": [],
        "scripts": [],
        "suspicious_paths": [],
        "encrypted_members": False,
        "urls": [],
        "indicators": [],
    }

    max_members = 10000
    max_total_uncompressed = 512 * 1024 * 1024
    max_total_compressed = 128 * 1024 * 1024
    max_text_member_size = 256 * 1024
    max_text_bytes = 2 * 1024 * 1024
    max_report_items = 100
    max_name_length = 160
    max_path_depth = 8
    executable_extensions = {
        ".exe", ".dll", ".scr", ".com", ".msi", ".sys", ".cpl"
    }
    script_extensions = {
        ".ps1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
        ".wsf", ".wsh", ".hta", ".py", ".sh"
    }
    archive_extensions = {
        ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz"
    }
    text_extensions = {
        ".txt", ".csv", ".json", ".xml", ".html", ".htm", ".js",
        ".jse", ".ps1", ".bat", ".cmd", ".vbs", ".vbe", ".wsf",
        ".wsh", ".hta", ".py", ".sh", ".ini", ".cfg", ".conf",
        ".yml", ".yaml", ".md", ".url"
    }

    def bounded_name(name: str) -> str:
        name = str(name)
        if len(name) <= max_name_length:
            return name
        return name[:max_name_length - 3] + "..."

    def add_unique(field: str, value: str) -> None:
        values = result[field]
        if value not in values and len(values) < max_report_items:
            values.append(value)

    try:
        with zipfile.ZipFile(io.BytesIO(data), "r") as archive:
            infos = archive.infolist()
            result["available"] = True
            result["member_count"] = len(infos)
            text_bytes_read = 0

            for info in infos:
                name = str(info.filename)
                safe_name = bounded_name(name)
                lower_name = name.lower()
                suffix = lower_name.rsplit(".", 1)[-1] if "." in lower_name else ""
                suffix = "." + suffix if suffix else ""
                result["total_uncompressed_size"] += max(info.file_size, 0)
                result["total_compressed_size"] += max(info.compress_size, 0)

                if suffix in executable_extensions:
                    add_unique("executables", safe_name)
                    result["indicators"].append(
                        f"ZIP executable member detected: {safe_name}"
                    )

                if suffix in script_extensions:
                    add_unique("scripts", safe_name)
                    result["indicators"].append(
                        f"ZIP script member detected: {safe_name}"
                    )

                if suffix in archive_extensions:
                    result["nested_archives"] = True
                    result["indicators"].append(
                        f"ZIP nested archive detected: {safe_name}"
                    )

                normalized_path = name.replace("\\", "/")
                path_parts = [part for part in normalized_path.split("/") if part]
                is_absolute = (
                    normalized_path.startswith("/")
                    or normalized_path.startswith("\\")
                    or bool(re.match(r"^[a-zA-Z]:/", normalized_path))
                )
                has_traversal = ".." in path_parts
                is_too_deep = len(path_parts) > max_path_depth
                if is_absolute or has_traversal or is_too_deep:
                    add_unique("suspicious_paths", safe_name)
                    result["indicators"].append(
                        f"ZIP suspicious path detected: {safe_name}"
                    )

                if info.flag_bits & 0x1:
                    result["encrypted_members"] = True
                    result["indicators"].append(
                        "ZIP encrypted member detected"
                    )

                if (
                    not info.is_dir()
                    and suffix in text_extensions
                    and info.file_size <= max_text_member_size
                    and text_bytes_read < max_text_bytes
                ):
                    read_size = min(
                        info.file_size,
                        max_text_member_size,
                        max_text_bytes - text_bytes_read,
                    )
                    try:
                        with archive.open(info, "r") as member:
                            content = member.read(read_size)
                        text_bytes_read += len(content)
                        text = content.decode("utf-8", errors="ignore")
                        for url in re.findall(
                            r"(?:https?|ftp)://[^\s<>\"']+",
                            text,
                            flags=re.IGNORECASE,
                        ):
                            add_unique("urls", url.rstrip(".,;)]}"))
                    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile):
                        continue

            if result["total_compressed_size"] > 0:
                result["compression_ratio"] = round(
                    result["total_uncompressed_size"]
                    / result["total_compressed_size"],
                    2,
                )

            if len(infos) > max_members:
                result["indicators"].append(
                    "ZIP member count is unusually large"
                )
            if result["total_uncompressed_size"] > max_total_uncompressed:
                result["indicators"].append(
                    "ZIP total uncompressed size is unusually large"
                )
            if result["total_compressed_size"] > max_total_compressed:
                result["indicators"].append(
                    "ZIP total compressed size is unusually large"
                )
            if (
                result["compression_ratio"] is not None
                and result["compression_ratio"] >= 100
                and result["total_uncompressed_size"] >= 1024 * 1024
            ):
                result["indicators"].append(
                    "ZIP high compression ratio observed"
                )

            result["indicators"] = list(
                dict.fromkeys(result["indicators"])
            )[:max_report_items]
            return result

    except Exception as exc:
        result["reason"] = f"ZIP parsing failed: {exc}"
        return result

def analyze_image_static(data: bytes) -> dict:
    """Inspect common image headers and bounded textual metadata only."""
    result = {
        "available": False,
        "format": None,
        "width": None,
        "height": None,
        "mode": None,
        "animated": False,
        "frame_count": None,
        "metadata": {},
        "urls": [],
        "indicators": [],
    }

    max_metadata_fields = 20
    max_metadata_value_length = 200
    max_urls = 20
    max_dimension = 20000
    max_pixels = 200_000_000
    suspicious_metadata_terms = {
        "javascript", "powershell", "cmd.exe", "wscript", "<script",
        "payload", "base64"
    }

    def add_url(value: str) -> None:
        value = value.strip().rstrip(".,;)]}")
        if value and value not in result["urls"] and len(result["urls"]) < max_urls:
            result["urls"].append(value)

    def add_metadata(key: str, value: object) -> None:
        if len(result["metadata"]) >= max_metadata_fields:
            return
        text = str(value).replace("\x00", " ")
        text = re.sub(r"\s+", " ", text).strip()
        if not text:
            return
        text = text[:max_metadata_value_length]
        result["metadata"][key[:80]] = text
        for url in re.findall(
            r"(?:https?|ftp)://[^\s<>\"']+",
            text,
            flags=re.IGNORECASE,
        ):
            add_url(url)
        lowered = text.lower()
        if any(term in lowered for term in suspicious_metadata_terms):
            result["indicators"].append(
                f"IMAGE suspicious metadata field detected: {key[:80]}"
            )

    def set_dimensions(width: int, height: int) -> None:
        if width <= 0 or height <= 0:
            raise ValueError("invalid image dimensions")
        result["width"] = width
        result["height"] = height
        if width > max_dimension or height > max_dimension:
            result["indicators"].append(
                f"IMAGE unusually large dimensions: {width}x{height}"
            )
        if width * height > max_pixels:
            result["indicators"].append("IMAGE unusually large pixel count")

    def skip_gif_subblocks(offset: int) -> int:
        while offset < len(data):
            block_size = data[offset]
            offset += 1
            if block_size == 0:
                return offset
            offset += block_size
        return len(data)

    def parse_png() -> None:
        if len(data) < 33 or data[:8] != b"\x89PNG\r\n\x1a\n":
            raise ValueError("invalid PNG signature")
        width, height, bit_depth, color_type = struct.unpack(
            ">IIBB", data[16:26]
        )
        modes = {0: "L", 2: "RGB", 3: "P", 4: "LA", 6: "RGBA"}
        set_dimensions(width, height)
        result["mode"] = modes.get(color_type, f"color_type_{color_type}")
        result["metadata"]["bit_depth"] = bit_depth
        offset = 8
        frame_count = 1
        chunks_seen = 0
        while offset + 12 <= len(data) and chunks_seen < 10000:
            length = struct.unpack(">I", data[offset:offset + 4])[0]
            chunk_end = offset + 12 + length
            if chunk_end > len(data):
                break
            chunk_type = data[offset + 4:offset + 8]
            chunk_data = data[offset + 8:offset + 8 + length]
            if chunk_type == b"acTL" and len(chunk_data) >= 8:
                frame_count = struct.unpack(">I", chunk_data[:4])[0]
            elif chunk_type == b"tEXt" and b"\x00" in chunk_data:
                key, value = chunk_data.split(b"\x00", 1)
                add_metadata(key.decode("latin-1", errors="ignore"), value.decode("latin-1", errors="ignore"))
            elif chunk_type == b"iTXt":
                fields = chunk_data.split(b"\x00", 5)
                if len(fields) == 6:
                    add_metadata(fields[0].decode("latin-1", errors="ignore"), fields[5].decode("utf-8", errors="ignore"))
            offset = chunk_end
            chunks_seen += 1
        result["frame_count"] = frame_count
        result["animated"] = frame_count > 1

    def parse_gif() -> None:
        if len(data) < 13 or data[:6] not in {b"GIF87a", b"GIF89a"}:
            raise ValueError("invalid GIF signature")
        width, height = struct.unpack("<HH", data[6:10])
        packed = data[10]
        set_dimensions(width, height)
        result["mode"] = "P"
        offset = 13
        if packed & 0x80:
            offset += 3 * (2 ** ((packed & 0x07) + 1))
        frames = 0
        has_loop_extension = False
        while offset < len(data) and frames < 10000:
            marker = data[offset]
            offset += 1
            if marker == 0x3B:
                break
            if marker == 0x2C:
                if offset + 9 > len(data):
                    break
                image_packed = data[offset + 8]
                offset += 9
                if image_packed & 0x80:
                    offset += 3 * (2 ** ((image_packed & 0x07) + 1))
                if offset >= len(data):
                    break
                offset += 1
                offset = skip_gif_subblocks(offset)
                frames += 1
            elif marker == 0x21:
                if offset >= len(data):
                    break
                label = data[offset]
                offset += 1
                if label == 0xFE:
                    comment_start = offset
                    offset = skip_gif_subblocks(offset)
                    add_metadata("comment", data[comment_start:offset].decode("latin-1", errors="ignore"))
                elif label == 0xFF:
                    if offset >= len(data):
                        break
                    block_size = data[offset]
                    app_start = offset + 1
                    offset = skip_gif_subblocks(app_start + block_size)
                    if b"NETSCAPE" in data[app_start:app_start + block_size]:
                        has_loop_extension = True
                else:
                    offset = skip_gif_subblocks(offset)
            else:
                break
        result["frame_count"] = frames
        result["animated"] = frames > 1 or has_loop_extension

    def parse_jpeg() -> None:
        if len(data) < 4 or data[:2] != b"\xff\xd8":
            raise ValueError("invalid JPEG signature")
        offset = 2
        frames = 0
        while offset + 4 <= len(data) and frames < 10000:
            while offset < len(data) and data[offset] != 0xFF:
                offset += 1
            while offset < len(data) and data[offset] == 0xFF:
                offset += 1
            if offset >= len(data):
                break
            marker = data[offset]
            offset += 1
            if marker in {0xD8, 0xD9}:
                continue
            if marker == 0xDA:
                break
            if offset + 2 > len(data):
                break
            segment_length = struct.unpack(">H", data[offset:offset + 2])[0]
            if segment_length < 2 or offset + segment_length > len(data):
                break
            segment = data[offset + 2:offset + segment_length]
            if marker in set(range(0xC0, 0xC4)) | set(range(0xC5, 0xC8)) | set(range(0xC9, 0xCC)) | set(range(0xCD, 0xD0)):
                if len(segment) >= 6:
                    height, width, components = struct.unpack(">HHB", segment[1:6])
                    set_dimensions(width, height)
                    result["mode"] = {1: "L", 3: "RGB", 4: "CMYK"}.get(components, f"components_{components}")
                    frames += 1
            elif marker == 0xE1 and segment.startswith(b"Exif\x00\x00"):
                result["metadata"]["exif_present"] = True
                for text in re.findall(rb"[ -~]{4,}", segment[6:]):
                    add_metadata("exif_text", text.decode("latin-1", errors="ignore"))
            elif marker == 0xFE:
                add_metadata("comment", segment)
            offset += segment_length
        result["frame_count"] = frames or 1

    def parse_bmp() -> None:
        if len(data) < 26 or data[:2] != b"BM":
            raise ValueError("invalid BMP signature")
        dib_size = struct.unpack("<I", data[14:18])[0]
        if dib_size < 12 or len(data) < 14 + dib_size:
            raise ValueError("invalid BMP header")
        if dib_size == 12:
            width, height, planes, bits = struct.unpack("<HHHH", data[18:26])
        else:
            width, height, planes, bits = struct.unpack("<iiHH", data[18:30])
            height = abs(height)
        set_dimensions(width, height)
        result["mode"] = {1: "1", 4: "P", 8: "P", 16: "RGB", 24: "RGB", 32: "RGBA"}.get(bits, f"bits_{bits}")
        result["metadata"]["bits_per_pixel"] = bits

    def parse_tiff() -> None:
        if len(data) < 8 or data[:2] not in {b"II", b"MM"}:
            raise ValueError("invalid TIFF byte order")
        endian = "<" if data[:2] == b"II" else ">"
        if struct.unpack(endian + "H", data[2:4])[0] != 42:
            raise ValueError("invalid TIFF signature")
        ifd_offset = struct.unpack(endian + "I", data[4:8])[0]
        frames = 0
        while ifd_offset and ifd_offset + 2 <= len(data) and frames < 100:
            count = struct.unpack(endian + "H", data[ifd_offset:ifd_offset + 2])[0]
            entries_end = ifd_offset + 2 + count * 12
            if entries_end + 4 > len(data):
                break
            values = {}
            for index in range(count):
                entry = ifd_offset + 2 + index * 12
                tag, value_type, value_count = struct.unpack(endian + "HHI", data[entry:entry + 8])
                value_size = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8}.get(value_type, 0) * value_count
                raw = data[entry + 8:entry + 12] if value_size <= 4 else data[struct.unpack(endian + "I", data[entry + 8:entry + 12])[0]:][:value_size]
                if value_type == 3 and len(raw) >= 2:
                    values[tag] = struct.unpack(endian + "H", raw[:2])[0]
                elif value_type == 4 and len(raw) >= 4:
                    values[tag] = struct.unpack(endian + "I", raw[:4])[0]
                elif value_type == 2:
                    add_metadata(f"tiff_{tag}", raw.decode("latin-1", errors="ignore"))
            if 256 in values and 257 in values:
                set_dimensions(values[256], values[257])
            result["mode"] = {1: "L", 2: "RGB", 5: "CMYK"}.get(values.get(262), "RGB")
            frames += 1
            ifd_offset = struct.unpack(endian + "I", data[entries_end:entries_end + 4])[0]
        if frames == 0 or result["width"] is None:
            raise ValueError("TIFF dimensions unavailable")
        result["frame_count"] = frames
        result["animated"] = frames > 1

    def parse_webp() -> None:
        if len(data) < 12 or data[:4] != b"RIFF" or data[8:12] != b"WEBP":
            raise ValueError("invalid WEBP signature")
        offset = 12
        frames = 0
        animation_flag = False
        while offset + 8 <= len(data) and frames < 10000:
            chunk_type = data[offset:offset + 4]
            chunk_size = struct.unpack("<I", data[offset + 4:offset + 8])[0]
            chunk_start = offset + 8
            chunk_end = chunk_start + chunk_size
            if chunk_end > len(data):
                break
            chunk = data[chunk_start:chunk_end]
            if chunk_type == b"VP8X" and len(chunk) >= 10:
                flags = chunk[0]
                animation_flag = bool(flags & 0x02)
                width = 1 + int.from_bytes(chunk[4:7], "little")
                height = 1 + int.from_bytes(chunk[7:10], "little")
                set_dimensions(width, height)
                result["mode"] = "RGBA" if flags & 0x10 else "RGB"
            elif chunk_type == b"ANIM":
                animation_flag = True
            elif chunk_type == b"ANMF":
                frames += 1
            offset = chunk_end + (chunk_size & 1)
        result["frame_count"] = frames or 1
        result["animated"] = animation_flag or frames > 1

    try:
        if data.startswith(b"\x89PNG\r\n\x1a\n"):
            result["format"] = "PNG"
            parse_png()
        elif data[:6] in {b"GIF87a", b"GIF89a"}:
            result["format"] = "GIF"
            parse_gif()
        elif data[:2] == b"\xff\xd8":
            result["format"] = "JPEG"
            parse_jpeg()
        elif data[:2] == b"BM":
            result["format"] = "BMP"
            parse_bmp()
        elif data[:2] in {b"II", b"MM"}:
            result["format"] = "TIFF"
            parse_tiff()
        elif len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
            result["format"] = "WEBP"
            parse_webp()
        else:
            raise ValueError("unsupported or malformed image format")
        result["available"] = True
        if result["animated"]:
            result["indicators"].append("IMAGE animated/multi-frame content detected")
        result["indicators"] = list(dict.fromkeys(result["indicators"]))
        return result
    except Exception as exc:
        result["reason"] = f"Image parsing failed: {exc}"
        return result

def analyze_svg_static(data: bytes) -> dict:
    """Inspect SVG XML as static data without executing or resolving resources."""
    result = {
        "available": False,
        "width": None,
        "height": None,
        "viewbox": None,
        "script": False,
        "event_handlers": [],
        "external_references": [],
        "javascript_urls": [],
        "embedded_data": False,
        "indicators": [],
    }
    max_values = 20
    max_value_length = 200

    def add_indicator(value: str) -> None:
        if value not in result["indicators"]:
            result["indicators"].append(value)

    def bounded_value(value: object) -> str:
        return str(value).strip()[:max_value_length]

    def add_external_reference(value: object) -> None:
        value = bounded_value(value)
        if value and value not in result["external_references"]:
            if len(result["external_references"]) < max_values:
                result["external_references"].append(value)
                add_indicator("SVG external reference detected")

    def add_javascript_url(value: object) -> None:
        value = bounded_value(value)
        if value and value not in result["javascript_urls"]:
            if len(result["javascript_urls"]) < max_values:
                result["javascript_urls"].append(value)
                add_indicator("SVG javascript URL detected")

    def local_name(name: str) -> str:
        return name.rsplit("}", 1)[-1].lower()

    def inspect_reference(value: object) -> None:
        reference = bounded_value(value)
        lowered = reference.lower()
        if lowered.startswith("javascript:"):
            add_javascript_url(reference)
            return
        if lowered.startswith("data:"):
            result["embedded_data"] = True
            add_indicator("SVG embedded data detected")
            return
        if (
            lowered.startswith(("http://", "https://", "//", "ftp://", "file:"))
            or re.match(r"^[a-z][a-z0-9+.-]*:", lowered)
        ):
            add_external_reference(reference)

    try:
        raw_text = data.decode("utf-8", errors="ignore")
        if re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", raw_text, re.IGNORECASE):
            add_indicator("SVG XML entity/DOCTYPE construct detected")

        root = ET.fromstring(data)
        result["available"] = True

        for attribute_name, attribute_value in root.attrib.items():
            name = local_name(attribute_name)
            value = bounded_value(attribute_value)
            if name == "width":
                result["width"] = value
            elif name == "height":
                result["height"] = value
            elif name == "viewbox":
                result["viewbox"] = value

        for element in root.iter():
            if local_name(str(element.tag)) == "script":
                result["script"] = True
                add_indicator("SVG script element detected")

            for attribute_name, attribute_value in element.attrib.items():
                name = local_name(attribute_name)
                value = bounded_value(attribute_value)
                if name.startswith("on"):
                    if name not in result["event_handlers"] and len(result["event_handlers"]) < max_values:
                        result["event_handlers"].append(name)
                    add_indicator("SVG event handler detected")
                elif name in {"href", "src", "link"}:
                    inspect_reference(value)

        return result
    except Exception as exc:
        result["reason"] = f"SVG parsing failed: {exc}"
        return result

def extract_interesting_imports(lief_analysis: dict) -> list[dict]:
    """
    Classify potentially interesting imported Windows APIs.
    These are supporting static-analysis indicators, not malware verdicts.
    """
    if not lief_analysis or not lief_analysis.get("available"):
        return []

    import_categories = {
        "Process Injection": {
            "VirtualAlloc",
            "VirtualAllocEx",
            "VirtualProtect",
            "VirtualProtectEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
            "NtCreateThreadEx",
            "QueueUserAPC",
        },
        "Process Creation": {
            "CreateProcessA",
            "CreateProcessW",
            "WinExec",
            "ShellExecuteA",
            "ShellExecuteW",
        },
        "Memory Manipulation": {
            "HeapAlloc",
            "HeapCreate",
            "VirtualFree",
            "VirtualFreeEx",
            "MapViewOfFile",
            "UnmapViewOfFile",
        },
        "Networking": {
            "InternetOpenA",
            "InternetOpenW",
            "InternetConnectA",
            "InternetConnectW",
            "HttpOpenRequestA",
            "HttpOpenRequestW",
            "WinHttpOpen",
            "WinHttpConnect",
            "WSAStartup",
            "connect",
        },
    }

    results = []

    for library in lief_analysis.get("imports", []):
        library_name = library.get("name", "")
        functions = library.get("functions", [])

        for function_name in functions:
            for category, apis in import_categories.items():
                if function_name in apis:
                    results.append({
                        "library": library_name,
                        "function": function_name,
                        "category": category,
                    })

    return results

def detect_file_type(data: bytes, filename: str) -> Dict[str, Any]:
    """
    Uses Google Magika to detect actual file type from binary contents
    and flags extension spoofing (e.g. invoice.pdf secretly being an executable).
    """
    magika_result = magika.identify_bytes(data)
    actual_label = magika_result.output.label
    actual_mime = magika_result.output.mime_type
    confidence = round(getattr(magika_result, "score", 1.0) * 100, 1)

    # Check extension mismatch
    claimed_ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    double_ext = bool(re.search(r"\.[a-zA-Z0-9]+\.(exe|bat|ps1|vbs|cmd|scr|sh|js|dll)$", filename, re.IGNORECASE))

    # Known executable/script labels flagged by Magika
    executable_labels = {
        "exe", "elf", "mach-o", "dll", "pe", "batch", "powershell",
        "sh", "vbs", "javascript", "python", "autorun", "pebin"
    }

    is_dangerous_executable = actual_label in executable_labels
    spoofed = False

    # Only treat a text-like extension as spoofed when Magika is confidently identifying
    # an executable/script payload rather than a low-confidence guess from ordinary text.
    innocent_extensions = {"pdf", "jpg", "jpeg", "png", "gif", "txt", "docx", "xlsx", "mp4", "mp3"}
    if claimed_ext in innocent_extensions and is_dangerous_executable and confidence >= 80.0:
        spoofed = True

    return {
        "claimed_extension": claimed_ext,
        "actual_type": actual_label,
        "mime_type": actual_mime,
        "confidence": confidence,
        "is_spoofed": spoofed,
        "is_double_extension": double_ext,
        "is_executable": is_dangerous_executable
    }

def scan_clamav(data: bytes) -> Tuple[bool, Optional[str]]:
    """
    Streams file bytes directly to the local ClamAV daemon.
    Returns (is_infected, threat_name).
    """
    client = get_clamd_client()
    if not client:
        return False, "ClamAV daemon offline (skipped)"
    
    try:
        scan_result = client.instream(io.BytesIO(data))
        if scan_result and "stream" in scan_result:
            status, threat = scan_result["stream"]
            if status == "FOUND":
                return True, threat
        return False, None
    except Exception as e:
        return False, f"Scan error: {str(e)}"

def extract_suspicious_indicators(data: bytes) -> list[str]:
    """
    Extracts heuristic security indicators from raw file bytes.

    Indicators are classified by strength. Common words such as
    'powershell' are treated as weak signals, while combinations
    associated with code injection or payload execution are stronger.
    """
    indicators = []

    sample = data[:1024 * 1024].lower()

    weak_patterns = [
        (b"powershell", "PowerShell reference detected"),
        (b"cmd.exe", "Command prompt reference detected"),
        (b"/bin/sh", "Unix shell reference detected"),
        (b"/bin/bash", "Bash shell reference detected"),
        (b"curl ", "Curl command reference detected"),
        (b"wget ", "Wget command reference detected"),
    ]

    strong_patterns = [
        (b"wscript.shell", "Windows Script Host invocation detected"),
        (b"frombase64string", "Base64 payload de-obfuscation marker detected"),
        (b"virtualalloc", "Memory allocation API associated with code injection detected"),
        (b"createremotethread", "Remote thread creation API detected"),
    ]

    for pattern, description in weak_patterns:
        if pattern in sample:
            indicators.append(f"WEAK: {description}")

    for pattern, description in strong_patterns:
        if pattern in sample:
            indicators.append(f"STRONG: {description}")

    if b"-enc" in sample and b"powershell" in sample:
        indicators.append("STRONG: PowerShell encoded-command combination detected")

    if b"eval(" in sample or b"exec(" in sample:
        indicators.append("WEAK: Dynamic code execution reference detected")

    return indicators

def llm_worst_case_analysis(data: bytes, filename: str, context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Tier 3: Specialized LLM Security Auditor.
    Only triggered when a file is suspicious, obfuscated, or ambiguous.
    Passes extracted printable strings and metadata (NOT dangerous raw execution).
    """
    sample = data[:4096]
    printable_chars = [chr(b) if 32 <= b <= 126 or b in (10, 13, 9) else " " for b in sample]
    extracted_text = "".join(printable_chars).strip()
    extracted_text = re.sub(r"\s+", " ", extracted_text)[:1500]

    system_prompt = f"""You are a local malware triage model. Use the supplied static-analysis evidence as the authoritative context. Do not invent malicious behavior. Never mention an indicator that is not present in the evidence. API names alone do not prove malware. Common PowerShell references alone do not prove malware. Do not infer PowerShell unless PowerShell is explicitly present in the indicators, YARA matches, or supplied snippet.

If the supplied evidence directly shows executable APIs or YARA injection indicators, prefer SUSPICIOUS and explain only the observed evidence. For PDF files, JavaScript, OpenAction, additional actions, embedded files, Launch actions, and suspicious URI actions are static-analysis indicators that must be explicitly considered in the assessment. Their presence alone does not automatically prove malware. For DOCX files, external relationships, ordinary hyperlinks, embedded objects, and VBA macro projects are static-analysis findings that must be considered in context; their presence alone does not automatically prove malicious behavior. PPTX findings must be interpreted the same way: macros, embedded objects, external relationships, URLs, and action or hyperlink elements are evidence only and do not alone prove malicious behavior. ZIP findings are static-analysis evidence only: executable or script members, nested archives, encryption, suspicious paths, and compression/resource-abuse indicators do not automatically prove malicious behavior.
If the supplied evidence directly shows executable APIs or YARA injection indicators, prefer SUSPICIOUS and explain only the observed evidence. For PDF files, JavaScript, OpenAction, additional actions, embedded files, Launch actions, and suspicious URI actions are static-analysis indicators that must be explicitly considered in the assessment. Their presence alone does not automatically prove malware. For DOCX files, external relationships, ordinary hyperlinks, embedded objects, and VBA macro projects are static-analysis findings that must be considered in context; their presence alone does not automatically prove malicious behavior. PPTX findings must be interpreted the same way: macros, embedded objects, external relationships, URLs, and action or hyperlink elements are evidence only and do not alone prove malicious behavior.

ZIP findings are static-analysis evidence only: executable or script members, nested archives, encryption, suspicious paths, and compression/resource-abuse indicators do not automatically prove malicious behavior.

File details:
- Filename: {filename}
- Claimed type: {context.get('claimed_extension')}
- Detected type: {context.get('actual_type')} ({context.get('mime_type')})
- Entropy: {context.get('entropy')}
- Indicators: {context.get('indicators')}
- YARA matches: {context.get('yara_matches')}
- PDF static analysis: {context.get('pdf_analysis')}
- DOCX static analysis: {context.get('docx_analysis')}
- XLSX static analysis: {context.get('xlsx_analysis')}
- PPTX static analysis: {context.get('pptx_analysis')}
- ZIP static analysis: {context.get('zip_analysis')}
- IMAGE static analysis: {context.get('image_analysis')}
- SVG static analysis: {context.get('svg_analysis')}
- LIEF analysis: {context.get('lief_analysis')}

DOCX interpretation guidance:
- The "indicators" field contains static-analysis findings. These are not automatically malicious.
- If the DOCX indicators list is non-empty, the reason MUST explicitly acknowledge the detected finding(s).
- A detected VBA macro project means macro code exists, but does not by itself prove malicious behavior.
- A detected embedded object means an embedded object exists, but does not by itself prove malicious behavior.
- A detected external relationship or URL means an external reference exists, but does not by itself prove malicious behavior.
- Keep static-analysis findings separate from malicious behavior. Do not call a file "free of indicators" when the indicators list is non-empty.
- If static-analysis indicators are present but there is no direct evidence of malicious behavior, SAFE may still be returned, but the reason MUST state the detected finding and explain that it is not sufficient by itself to establish malicious behavior.
- Treat "embedded objects", "embedded files", "OLE objects", and "macro projects" as distinct findings.
- Never invent macro behavior, payloads, commands, network activity, or execution behavior that was not observed.

XLSX static analysis: treat the reported findings as static-analysis evidence only.
- A VBA macro project means macro code is present, but does not by itself prove malicious behavior.
- Embedded objects do not by themselves prove malicious behavior.
- An external relationship or URL does not by itself prove malicious behavior.
- An Excel 4.0 macro sheet is a static finding; do not invent what the macro does.
- DDE-related formula content is a static finding; do not invent execution behavior.
- Excel add-in content is a static finding; do not invent payloads, commands, or malicious behavior.
- Never describe an XLSX finding as a DOCX finding.
- When multiple XLSX indicators are present, mention the actual XLSX indicators by name and do not refer to the file as DOCX or another file type.
- Never claim a macro, embedded object, DDE, external relationship, Excel 4.0 macro sheet, or add-in exists unless it is explicitly present in xlsx_analysis.
- If xlsx_analysis.indicators is non-empty, the reason must explicitly acknowledge the actual indicator(s).
- Do not say that no suspicious indicators were detected when xlsx_analysis.indicators is non-empty.

PPTX static analysis: treat the reported findings as static-analysis evidence only.
- A VBA macro project means macro code is present, but does not by itself prove malicious behavior.
- Embedded objects, external relationships, URLs, and action or hyperlink elements do not by themselves prove malicious behavior.
- Never describe a PPTX finding as a DOCX or XLSX finding.
- Never claim a macro, embedded object, external relationship, URL, or action exists unless it is explicitly present in pptx_analysis.
- If pptx_analysis.indicators is non-empty, the reason must explicitly acknowledge the actual indicator(s).
- Do not say that no suspicious indicators were detected when pptx_analysis.indicators is non-empty.

ZIP static analysis guidance:
- ZIP findings are static-analysis evidence only. An executable or script member, nested archive, encryption, suspicious path, or compression/resource-abuse indicator does not automatically prove malicious behavior.
- Do not invent commands, payloads, execution behavior, URLs, or malware capabilities. Only mention files and indicators explicitly present in zip_analysis.
- Never confuse ZIP findings with DOCX, XLSX, or PPTX findings.
- If zip_analysis.indicators is non-empty, the reason MUST acknowledge the actual observed indicator(s).
- Do not claim that no suspicious indicators were detected when zip_analysis.indicators is non-empty.

IMAGE static analysis guidance:
- Image findings are static-analysis evidence only. EXIF metadata, large dimensions, animation, multiple frames, and URLs in image metadata do not automatically prove malicious behavior.
- Do not invent payloads, scripts, execution behavior, exploits, or malware capabilities. Only mention metadata and indicators explicitly present in image_analysis.
- Never confuse image findings with PDF, DOCX, XLSX, PPTX, or ZIP findings.
- If image_analysis.indicators is non-empty, the reason MUST acknowledge the actual observed indicator(s).
- Do not claim that no suspicious indicators were detected when image_analysis.indicators is non-empty.

SVG static analysis guidance:
- SVG findings are static-analysis evidence only. A script, event handler, external reference, javascript URL, embedded data, or XML entity/DOCTYPE construct does not automatically prove malware.
- Never invent payloads, execution behavior, URLs, exploits, or malware capabilities.
- If svg_analysis.indicators is non-empty, the reason MUST acknowledge the actual observed indicator(s).
- Never confuse SVG findings with PNG, JPEG, GIF, BMP, TIFF, or WEBP findings.

Printable snippet:
\"\"\"{extracted_text}\"\"\"

Return ONLY compact JSON with this exact schema:
{{"verdict":"SAFE","threat_score":0,"confidence":0,"reason":"short assessment","flagged_traits":[]}}
Allowed verdict values: SAFE, SUSPICIOUS, MALICIOUS.
When multiple DOCX findings are present, prioritize them in this order for the reason: VBA macro project, embedded object/OLE object, DDE, external relationship/URL.
If a VBA macro project is present, the reason MUST mention the VBA macro project before mentioning any external relationship or URL.
If an embedded object or OLE object is present and no VBA macro project is present, the reason MUST mention the embedded object/OLE object before any external relationship or URL.
If DDE is present and no higher-priority finding is present, the reason MUST mention the DDE finding.
If only an external relationship or URL is present, the reason MUST mention that external relationship or URL.
If indicators are present but do not establish malicious behavior, explicitly state that the finding was detected but is not sufficient by itself to establish malicious behavior.
Never describe a non-empty indicators list as having "no indicators".
Keep reason to one sentence, no markdown, no backticks, no extra text, and no backslashes unless escaped correctly.
"""

    try:
        raw_response = llm.invoke(system_prompt)

        if isinstance(raw_response, dict):
            candidate = raw_response.get("content") or raw_response.get("text") or json.dumps(raw_response)
        else:
            candidate = str(raw_response)

        candidate = (candidate or "").strip()
        if not candidate:
            raise ValueError("Empty model response")

        candidate = re.sub(r"^```(?:json)?\s*", "", candidate, flags=re.IGNORECASE)
        candidate = re.sub(r"\s*```\s*$", "", candidate, flags=re.IGNORECASE)
        candidate = candidate.strip()

        match = re.search(r"\{.*\}", candidate, flags=re.DOTALL)
        if match:
            candidate = match.group(0)

        try:
            result = json.loads(candidate)
        except json.JSONDecodeError:
            cleaned = candidate.replace("\t", " ")
            try:
                result = json.loads(cleaned)
            except json.JSONDecodeError:
                raise ValueError("Malformed JSON returned by AI")

        if not isinstance(result, dict):
            raise ValueError("AI returned a non-object JSON value")

        verdict = str(result.get("verdict", "")).upper()
        if verdict not in {"SAFE", "SUSPICIOUS", "MALICIOUS", "ANALYSIS_ERROR"}:
            raise ValueError("Invalid verdict returned by AI")

        try:
            threat_score = int(float(result.get("threat_score", 0)))
        except (TypeError, ValueError):
            threat_score = 0
        threat_score = max(0, min(100, threat_score))

        try:
            confidence = int(float(result.get("confidence", 0)))
        except (TypeError, ValueError):
            confidence = 0
        confidence = max(0, min(100, confidence))

        reason = result.get("reason", "")
        if not isinstance(reason, str):
            reason = "Security assessment based on static-analysis evidence."
        reason = reason.strip()[:300] or "Security assessment based on static-analysis evidence."

        flagged_traits = result.get("flagged_traits", [])
        if not isinstance(flagged_traits, list):
            flagged_traits = []
        flagged_traits = [str(item) for item in flagged_traits[:10] if str(item).strip()]

        return {
            "verdict": verdict,
            "threat_score": threat_score,
            "confidence": confidence,
            "reason": reason,
            "flagged_traits": flagged_traits,
        }

    except Exception:
        return {
            "verdict": "ANALYSIS_ERROR",
            "threat_score": 0,
            "confidence": 0,
            "reason": "AI returned an invalid response; static-analysis results remain available.",
            "flagged_traits": ["LLM returned invalid JSON"],
        }

def analyze_xlsx_static(data: bytes) -> dict:
    result = {
        "available": False,
        "macro": False,
        "embedded_objects": False,
        "external_links": False,
        "dde": False,
        "excel_4_macro_sheets": False,
        "add_in": False,
        "urls": [],
        "indicators": [],
    }

    try:
        with zipfile.ZipFile(io.BytesIO(data), "r") as z:
            names = z.namelist()
            result["available"] = True

            # VBA macro project detection
            if any(name.lower().endswith("vbaProject.bin".lower()) for name in names):
                result["macro"] = True
                result["indicators"].append(
                    "XLSX VBA macro project detected"
                )

            # Embedded OLE/object detection
            if any(
                name.lower().startswith("xl/embeddings/")
                for name in names
            ):
                result["embedded_objects"] = True
                result["indicators"].append(
                    "XLSX embedded objects detected"
                )

            # Excel 4.0 macro sheet detection
            if any(
                name.lower().startswith("xl/macrosheets/")
                for name in names
            ):
                result["excel_4_macro_sheets"] = True
                result["indicators"].append(
                    "Excel 4.0 macro sheet detected"
                )

            # Excel add-in content detection
            if any(
                name.lower().startswith("xl/addins/")
                for name in names
            ):
                result["add_in"] = True
                result["indicators"].append(
                    "Excel add-in content detected"
                )

            # External relationship and URL detection
            for name in names:
                if not name.lower().endswith(".rels"):
                    continue

                content = z.read(name).decode(
                    "utf-8",
                    errors="ignore"
                )

                if 'TargetMode="External"' in content:
                    result["external_links"] = True
                    result["indicators"].append(
                        "XLSX external relationship detected"
                    )

                urls = re.findall(
                    r'https?://[^\s"<>\']+',
                    content,
                    flags=re.IGNORECASE
                )

                for url in urls:
                    if (
                        "schemas.openxmlformats.org" not in url
                        and "schemas.microsoft.com" not in url
                        and url not in result["urls"]
                    ):
                        result["urls"].append(url)

            # Search worksheet/formula XML for DDE indicators
            for name in names:
                lower_name = name.lower()

                if not (
                    lower_name.endswith(".xml")
                    and (
                        lower_name.startswith("xl/worksheets/")
                        or lower_name.startswith("xl/charts/")
                    )
                ):
                    continue

                content = z.read(name).decode(
                    "utf-8",
                    errors="ignore"
                )

                lower_content = content.lower()

                if (
                    "ddeauto" in lower_content
                    or "dde" in lower_content
                    and "instrtext" in lower_content
                ):
                    result["dde"] = True
                    result["indicators"].append(
                        "XLSX DDE-related formula content detected"
                    )

            result["indicators"] = list(
                dict.fromkeys(result["indicators"])
            )

            return result

    except Exception:
        return result

def analyze_pptx_static(data: bytes) -> dict:
    """Inspect PPTX package structures without assigning a malware verdict."""
    result = {
        "available": False,
        "macro": False,
        "embedded_objects": False,
        "external_links": False,
        "actions": False,
        "urls": [],
        "indicators": [],
    }

    try:
        with zipfile.ZipFile(io.BytesIO(data), "r") as z:
            names = z.namelist()
            result["available"] = True

            if any(name.lower().endswith("vbaproject.bin") for name in names):
                result["macro"] = True
                result["indicators"].append("PPTX VBA macro project detected")

            if any(name.lower().startswith("ppt/embeddings/") for name in names):
                result["embedded_objects"] = True
                result["indicators"].append("PPTX embedded objects detected")

            for name in names:
                if not name.lower().endswith(".rels"):
                    continue

                content = z.read(name).decode("utf-8", errors="ignore")
                if 'TargetMode="External"' in content:
                    result["external_links"] = True
                    result["indicators"].append(
                        "PPTX external relationship detected"
                    )

                for url in re.findall(
                    r"https?://[^\s\"'<>]+", content, flags=re.IGNORECASE
                ):
                    if (
                        "schemas.openxmlformats.org" not in url.lower()
                        and "schemas.microsoft.com" not in url.lower()
                        and url not in result["urls"]
                    ):
                        result["urls"].append(url)

            for name in names:
                lower_name = name.lower()
                if not (
                    lower_name.startswith("ppt/slides/")
                    or lower_name.startswith("ppt/slidemasters/")
                    or lower_name == "ppt/presentation.xml"
                ):
                    continue

                content = z.read(name).decode("utf-8", errors="ignore")
                if any(
                    marker in content.lower()
                    for marker in (
                        "hlinkclick",
                        "<p:action",
                        "<p14:action",
                        "oleobject",
                    )
                ):
                    result["actions"] = True
                    result["indicators"].append(
                        "PPTX action or hyperlink element detected"
                    )

            result["indicators"] = list(dict.fromkeys(result["indicators"]))
            return result

    except Exception as exc:
        result["reason"] = f"PPTX parsing failed: {exc}"
        return result

def run_full_triage(data: bytes, filename: str) -> Dict[str, Any]:
    """
    Orchestrates the entire multi-tier pipeline:
    Tier 1: Disguise & Magic Byte Check
    Tier 2: Antivirus (ClamAV) + Shannon Entropy + Static Heuristics
    Tier 3: AI Specialist Triage (Only for worst-case / ambiguous payloads)
    """
    # 1. Tier 1: File Disguise & Type Detection
    type_info = detect_file_type(data, filename)
    
    # Critical immediate block: Spoofed extension or double extension
    if type_info["is_spoofed"] or type_info["is_double_extension"]:
        return {
            "status": "REJECTED",
            "verdict": "MALICIOUS",
            "stage": "TIER_1_DISGUISE_CHECK",
            "reason": "File extension spoofing or double-extension attack detected.",
            "details": type_info
        }

    # 2. Tier 2: ClamAV Antivirus Scan
    clam_infected, clam_threat = scan_clamav(data)
    if clam_infected:
        return {
            "status": "REJECTED",
            "verdict": "MALICIOUS",
            "stage": "TIER_2_CLAMAV",
            "reason": f"Known malware detected: {clam_threat}",
            "threat_name": clam_threat,
            "details": type_info
        }

    # 3. Tier 2: Heuristics & Entropy
    entropy = calculate_entropy(data)
    indicators = extract_suspicious_indicators(data)
    yara_matches = scan_yara(data)

    pdf_analysis = None

    if (
        type_info["actual_type"].lower() == "pdf"
        or type_info["mime_type"].lower() == "application/pdf"
    ):
        pdf_analysis = analyze_pdf_static(data)

        indicators.extend(pdf_analysis.get("indicators", []))

    docx_analysis = None

    if (
        type_info["actual_type"].lower() == "docx"
        or type_info["mime_type"].lower()
        == "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    ):
        docx_analysis = analyze_docx_static(data)

        indicators.extend(
            docx_analysis.get("indicators", [])
        )

    xlsx_analysis = None

    if (
        type_info["actual_type"].lower() == "xlsx"
        or type_info["mime_type"].lower()
        == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    ):
        xlsx_analysis = analyze_xlsx_static(data)

        indicators.extend(
            xlsx_analysis.get("indicators", [])
        )

    pptx_analysis = None

    if (
        type_info["actual_type"].lower() == "pptx"
        or type_info["mime_type"].lower()
        == "application/vnd.openxmlformats-officedocument.presentationml.presentation"
    ):
        pptx_analysis = analyze_pptx_static(data)

        indicators.extend(
            pptx_analysis.get("indicators", [])
        )

    actual_type = type_info["actual_type"].lower()
    mime_type = type_info["mime_type"].lower()
    office_package_detected = (
        actual_type in {"docx", "xlsx", "pptx"}
        or mime_type in {
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        }
    )
    is_zip_archive = (
        not office_package_detected
        and (
            actual_type in {"zip", "zip archive"}
            or mime_type in {"application/zip", "application/x-zip-compressed"}
            or zipfile.is_zipfile(io.BytesIO(data))
        )
    )

    zip_analysis = None

    if is_zip_archive:
        zip_analysis = analyze_zip_static(data)
        indicators.extend(zip_analysis.get("indicators", []))

    svg_analysis = None
    is_svg_file = (
        actual_type in {"svg", "svg+xml"}
        or mime_type == "image/svg+xml"
    )

    if is_svg_file:
        svg_analysis = analyze_svg_static(data)
        indicators.extend(svg_analysis.get("indicators", []))

    image_analysis = None
    image_types = {"jpeg", "jpg", "png", "gif", "bmp", "tiff", "webp"}
    is_image_file = (
        not is_svg_file
        and (
            actual_type in image_types
            or mime_type.startswith("image/")
        )
    )

    if is_image_file:
        image_analysis = analyze_image_static(data)
        indicators.extend(image_analysis.get("indicators", []))

    lief_analysis = None
    interesting_imports = []


    if type_info["is_executable"]:
        lief_analysis = analyze_executable_lief(data)
        interesting_imports = extract_interesting_imports(lief_analysis)
    
    context = {
        "interesting_imports": interesting_imports,
        "claimed_extension": type_info["claimed_extension"],
        "actual_type": type_info["actual_type"],
        "mime_type": type_info["mime_type"],
        "entropy": entropy,
        "indicators": indicators,
        "yara_matches": yara_matches,
        "pdf_analysis": pdf_analysis,
        "docx_analysis": docx_analysis,
        "xlsx_analysis": xlsx_analysis,
        "pptx_analysis": pptx_analysis,
        "zip_analysis": zip_analysis,
        "image_analysis": image_analysis,
        "svg_analysis": svg_analysis,
        "lief_analysis": lief_analysis,
    }

    # Criteria to invoke Tier 3 AI Specialist:
    # - Suspicious heuristics found
    # - Executable file format detected
    # - High entropy is retained as supporting evidence, not an automatic trigger
    needs_ai_triage = (
        len(indicators) > 0 or
        len(yara_matches) > 0
    )

    llm_result = None
    final_verdict = "SAFE"
    status = "APPROVED"

    if needs_ai_triage:
        llm_result = llm_worst_case_analysis(data, filename, context)

    if needs_ai_triage and not llm_result:
        final_verdict = "ANALYSIS_ERROR"
        status = "ANALYSIS_ERROR"

    elif llm_result is None:
        final_verdict = "SAFE"
        status = "APPROVED"

    elif llm_result.get("verdict") == "SAFE":
        docx_macro_detected = (
            type_info["actual_type"].lower() == "docx"
            and docx_analysis
            and docx_analysis.get("macro") is True
        )

        xlsx_macro_detected = (
            type_info["actual_type"].lower() == "xlsx"
            and xlsx_analysis
            and xlsx_analysis.get("macro") is True
        )

        pptx_macro_detected = (
            type_info["actual_type"].lower() == "pptx"
            and pptx_analysis
            and pptx_analysis.get("macro") is True
        )

        if docx_macro_detected or xlsx_macro_detected or pptx_macro_detected:
            final_verdict = "SUSPICIOUS"
            status = "QUARANTINE"
        else:
            final_verdict = "SAFE"
            status = "APPROVED"

    elif llm_result.get("verdict") == "MALICIOUS":
        final_verdict = "MALICIOUS"
        status = "REJECTED"

    elif llm_result.get("verdict") == "SUSPICIOUS":
        non_docx_indicators = [
            indicator
            for indicator in indicators
            if indicator != "DOCX external relationship detected"
        ]

        docx_only_external_link = (
            type_info["actual_type"].lower() == "docx"
            and docx_analysis
            and docx_analysis.get("external_links") is True
            and not docx_analysis.get("macro")
            and not docx_analysis.get("embedded_objects")
            and not docx_analysis.get("dde")
            and not yara_matches
            and not non_docx_indicators
            and not interesting_imports
        )

        xlsx_only_external_link = (
            type_info["actual_type"].lower() == "xlsx"
            and xlsx_analysis
            and xlsx_analysis.get("external_links") is True
            and not xlsx_analysis.get("macro")
            and not xlsx_analysis.get("embedded_objects")
            and not xlsx_analysis.get("dde")
            and not xlsx_analysis.get("excel_4_macro_sheets")
            and not xlsx_analysis.get("add_in")
            and not yara_matches
            and not interesting_imports
            and indicators == ["XLSX external relationship detected"]
        )

        pptx_only_external_link = (
            type_info["actual_type"].lower() == "pptx"
            and pptx_analysis
            and pptx_analysis.get("external_links") is True
            and not pptx_analysis.get("macro")
            and not pptx_analysis.get("embedded_objects")
            and not pptx_analysis.get("actions")
            and not yara_matches
            and not interesting_imports
            and indicators == ["PPTX external relationship detected"]
        )

        if docx_only_external_link or xlsx_only_external_link or pptx_only_external_link:
            final_verdict = "SAFE"
            status = "APPROVED"
        else:
            final_verdict = "SUSPICIOUS"
            status = "QUARANTINE"

    elif llm_result.get("verdict") == "ANALYSIS_ERROR":
        final_verdict = "ANALYSIS_ERROR"
        status = "ANALYSIS_ERROR"
    else:
        final_verdict = "ANALYSIS_ERROR"
        status = "ANALYSIS_ERROR"

    return {
        "interesting_imports": interesting_imports,
        "status": status,
        "verdict": final_verdict,
        "stage": "TIER_3_AI_TRIAGE" if needs_ai_triage else "TIER_2_PASSED",
        "file_info": type_info,
        "entropy": entropy,
        "indicators": indicators,
        "yara_matches": yara_matches,
        "pdf_analysis": pdf_analysis,
        "docx_analysis": docx_analysis,
        "xlsx_analysis": xlsx_analysis,
        "pptx_analysis": pptx_analysis,
        "zip_analysis": zip_analysis,
        "image_analysis": image_analysis,
        "svg_analysis": svg_analysis,
        "lief_analysis": lief_analysis,
        "clamav_status": "CLEAN" if not clam_threat else clam_threat,
        "ai_triage": llm_result
    }

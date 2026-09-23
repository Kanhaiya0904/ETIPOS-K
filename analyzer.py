import io
import math
import json
import re
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

If the supplied evidence directly shows executable APIs or YARA injection indicators, prefer SUSPICIOUS and explain only the observed evidence. For PDF files, JavaScript, OpenAction, additional actions, embedded files, Launch actions, and suspicious URI actions are static-analysis indicators that must be explicitly considered in the assessment. Their presence alone does not automatically prove malware.

File details:
- Filename: {filename}
- Claimed type: {context.get('claimed_extension')}
- Detected type: {context.get('actual_type')} ({context.get('mime_type')})
- Entropy: {context.get('entropy')}
- Indicators: {context.get('indicators')}
- YARA matches: {context.get('yara_matches')}
- PDF static analysis: {context.get('pdf_analysis')}
- LIEF analysis: {context.get('lief_analysis')}


Printable snippet:
\"\"\"{extracted_text}\"\"\"

Return ONLY compact JSON with this exact schema:
{{"verdict":"SAFE","threat_score":0,"confidence":0,"reason":"short assessment","flagged_traits":[]}}
Allowed verdict values: SAFE, SUSPICIOUS, MALICIOUS.
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
        final_verdict = "SAFE"
        status = "APPROVED"

    elif llm_result.get("verdict") == "MALICIOUS":
        final_verdict = "MALICIOUS"
        status = "REJECTED"

    elif llm_result.get("verdict") == "SUSPICIOUS":
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
        "lief_analysis": lief_analysis,
        "clamav_status": "CLEAN" if not clam_threat else clam_threat,
        "ai_triage": llm_result
    }

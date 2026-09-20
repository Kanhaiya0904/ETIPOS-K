import io
import math
import json
import re
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
        "sh", "vbs", "javascript", "python", "autorun"
    }

    is_dangerous_executable = actual_label in executable_labels
    spoofed = False

    # Check if a non-executable extension claims an executable payload
    innocent_extensions = {"pdf", "jpg", "jpeg", "png", "gif", "txt", "docx", "xlsx", "mp4", "mp3"}
    if claimed_ext in innocent_extensions and is_dangerous_executable:
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
    Extracts suspicious heuristic markers such as shellcode APIs,
    PowerShell encoded commands, dangerous system calls, or eval loops.
    """
    indicators = []
    # Sample up to first 1MB for heuristic string checks
    sample = data[:1024 * 1024]
    
    patterns = [
        (b"powershell", "PowerShell invocation detected"),
        (b"-enc", "Possible base64 encoded command flag"),
        (b"WScript.Shell", "Windows Script Host invocation"),
        (b"FromBase64String", "Base64 payload de-obfuscation marker"),
        (b"VirtualAlloc", "Memory allocation API often used for shellcode injection"),
        (b"CreateRemoteThread", "Thread injection API detected"),
        (b"cmd.exe", "Command prompt invocation"),
        (b"eval(", "Dynamic code execution (eval) detected"),
        (b"exec(", "Dynamic execution (exec) detected"),
        (b"/bin/sh", "Unix shell execution detected"),
        (b"/bin/bash", "Unix bash execution detected"),
        (b"curl ", "Embedded HTTP downloader detected"),
        (b"wget ", "Embedded HTTP downloader detected"),
    ]

    for pat, desc in patterns:
        if pat.lower() in sample.lower():
            indicators.append(desc)

    return indicators

def llm_worst_case_analysis(data: bytes, filename: str, context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Tier 3: Specialized LLM Security Auditor.
    Only triggered when a file is suspicious, obfuscated, or ambiguous.
    Passes extracted printable strings and metadata (NOT dangerous raw execution).
    """
    # Extract printable ASCII/UTF-8 snippets safely
    sample = data[:4096]
    printable_chars = [chr(b) if 32 <= b <= 126 or b in (10, 13, 9) else " " for b in sample]
    extracted_text = "".join(printable_chars).strip()
    # Compact multiple spaces
    extracted_text = re.sub(r"\s+", " ", extracted_text)[:1500]

    system_prompt = f"""You are a specialized malware and security triage analyst.
Your job is to analyze suspicious or anomalous files that passed standard filters but exhibit abnormal characteristics.

File Details:
- Filename: {filename}
- Claimed Type: {context.get('claimed_extension')}
- Detected Type: {context.get('actual_type')} ({context.get('mime_type')})
- Shannon Entropy: {context.get('entropy')} (Normal text/code is 3.5-5.5, high is >7.0)
- Detected Indicators: {context.get('indicators')}

Extracted Printable Byte Snippet (First 1.5KB sanitized):
\"\"\"{extracted_text}\"\"\"

Evaluate if this file exhibits indicators of malicious intent (such as obfuscation, reverse shells, dropper behavior, malicious macros, or exploit staging).

Respond ONLY with a valid JSON object in this exact schema (no markdown, no backticks, no explanations outside JSON):
{{
  "verdict": "SAFE" or "SUSPICIOUS" or "MALICIOUS",
  "threat_score": <number from 0 to 100>,
  "confidence": <number from 0 to 100>,
  "reason": "<one or two sentences explaining your security assessment>",
  "flagged_traits": ["<trait 1>", "<trait 2>"]
}}
"""
    try:
        raw_response = llm.invoke(system_prompt).strip()
        # Clean potential markdown wrapping
        cleaned = re.sub(r"^```json\s*", "", raw_response)
        cleaned = re.sub(r"^```\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned).strip()
        result = json.loads(cleaned)
        return result
    except Exception as e:
        return {
            "verdict": "ANALYSIS_ERROR",
            "threat_score": 0,
            "confidence": 0,
            "reason": f"AI triage could not be completed: {str(e)}",
            "flagged_traits": ["LLM evaluation unavailable"]
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
    
    context = {
        "claimed_extension": type_info["claimed_extension"],
        "actual_type": type_info["actual_type"],
        "mime_type": type_info["mime_type"],
        "entropy": entropy,
        "indicators": indicators
    }

    # Criteria to invoke Tier 3 AI Specialist:
    # - Suspicious heuristics found
    # - Executable file format detected
    # - High entropy is retained as supporting evidence, not an automatic trigger
    needs_ai_triage = (
        len(indicators) > 0 or
        type_info["is_executable"]
    )

    llm_result = None
    final_verdict = "SAFE"
    status = "APPROVED"

    if needs_ai_triage:
        llm_result = llm_worst_case_analysis(data, filename, context)
        if llm_result.get("verdict") == "MALICIOUS" or llm_result.get("threat_score", 0) >= 70:
            final_verdict = "MALICIOUS"
            status = "REJECTED"
        elif llm_result.get("verdict") == "SUSPICIOUS" or llm_result.get("threat_score", 0) >= 40:
            final_verdict = "SUSPICIOUS"
            status = "QUARANTINE"
        elif llm_result.get("verdict") == "ANALYSIS_ERROR":
            final_verdict = "ANALYSIS_ERROR"
            status = "ANALYSIS_ERROR"

    return {
        "status": status,
        "verdict": final_verdict,
        "stage": "TIER_3_AI_TRIAGE" if needs_ai_triage else "TIER_2_PASSED",
        "file_info": type_info,
        "entropy": entropy,
        "indicators": indicators,
        "clamav_status": "CLEAN" if not clam_threat else clam_threat,
        "ai_triage": llm_result
    }

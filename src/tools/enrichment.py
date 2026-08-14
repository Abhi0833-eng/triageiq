"""
Threat Intelligence Enrichment Module
Supports VirusTotal v3 API, AbuseIPDB v2 API, and intelligent offline fallbacks.
"""

import os
import re
import requests
from typing import Dict, Any
from src.schema import ThreatIntel


# Pre-computed threat intelligence registry for offline/demo reliability
KNOWN_IOC_DATABASE: Dict[str, Dict[str, Any]] = {
    # Known Malicious IPs & Hashes (from Attack Scenarios)
    "185.220.101.5": {
        "ioc_type": "ip",
        "reputation_score": 92,
        "malicious_votes": 48,
        "benign_votes": 2,
        "threat_tags": ["Tor Exit Node", "Known Scanner", "AbuseIPDB High Risk"],
        "details": "AbuseIPDB score 92%. Reported 1,420 times for SSH brute-force and port scans."
    },
    "198.51.100.42": {
        "ioc_type": "ip",
        "reputation_score": 88,
        "malicious_votes": 35,
        "benign_votes": 1,
        "threat_tags": ["APT29 C2 Server", "Credential Harvester", "Phishing Infrastructure"],
        "details": "Associated with APT29 phishing campaign targeting enterprise OAuth endpoints."
    },
    "45.146.164.110": {
        "ioc_type": "ip",
        "reputation_score": 96,
        "malicious_votes": 62,
        "benign_votes": 0,
        "threat_tags": ["LockBit Ransomware", "C2 Beacon", "Cobalt Strike Stager"],
        "details": "Active C2 beacon server flagged by VirusTotal vendor engines."
    },
    "b10a8db164e0d9b4b0e5170327f2c8d2": {
        "ioc_type": "hash",
        "reputation_score": 99,
        "malicious_votes": 57,
        "benign_votes": 0,
        "threat_tags": ["LockBit 3.0 Binary", "Ransomware Encryptor", "Shadow Copy Deleter"],
        "details": "VirusTotal 57/70 antivirus engines detect LockBit 3.0 ransomware executable."
    },
    "login-secure-auth-update.com": {
        "ioc_type": "domain",
        "reputation_score": 85,
        "malicious_votes": 22,
        "benign_votes": 3,
        "threat_tags": ["Typosquatting", "Credential Phishing", "Recently Registered"],
        "details": "Registered 2 days ago via privacy WHOIS. Impersonating corporate SSO portal."
    },
    "dns-tunnel-exfil-node.ru": {
        "ioc_type": "domain",
        "reputation_score": 94,
        "malicious_votes": 41,
        "benign_votes": 0,
        "threat_tags": ["DNS Exfiltration Target", "Data Staging", "Suspicious TLD"],
        "details": "Known command-and-control destination receiving encoded TXT query data."
    },
    # Benign / Internal IPs
    "10.0.0.45": {
        "ioc_type": "ip",
        "reputation_score": 0,
        "malicious_votes": 0,
        "benign_votes": 100,
        "threat_tags": ["Internal Workstation", "RFC1918 Private Subnet"],
        "details": "Internal private network endpoint (Engineering Workstation-04)."
    },
    "192.168.1.10": {
        "ioc_type": "ip",
        "reputation_score": 0,
        "malicious_votes": 0,
        "benign_votes": 100,
        "threat_tags": ["Internal Domain Controller", "Private Subnet"],
        "details": "Internal AD Domain Controller (DC-SEC-01)."
    }
}


def detect_ioc_type(ioc: str) -> str:
    """Classifies an IOC string as ip, domain, or hash."""
    ip_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    hash_pattern = r"^[a-fA-F0-9]{32,64}$"
    
    if re.match(ip_pattern, ioc):
        return "ip"
    elif re.match(hash_pattern, ioc):
        return "hash"
    else:
        return "domain"


def enrich_ioc(ioc: str) -> ThreatIntel:
    """
    Enriches an IOC by checking live APIs (VirusTotal, AbuseIPDB) or falling back to
    intelligent mock threat intelligence data.
    """
    ioc = ioc.strip()
    vt_key = os.getenv("VIRUSTOTAL_API_KEY")
    abuse_key = os.getenv("ABUSEIPDB_API_KEY")
    ioc_type = detect_ioc_type(ioc)

    # 1. Try VirusTotal v3 API if key is present
    if vt_key and ioc_type in ["ip", "domain", "hash"]:
        try:
            headers = {"x-apikey": vt_key}
            endpoint = f"https://www.virustotal.com/api/v3/{'ip_addresses' if ioc_type=='ip' else ('domains' if ioc_type=='domain' else 'files')}/{ioc}"
            resp = requests.get(endpoint, headers=headers, timeout=4)
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                harmless = stats.get("harmless", 0)
                total = sum(stats.values()) or 1
                rep_score = int((malicious / total) * 100)
                
                return ThreatIntel(
                    ioc=ioc,
                    ioc_type=ioc_type,
                    reputation_score=rep_score,
                    malicious_votes=malicious,
                    benign_votes=harmless,
                    threat_tags=data.get("tags", ["VirusTotal Scanned"]),
                    source_api="VirusTotal API v3",
                    details=f"VirusTotal detections: {malicious}/{total} security vendors."
                )
        except Exception as e:
            pass  # Fallback to AbuseIPDB or Offline DB

    # 2. Try AbuseIPDB v2 API if key is present and IOC is IP
    if abuse_key and ioc_type == "ip":
        try:
            headers = {"Key": abuse_key, "Accept": "application/json"}
            params = {"ipAddress": ioc, "maxAgeInDays": 90}
            resp = requests.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params, timeout=4)
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                abuse_score = data.get("abuseConfidenceScore", 0)
                total_reports = data.get("totalReports", 0)
                
                return ThreatIntel(
                    ioc=ioc,
                    ioc_type="ip",
                    reputation_score=abuse_score,
                    malicious_votes=total_reports,
                    benign_votes=100 - abuse_score,
                    threat_tags=["AbuseIPDB Flagged"] if abuse_score > 50 else ["Clean IP"],
                    source_api="AbuseIPDB API v2",
                    details=f"Abuse confidence score: {abuse_score}%. Total reports: {total_reports}."
                )
        except Exception as e:
            pass

    # 3. Fallback to Known Database or Intelligent Dynamic Fallback
    if ioc in KNOWN_IOC_DATABASE:
        item = KNOWN_IOC_DATABASE[ioc]
        return ThreatIntel(
            ioc=ioc,
            ioc_type=item["ioc_type"],
            reputation_score=item["reputation_score"],
            malicious_votes=item["malicious_votes"],
            benign_votes=item["benign_votes"],
            threat_tags=item["threat_tags"],
            source_api="Offline Threat DB (Simulated)",
            details=item["details"]
        )

    # General fallback for arbitrary unseen external IPs/domains
    is_private = ioc.startswith("10.") or ioc.startswith("192.168.") or ioc.startswith("172.16.")
    if is_private:
        return ThreatIntel(
            ioc=ioc,
            ioc_type=ioc_type,
            reputation_score=0,
            malicious_votes=0,
            benign_votes=100,
            threat_tags=["Internal Network Asset"],
            source_api="Offline Threat DB (Simulated)",
            details="Private IP address inside local subnet."
        )
    else:
        return ThreatIntel(
            ioc=ioc,
            ioc_type=ioc_type,
            reputation_score=25,
            malicious_votes=3,
            benign_votes=40,
            threat_tags=["Uncategorized External Asset"],
            source_api="Offline Threat DB (Simulated)",
            details="External address with low-risk baseline reputation."
        )

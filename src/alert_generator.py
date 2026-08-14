"""
Attack Scenario & Synthetic Alert Generator for TriageIQ
Provides 5 realistic attack scenarios and custom raw alert import functions.
"""

from typing import List, Dict, Any
from datetime import datetime, timedelta


ATTACK_SCENARIOS: Dict[str, Dict[str, Any]] = {
    "APT29_OAuth_Phishing": {
        "title": "APT29 Credential Theft & OAuth Abuse",
        "description": "Multi-stage credential harvesting campaign using spoofed OAuth application permissions.",
        "expected_severity": "HIGH",
        "alerts": [
            {
                "alert_id": "ALT-2026-09101",
                "timestamp": (datetime.utcnow() - timedelta(minutes=25)).isoformat(),
                "source_ip": "198.51.100.42",
                "destination_ip": "10.0.0.45",
                "destination_port": 443,
                "protocol": "HTTPS",
                "event_type": "Suspicious External Authentication",
                "raw_severity": "MEDIUM",
                "user": "j.smith@corp.local",
                "hostname": "workstation-04",
                "payload": {
                    "login_location": "Moscow, RU",
                    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                    "auth_result": "SUCCESS_MFA_BYPASSED"
                },
                "iocs": ["198.51.100.42", "login-secure-auth-update.com"]
            },
            {
                "alert_id": "ALT-2026-09102",
                "timestamp": (datetime.utcnow() - timedelta(minutes=18)).isoformat(),
                "source_ip": "198.51.100.42",
                "destination_ip": "10.0.0.45",
                "destination_port": 443,
                "protocol": "HTTPS",
                "event_type": "OAuth App Consent Granted",
                "raw_severity": "HIGH",
                "user": "j.smith@corp.local",
                "hostname": "workstation-04",
                "payload": {
                    "app_name": "SecureAuth_Update_Helper",
                    "permissions": ["Mail.ReadWrite", "Directory.ReadWrite.All", "User.Read"]
                },
                "iocs": ["198.51.100.42", "login-secure-auth-update.com"]
            },
            {
                "alert_id": "ALT-2026-09103",
                "timestamp": (datetime.utcnow() - timedelta(minutes=5)).isoformat(),
                "source_ip": "198.51.100.42",
                "destination_ip": "192.168.1.10",
                "destination_port": 389,
                "protocol": "LDAP",
                "event_type": "Active Directory Privilege Escalation Attempt",
                "raw_severity": "HIGH",
                "user": "j.smith@corp.local",
                "hostname": "DC-SEC-01",
                "payload": {
                    "target_group": "Domain Admins",
                    "action": "AddMemberRequest"
                },
                "iocs": ["198.51.100.42"]
            }
        ]
    },
    "LockBit_Ransomware": {
        "title": "LockBit 3.0 Ransomware Encryption Attempt",
        "description": "Rapid shadow copy deletion, malicious payload execution, and active C2 beaconing.",
        "expected_severity": "CRITICAL",
        "alerts": [
            {
                "alert_id": "ALT-2026-09201",
                "timestamp": (datetime.utcnow() - timedelta(minutes=12)).isoformat(),
                "source_ip": "10.0.0.88",
                "destination_ip": "10.0.0.88",
                "destination_port": 0,
                "protocol": "LOCAL",
                "event_type": "Volume Shadow Copy Deletion (vssadmin)",
                "raw_severity": "HIGH",
                "user": "SYSTEM",
                "hostname": "FINANCE-SERVER-02",
                "payload": {
                    "cmdline": "vssadmin.exe Delete Shadows /All /Quiet",
                    "parent_process": "cmd.exe"
                },
                "iocs": ["b10a8db164e0d9b4b0e5170327f2c8d2"]
            },
            {
                "alert_id": "ALT-2026-09202",
                "timestamp": (datetime.utcnow() - timedelta(minutes=10)).isoformat(),
                "source_ip": "10.0.0.88",
                "destination_ip": "10.0.0.88",
                "destination_port": 0,
                "protocol": "LOCAL",
                "event_type": "Malware Execution Detected",
                "raw_severity": "CRITICAL",
                "user": "SYSTEM",
                "hostname": "FINANCE-SERVER-02",
                "payload": {
                    "file_path": "C:\\Windows\\Temp\\update.exe",
                    "file_hash": "b10a8db164e0d9b4b0e5170327f2c8d2",
                    "signature": "Unsigned"
                },
                "iocs": ["b10a8db164e0d9b4b0e5170327f2c8d2"]
            },
            {
                "alert_id": "ALT-2026-09203",
                "timestamp": (datetime.utcnow() - timedelta(minutes=3)).isoformat(),
                "source_ip": "10.0.0.88",
                "destination_ip": "45.146.164.110",
                "destination_port": 8443,
                "protocol": "TCP",
                "event_type": "Encrypted Outbound C2 Beacon",
                "raw_severity": "HIGH",
                "user": "SYSTEM",
                "hostname": "FINANCE-SERVER-02",
                "payload": {
                    "bytes_sent": 45020,
                    "beacon_interval_sec": 30
                },
                "iocs": ["45.146.164.110", "b10a8db164e0d9b4b0e5170327f2c8d2"]
            }
        ]
    },
    "SSH_Brute_Force": {
        "title": "SSH Brute Force & Compromise",
        "description": "High volume authentication failure stream from Tor exit node resulting in root account compromise.",
        "expected_severity": "HIGH",
        "alerts": [
            {
                "alert_id": "ALT-2026-09301",
                "timestamp": (datetime.utcnow() - timedelta(minutes=40)).isoformat(),
                "source_ip": "185.220.101.5",
                "destination_ip": "192.168.1.50",
                "destination_port": 22,
                "protocol": "SSH",
                "event_type": "High Rate SSH Authentication Failures",
                "raw_severity": "MEDIUM",
                "user": "root",
                "hostname": "bastion-host-01",
                "payload": {
                    "failed_attempts": 340,
                    "time_window_sec": 60
                },
                "iocs": ["185.220.101.5"]
            },
            {
                "alert_id": "ALT-2026-09302",
                "timestamp": (datetime.utcnow() - timedelta(minutes=35)).isoformat(),
                "source_ip": "185.220.101.5",
                "destination_ip": "192.168.1.50",
                "destination_port": 22,
                "protocol": "SSH",
                "event_type": "SSH Login Success Following Failures",
                "raw_severity": "HIGH",
                "user": "root",
                "hostname": "bastion-host-01",
                "payload": {
                    "auth_method": "password",
                    "session_id": "ssh-sess-994"
                },
                "iocs": ["185.220.101.5"]
            }
        ]
    },
    "Internal_Port_Scan_Noise": {
        "title": "Internal Security Scanner Reconnaissance (Noise)",
        "description": "Routine scheduled security scan from known internal IT vulnerability scanner.",
        "expected_severity": "FALSE_POSITIVE",
        "alerts": [
            {
                "alert_id": "ALT-2026-09401",
                "timestamp": (datetime.utcnow() - timedelta(minutes=15)).isoformat(),
                "source_ip": "10.0.0.45",
                "destination_ip": "192.168.1.10",
                "destination_port": 80,
                "protocol": "TCP",
                "event_type": "TCP Port Sweep Detected",
                "raw_severity": "LOW",
                "user": "sec_scanner_svc",
                "hostname": "SEC-QUALYS-SCANNER",
                "payload": {
                    "ports_scanned": [80, 443, 8080, 8443, 22],
                    "scan_type": "SYN_SWEEP"
                },
                "iocs": ["10.0.0.45"]
            },
            {
                "alert_id": "ALT-2026-09402",
                "timestamp": (datetime.utcnow() - timedelta(minutes=14)).isoformat(),
                "source_ip": "10.0.0.45",
                "destination_ip": "192.168.1.10",
                "destination_port": 443,
                "protocol": "HTTPS",
                "event_type": "SSL Certificate Enumeration",
                "raw_severity": "INFORMATIONAL",
                "user": "sec_scanner_svc",
                "hostname": "SEC-QUALYS-SCANNER",
                "payload": {
                    "scan_id": "QUALYS-WEEKLY-JOB-12"
                },
                "iocs": ["10.0.0.45"]
            }
        ]
    },
    "DNS_Data_Exfiltration": {
        "title": "DNS Tunneling Data Exfiltration",
        "description": "High entropy DNS TXT query flood exfiltrating confidential database dumps.",
        "expected_severity": "CRITICAL",
        "alerts": [
            {
                "alert_id": "ALT-2026-09501",
                "timestamp": (datetime.utcnow() - timedelta(minutes=30)).isoformat(),
                "source_ip": "10.0.0.99",
                "destination_ip": "10.0.0.1",
                "destination_port": 53,
                "protocol": "DNS",
                "event_type": "Anomalous DNS TXT Query Volume",
                "raw_severity": "HIGH",
                "user": "db_admin",
                "hostname": "SQL-PROD-DB-01",
                "payload": {
                    "domain": "dns-tunnel-exfil-node.ru",
                    "query_count": 1240,
                    "avg_subdomain_length": 64
                },
                "iocs": ["dns-tunnel-exfil-node.ru", "10.0.0.99"]
            },
            {
                "alert_id": "ALT-2026-09502",
                "timestamp": (datetime.utcnow() - timedelta(minutes=15)).isoformat(),
                "source_ip": "10.0.0.99",
                "destination_ip": "10.0.0.1",
                "destination_port": 53,
                "protocol": "DNS",
                "event_type": "Data Staging in Temp Directory",
                "raw_severity": "MEDIUM",
                "user": "db_admin",
                "hostname": "SQL-PROD-DB-01",
                "payload": {
                    "path": "C:\\Users\\Public\\cust_records.7z",
                    "archive_size_mb": 450.5
                },
                "iocs": ["10.0.0.99"]
            }
        ]
    }
}


def get_scenario_keys() -> List[str]:
    """Returns list of attack scenario keys."""
    return list(ATTACK_SCENARIOS.keys())


def load_scenario(scenario_key: str) -> List[Dict[str, Any]]:
    """Loads raw alert list for a given scenario."""
    if scenario_key in ATTACK_SCENARIOS:
        return ATTACK_SCENARIOS[scenario_key]["alerts"]
    return []

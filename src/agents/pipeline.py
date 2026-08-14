"""
LangGraph Multi-Agent Pipeline for TriageIQ SOC Alert System
Connects Ingestion -> Enrichment -> Correlation -> Triage -> Reporting nodes.
"""

import os
from typing import Dict, Any, List
from langgraph.graph import StateGraph, END
from langchain_groq import ChatGroq
from langchain_core.messages import SystemMessage, HumanMessage

from src.schema import (
    SOCAlert, ThreatIntel, CorrelatedGroup, TriageDecision, IncidentReport, TriageState
)
from src.tools.enrichment import enrich_ioc


def get_llm():
    """Returns a ChatGroq LLM instance if API key exists, else None."""
    groq_key = os.getenv("GROQ_API_KEY")
    if groq_key:
        try:
            return ChatGroq(model_name="llama-3.3-70b-versatile", groq_api_key=groq_key, temperature=0.1)
        except Exception:
            pass
    return None


# ----------------------------------------------------------------------
# AGENT NODES
# ----------------------------------------------------------------------

def ingest_node(state: TriageState) -> Dict[str, Any]:
    """Node 1: Ingests raw alert feeds and normalizes them into SOCAlert objects."""
    raw_alerts = state.get("raw_alerts", [])
    alerts: List[SOCAlert] = []
    
    for item in raw_alerts:
        # Auto-extract IOCs from payload if not specified
        payload = item.get("payload", {})
        iocs = list(item.get("iocs", []))
        if item.get("source_ip") and item["source_ip"] not in iocs:
            iocs.append(item["source_ip"])
        if item.get("destination_ip") and item["destination_ip"] not in iocs:
            iocs.append(item["destination_ip"])
            
        alert_obj = SOCAlert(
            alert_id=item["alert_id"],
            timestamp=item.get("timestamp"),
            source_ip=item["source_ip"],
            destination_ip=item["destination_ip"],
            destination_port=item.get("destination_port", 80),
            protocol=item.get("protocol", "TCP"),
            event_type=item["event_type"],
            raw_severity=item.get("raw_severity", "MEDIUM"),
            user=item.get("user", "SYSTEM"),
            hostname=item.get("hostname", "workstation-01"),
            payload=payload,
            iocs=iocs
        )
        alerts.append(alert_obj)

    trace = state.get("trace_logs", [])
    trace.append({
        "node": "Ingestion Agent",
        "status": "COMPLETED",
        "detail": f"Parsed and normalized {len(alerts)} raw security alerts."
    })
    
    return {
        "alerts": alerts,
        "trace_logs": trace,
        "current_step": "INGESTION_COMPLETE"
    }


def enrich_node(state: TriageState) -> Dict[str, Any]:
    """Node 2: Threat Intel Enrichment Agent (VirusTotal & AbuseIPDB)."""
    alerts = state.get("alerts", [])
    intel_map: Dict[str, ThreatIntel] = {}

    for alert in alerts:
        for ioc in alert.iocs:
            if ioc not in intel_map:
                intel_map[ioc] = enrich_ioc(ioc)

    trace = state.get("trace_logs", [])
    trace.append({
        "node": "Enrichment Agent",
        "status": "COMPLETED",
        "detail": f"Scanned VirusTotal & AbuseIPDB threat feeds for {len(intel_map)} unique IOCs."
    })

    return {
        "threat_intel": intel_map,
        "trace_logs": trace,
        "current_step": "ENRICHMENT_COMPLETE"
    }


def correlate_node(state: TriageState) -> Dict[str, Any]:
    """Node 3: Alert Correlation Agent (Groups alerts into campaign timelines)."""
    alerts = state.get("alerts", [])
    threat_intel = state.get("threat_intel", {})
    
    # Group by source_ip or primary IOC
    clusters: Dict[str, List[SOCAlert]] = {}
    for alert in alerts:
        key = alert.source_ip
        if key not in clusters:
            clusters[key] = []
        clusters[key].append(alert)

    correlations: List[CorrelatedGroup] = []
    idx = 1

    for src_ip, alert_group in clusters.items():
        alert_ids = [a.alert_id for a in alert_group]
        max_rep = max([threat_intel.get(a.source_ip, ThreatIntel(ioc=src_ip, ioc_type="ip")).reputation_score for a in alert_group] + [0])
        
        # Determine attack stage
        event_types = [a.event_type.lower() for a in alert_group]
        if any("shadow" in e or "malware" in e or "encrypt" in e for e in event_types):
            stage = "Execution & Impact (Ransomware)"
        elif any("exfil" in e or "dns" in e for e in event_types):
            stage = "Exfiltration"
        elif any("privilege" in e or "oauth" in e or "admin" in e for e in event_types):
            stage = "Privilege Escalation / Credential Theft"
        elif any("brute" in e or "login" in e for e in event_types):
            stage = "Initial Access / Credential Access"
        else:
            stage = "Reconnaissance / Port Scanning"

        composite_risk = float(max_rep) * 0.7 + (len(alert_group) * 10.0)
        
        correlations.append(CorrelatedGroup(
            campaign_id=f"CMP-2026-{idx:03d}",
            alert_ids=alert_ids,
            primary_ip=src_ip,
            target_asset=alert_group[0].hostname or alert_group[0].destination_ip,
            attack_stage=stage,
            risk_score=min(composite_risk, 100.0),
            summary=f"Campaign of {len(alert_group)} alerts from {src_ip} targeting {alert_group[0].hostname}."
        ))
        idx += 1

    trace = state.get("trace_logs", [])
    trace.append({
        "node": "Correlation Agent",
        "status": "COMPLETED",
        "detail": f"Correlated alerts into {len(correlations)} attack campaign clusters."
    })

    return {
        "correlations": correlations,
        "trace_logs": trace,
        "current_step": "CORRELATION_COMPLETE"
    }


def triage_node(state: TriageState) -> Dict[str, Any]:
    """Node 4: Triage & Severity Agent (LLM Reasoning + Rules Heuristics)."""
    alerts = state.get("alerts", [])
    threat_intel = state.get("threat_intel", {})
    correlations = state.get("correlations", [])
    llm = get_llm()

    triage_decisions: Dict[str, TriageDecision] = {}
    dismissed_count = 0

    for alert in alerts:
        ip_intel = threat_intel.get(alert.source_ip)
        rep_score = ip_intel.reputation_score if ip_intel else 0
        
        # Rule & Heuristic baseline
        is_internal_scanner = "scanner" in (alert.hostname or "").lower() or alert.user == "sec_scanner_svc" or rep_score == 0 and "sweep" in alert.event_type.lower()
        is_critical_malware = rep_score > 80 or "ransomware" in alert.event_type.lower() or "exfil" in alert.event_type.lower() or "shadow" in alert.event_type.lower()
        
        if is_internal_scanner:
            calc_severity = "FALSE_POSITIVE"
            action = "AUTO_DISMISS"
            reasoning = "Activity originates from authorized internal security scanning service. Suppressing alert to eliminate noise."
            dismissed_count += 1
            mitre = ["TA0043 Reconnaissance"]
        elif is_critical_malware:
            calc_severity = "CRITICAL" if rep_score > 90 else "HIGH"
            action = "ESCALATE"
            reasoning = f"High threat intelligence score ({rep_score}%) combined with destructive event signature ({alert.event_type}). Immediate SOC containment required."
            mitre = ["TA0002 Execution", "TA0040 Impact", "TA0011 Command and Control"]
        elif rep_score > 50 or "escalation" in alert.event_type.lower() or "oauth" in alert.event_type.lower():
            calc_severity = "HIGH"
            action = "ESCALATE"
            reasoning = f"Elevated IOC risk score ({rep_score}%) associated with credential manipulation or privilege escalation."
            mitre = ["TA0004 Privilege Escalation", "TA0006 Credential Access"]
        elif "brute" in alert.event_type.lower():
            calc_severity = "MEDIUM"
            action = "NEEDS_HUMAN_REVIEW"
            reasoning = "Authentication failure burst detected. Requires verification if login eventually succeeded."
            mitre = ["TA0006 Credential Access"]
        else:
            calc_severity = "LOW"
            action = "AUTO_DISMISS"
            reasoning = "Low risk rating with clean threat intelligence score."
            dismissed_count += 1
            mitre = ["TA0043 Reconnaissance"]

        # Enhance reasoning with LLM if available
        if llm and action != "AUTO_DISMISS":
            try:
                sys_msg = SystemMessage(content="You are an expert Tier-3 SOC Analyst. Provide a 1-sentence technical triage justification for the alert.")
                usr_msg = HumanMessage(content=f"Alert: {alert.event_type}, Source IP: {alert.source_ip}, Threat Score: {rep_score}%, Payload: {alert.payload}")
                res = llm.invoke([sys_msg, usr_msg])
                if res and res.content:
                    reasoning = f"{reasoning} [LLM Assessment: {res.content.strip()}]"
            except Exception:
                pass

        triage_decisions[alert.alert_id] = TriageDecision(
            alert_id=alert.alert_id,
            action=action,
            calculated_severity=calc_severity,
            confidence_score=0.95 if action != "NEEDS_HUMAN_REVIEW" else 0.82,
            reasoning=reasoning,
            mitre_tactics=mitre
        )

    noise_reduction = (dismissed_count / len(alerts) * 100.0) if alerts else 0.0

    trace = state.get("trace_logs", [])
    trace.append({
        "node": "Triage Agent",
        "status": "COMPLETED",
        "detail": f"Scored severity across {len(alerts)} alerts. Auto-dismissed {dismissed_count} false positives ({noise_reduction:.1f}% noise reduction)."
    })

    return {
        "triage_decisions": triage_decisions,
        "noise_reduced_percent": noise_reduction,
        "trace_logs": trace,
        "current_step": "TRIAGE_COMPLETE"
    }


def report_node(state: TriageState) -> Dict[str, Any]:
    """Node 5: Reporting Agent (Generates Markdown Incident Reports)."""
    alerts = state.get("alerts", [])
    correlations = state.get("correlations", [])
    triage_decisions = state.get("triage_decisions", {})
    threat_intel = state.get("threat_intel", {})

    reports: List[IncidentReport] = []

    for corp in correlations:
        # Check if any alert in campaign was escalated
        campaign_alerts = [a for a in alerts if a.alert_id in corp.alert_ids]
        escalated = any(triage_decisions.get(a.alert_id, TriageDecision(alert_id=a.alert_id, action="AUTO_DISMISS", calculated_severity="LOW", reasoning="")).action == "ESCALATE" for a in campaign_alerts)

        if not escalated and corp.risk_score < 40:
            continue  # Skip report for suppressed noise

        max_sev = "CRITICAL" if corp.risk_score > 80 else ("HIGH" if corp.risk_score > 50 else "MEDIUM")
        
        # Build timeline
        timeline = []
        evidence = []
        mitre_tactics = set()

        for a in campaign_alerts:
            timeline.append({
                "timestamp": a.timestamp,
                "event": f"{a.event_type} ({a.source_ip} -> {a.destination_ip})"
            })
            evidence.append(f"`{a.alert_id}`: {a.event_type} | User: `{a.user}` | Payload: {a.payload}")
            dec = triage_decisions.get(a.alert_id)
            if dec:
                mitre_tactics.update(dec.mitre_tactics)

        mitre_list = list(mitre_tactics) or ["TA0001 Initial Access", "TA0004 Privilege Escalation"]
        
        # Build markdown report body
        md_body = f"""# 🚨 SOC Incident Report: {corp.campaign_id}

**Target Asset:** `{corp.target_asset}` | **Attack Stage:** `{corp.attack_stage}`  
**Composite Risk Score:** `{corp.risk_score:.1f}/100` | **Severity:** `{max_sev}`

---

### Executive Summary
TriageIQ multi-agent security pipeline detected a coordinated security incident originating from primary attacker IP **`{corp.primary_ip}`**. 
The attack progression spans **{len(campaign_alerts)} correlated alerts** targeting `{corp.target_asset}`.

### MITRE ATT&CK Mapping
{chr(10).join([f"- **{m}**" for m in mitre_list])}

### Threat Intelligence & IOC Findings
"""
        for ioc_str in set([a.source_ip for a in campaign_alerts] + [a.destination_ip for a in campaign_alerts]):
            intel = threat_intel.get(ioc_str)
            if intel:
                md_body += f"- **IOC `{intel.ioc}`** ({intel.ioc_type.upper()}): Risk Score `{intel.reputation_score}%` | Source: `{intel.source_api}`  \n  *{intel.details}*\n"

        md_body += f"""
### Attack Timeline
| Timestamp | Event Signature & Trajectory |
|---|---|
"""
        for t in timeline:
            md_body += f"| `{t['timestamp']}` | {t['event']} |\n"

        md_body += f"""
### Key Evidence Artifacts
"""
        for ev in evidence:
            md_body += f"- {ev}\n"

        md_body += f"""
### Recommended Incident Response Playbook Actions
1. 🔒 **Network Containment**: Immediately block external IP `{corp.primary_ip}` at edge firewall / security group level.
2. 🔑 **Credential Revocation**: Reset active OAuth tokens and password credentials for user `{campaign_alerts[0].user}`.
3. 💻 **Host Isolation**: Isolate `{corp.target_asset}` from the internal subnet to prevent lateral movement.
4. 🔍 **Log Forensics**: Pull EDR process tree logs for host `{corp.target_asset}` during the alert window.
"""

        report_obj = IncidentReport(
            incident_id=f"INC-{corp.campaign_id}",
            title=f"Incident {corp.campaign_id}: {corp.attack_stage} on {corp.target_asset}",
            timestamp=campaign_alerts[0].timestamp,
            severity=max_sev,
            summary=corp.summary,
            affected_assets=[corp.target_asset, corp.primary_ip],
            mitre_tactics=mitre_list,
            timeline=timeline,
            evidence=evidence,
            recommended_actions=[
                f"Block IP {corp.primary_ip} on Perimeter Firewall",
                f"Isolate Host {corp.target_asset}",
                f"Revoke User Session for {campaign_alerts[0].user}"
            ],
            markdown_body=md_body
        )
        reports.append(report_obj)

    trace = state.get("trace_logs", [])
    trace.append({
        "node": "Reporting Agent",
        "status": "COMPLETED",
        "detail": f"Generated {len(reports)} comprehensive MITRE ATT&CK incident reports."
    })

    return {
        "incident_reports": reports,
        "trace_logs": trace,
        "current_step": "PIPELINE_COMPLETE"
    }


# ----------------------------------------------------------------------
# PIPELINE GRAPH CONSTRUCTION
# ----------------------------------------------------------------------

def build_triage_graph():
    """Builds and compiles the LangGraph StateGraph."""
    workflow = StateGraph(TriageState)

    # Add Nodes
    workflow.add_node("ingest", ingest_node)
    workflow.add_node("enrich", enrich_node)
    workflow.add_node("correlate", correlate_node)
    workflow.add_node("triage", triage_node)
    workflow.add_node("report", report_node)

    # Set Sequential Edges
    workflow.set_entry_point("ingest")
    workflow.add_edge("ingest", "enrich")
    workflow.add_edge("enrich", "correlate")
    workflow.add_edge("correlate", "triage")
    workflow.add_edge("triage", "report")
    workflow.add_edge("report", END)

    return workflow.compile()


def run_pipeline(raw_alerts: List[Dict[str, Any]]) -> TriageState:
    """Executes the full LangGraph pipeline end-to-end."""
    graph = build_triage_graph()
    
    initial_state: TriageState = {
        "raw_alerts": raw_alerts,
        "alerts": [],
        "threat_intel": {},
        "correlations": [],
        "triage_decisions": {},
        "incident_reports": [],
        "trace_logs": [],
        "current_step": "INITIALIZED",
        "noise_reduced_percent": 0.0
    }
    
    final_state = graph.invoke(initial_state)
    return final_state

"""
BCM/ITSM Tools for FinServe Digital Bank Incident Simulation
All tools are deterministic simulations — no real APIs are called.
Seeded randomness ensures reproducible outputs for the same inputs.
"""

import hashlib
import json
from datetime import datetime, timedelta
from typing import Optional
from crewai.tools import BaseTool
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _seed_from_str(s: str) -> int:
    """Derive a stable integer seed from an arbitrary string."""
    return int(hashlib.sha256(s.encode()).hexdigest(), 16) % (10 ** 9)


def _seeded_choice(seed: int, choices: list):
    """Pick a deterministic element from a list using a seed."""
    return choices[seed % len(choices)]


def _seeded_float(seed: int, lo: float, hi: float) -> float:
    """Return a deterministic float in [lo, hi]."""
    frac = (seed % 1000) / 1000.0
    return round(lo + frac * (hi - lo), 2)


# ---------------------------------------------------------------------------
# Threat intelligence lookup table (MITRE ATT&CK aligned)
# ---------------------------------------------------------------------------

THREAT_INTEL = {
    "ransomware": {
        "attack_vector": "Phishing / RDP brute-force",
        "mitre_tactics": ["TA0001 Initial Access", "TA0002 Execution", "TA0040 Impact"],
        "mitre_techniques": ["T1566 Phishing", "T1486 Data Encrypted for Impact"],
        "cve_refs": ["CVE-2023-27350 (PaperCut RCE)", "CVE-2021-34527 (PrintNightmare)"],
        "severity": "P1",
        "lateral_movement_suspected": True,
        "blast_radius": "Full datacenter — all Tier-1 services at risk",
        "containment_actions": [
            "Isolate affected hosts at network layer (VLAN quarantine)",
            "Revoke all active VPN and privileged sessions",
            "Snapshot affected volumes for forensic analysis before decryption attempts",
            "Activate offline backup restore procedure RB-DR-001",
        ],
    },
    "ddos": {
        "attack_vector": "Volumetric UDP/HTTPS flood via botnet",
        "mitre_tactics": ["TA0040 Impact"],
        "mitre_techniques": ["T1498 Network Denial of Service", "T1499 Endpoint Denial of Service"],
        "cve_refs": [],
        "severity": "P2",
        "lateral_movement_suspected": False,
        "blast_radius": "Internet-facing services; internal APIs unaffected",
        "containment_actions": [
            "Activate Cloudflare Magic Transit / upstream scrubbing",
            "Enable rate-limiting rules on WAF (block >500 req/s per IP)",
            "Black-hole suspicious ASNs via BGP community 65535:666",
        ],
    },
    "data_breach": {
        "attack_vector": "Compromised service account / SQL injection",
        "mitre_tactics": ["TA0006 Credential Access", "TA0009 Collection", "TA0010 Exfiltration"],
        "mitre_techniques": ["T1078 Valid Accounts", "T1041 Exfiltration Over C2 Channel"],
        "cve_refs": ["CVE-2023-34362 (MOVEit Transfer SQLi)"],
        "severity": "P1",
        "lateral_movement_suspected": True,
        "blast_radius": "Customer PII database; payment card data; transaction history",
        "containment_actions": [
            "Disable compromised service account immediately",
            "Block egress to confirmed exfiltration IPs at perimeter firewall",
            "Preserve database query logs (do NOT rotate yet)",
            "Notify DPO — GDPR 72-hour breach notification clock starts NOW",
        ],
    },
    "insider_threat": {
        "attack_vector": "Privileged insider misuse — DBA exporting data to personal cloud",
        "mitre_tactics": ["TA0009 Collection", "TA0010 Exfiltration"],
        "mitre_techniques": ["T1530 Data from Cloud Storage", "T1048 Exfiltration Over Alt Protocol"],
        "cve_refs": [],
        "severity": "P1",
        "lateral_movement_suspected": False,
        "blast_radius": "Customer financial records; 3 weeks of unauthorized access",
        "containment_actions": [
            "Immediately revoke DBA account and active sessions",
            "Preserve access logs, audit trails — legal hold in place",
            "Coordinate with HR and Legal before any user confrontation",
            "Engage CIRT for forensic image of workstation",
        ],
    },
    "supply_chain": {
        "attack_vector": "Compromised third-party payment processor API gateway",
        "mitre_tactics": ["TA0001 Initial Access", "TA0006 Credential Access"],
        "mitre_techniques": ["T1195 Supply Chain Compromise", "T1552 Unsecured Credentials"],
        "cve_refs": [],
        "severity": "P1",
        "lateral_movement_suspected": True,
        "blast_radius": "All transactions via PayBridge in last 48 hours; potential card data exposure",
        "containment_actions": [
            "Suspend PayBridge API integration immediately",
            "Route transactions to backup processor (FinancePay)",
            "Obtain full transaction logs from PayBridge for impact scoping",
            "Notify card schemes (Visa/Mastercard) per PCI-DSS 12.10.4",
        ],
    },
    "cloud_misconfiguration": {
        "attack_vector": "Publicly exposed S3 bucket / misconfigured IAM policy",
        "mitre_tactics": ["TA0009 Collection"],
        "mitre_techniques": ["T1530 Data from Cloud Storage"],
        "cve_refs": [],
        "severity": "P2",
        "lateral_movement_suspected": False,
        "blast_radius": "Cloud storage tier; specific bucket contents need scoping",
        "containment_actions": [
            "Apply bucket policy to block public access immediately",
            "Rotate IAM keys for over-privileged role",
            "Enable S3 access logging and CloudTrail",
            "Run AWS Macie scan to classify exposed data",
        ],
    },
}


def _detect_event_type(description: str) -> str:
    """Map free-text event description to a known threat category."""
    d = description.lower()
    if "ransomware" in d or "encrypted" in d:
        return "ransomware"
    if "ddos" in d or "denial of service" in d or "flood" in d:
        return "ddos"
    if "breach" in d or "exfiltrat" in d or "unauthorized" in d and "data" in d:
        return "data_breach"
    if "insider" in d or "personal cloud" in d or "dba" in d:
        return "insider_threat"
    if "supply chain" in d or "paybridge" in d or "third-party" in d:
        return "supply_chain"
    if "misconfigur" in d or "s3" in d or "bucket" in d:
        return "cloud_misconfiguration"
    return "ransomware"  # default for unknown events


# ---------------------------------------------------------------------------
# Service catalog data
# ---------------------------------------------------------------------------

SERVICE_CATALOG = {
    "Mobile Banking App": {
        "tier": 1,
        "rto_hours": 4,
        "rpo_minutes": 15,
        "mtpd_hours": 8,
        "owner": "Retail Digital Squad",
        "upstreams": ["Identity & Auth Service", "Core Banking API"],
        "downstreams": [],
        "dr_strategy": "Hot standby (active-active)",
        "last_dr_test": "2024-10-15",
        "last_dr_result": "PASS — RTO achieved in 12 min",
        "compliance": ["PCI-DSS", "GDPR"],
        "annual_revenue_usd": 48_000_000,
        "customers_affected": 1_200_000,
    },
    "Online Transfers": {
        "tier": 1,
        "rto_hours": 4,
        "rpo_minutes": 15,
        "mtpd_hours": 6,
        "owner": "Payments Engineering",
        "upstreams": ["Core Banking API", "Fraud Detection Engine"],
        "downstreams": ["Reconciliation Service"],
        "dr_strategy": "Hot standby (active-passive)",
        "last_dr_test": "2024-09-20",
        "last_dr_result": "PASS — RTO achieved in 34 min",
        "compliance": ["PCI-DSS", "SOX"],
        "annual_revenue_usd": 120_000_000,
        "customers_affected": 850_000,
    },
    "Fraud Detection Engine": {
        "tier": 1,
        "rto_hours": 2,
        "rpo_minutes": 5,
        "mtpd_hours": 4,
        "owner": "Risk & Compliance Engineering",
        "upstreams": ["Data Warehouse"],
        "downstreams": ["Online Transfers", "Mobile Banking App"],
        "dr_strategy": "Hot standby (active-active)",
        "last_dr_test": "2024-11-01",
        "last_dr_result": "PASS — RTO achieved in 8 min",
        "compliance": ["PCI-DSS", "SOX", "FFIEC"],
        "annual_revenue_usd": 0,
        "customers_affected": 2_100_000,
    },
    "Core Banking API": {
        "tier": 1,
        "rto_hours": 4,
        "rpo_minutes": 15,
        "mtpd_hours": 8,
        "owner": "Platform Engineering",
        "upstreams": ["Transaction Database"],
        "downstreams": ["Mobile Banking App", "Online Transfers", "Customer Portal"],
        "dr_strategy": "Warm standby (15-min switchover)",
        "last_dr_test": "2024-08-14",
        "last_dr_result": "PARTIAL — RTO 67 min, exceeded target",
        "compliance": ["PCI-DSS", "SOX", "ISO 27001"],
        "annual_revenue_usd": 200_000_000,
        "customers_affected": 2_100_000,
    },
    "Identity & Auth Service": {
        "tier": 1,
        "rto_hours": 1,
        "rpo_minutes": 5,
        "mtpd_hours": 2,
        "owner": "Security Engineering",
        "upstreams": [],
        "downstreams": ["Mobile Banking App", "Customer Portal", "Online Transfers"],
        "dr_strategy": "Hot standby (active-active, multi-region)",
        "last_dr_test": "2024-11-10",
        "last_dr_result": "PASS — RTO achieved in 3 min",
        "compliance": ["PCI-DSS", "SOX", "ISO 27001", "GDPR"],
        "annual_revenue_usd": 0,
        "customers_affected": 2_100_000,
    },
    "Customer Portal": {
        "tier": 2,
        "rto_hours": 8,
        "rpo_minutes": 60,
        "mtpd_hours": 24,
        "owner": "Retail Digital Squad",
        "upstreams": ["Core Banking API", "Identity & Auth Service"],
        "downstreams": [],
        "dr_strategy": "Warm standby (30-min switchover)",
        "last_dr_test": "2024-07-22",
        "last_dr_result": "PASS — RTO achieved in 28 min",
        "compliance": ["GDPR"],
        "annual_revenue_usd": 10_000_000,
        "customers_affected": 500_000,
    },
    "Transaction Database": {
        "tier": 1,
        "rto_hours": 2,
        "rpo_minutes": 1,
        "mtpd_hours": 4,
        "owner": "Data Platform Engineering",
        "upstreams": [],
        "downstreams": ["Core Banking API", "Reconciliation Service", "Data Warehouse"],
        "dr_strategy": "Synchronous replication + hot standby",
        "last_dr_test": "2024-10-30",
        "last_dr_result": "PASS — Zero data loss confirmed",
        "compliance": ["PCI-DSS", "SOX", "GDPR"],
        "annual_revenue_usd": 0,
        "customers_affected": 2_100_000,
    },
    "Reconciliation Service": {
        "tier": 2,
        "rto_hours": 8,
        "rpo_minutes": 30,
        "mtpd_hours": 24,
        "owner": "Finance Technology",
        "upstreams": ["Transaction Database", "Online Transfers"],
        "downstreams": [],
        "dr_strategy": "Cold standby (2-hour build time)",
        "last_dr_test": "2024-05-18",
        "last_dr_result": "FAIL — DR environment not up to date",
        "compliance": ["SOX"],
        "annual_revenue_usd": 0,
        "customers_affected": 0,
    },
    "Data Warehouse": {
        "tier": 3,
        "rto_hours": 24,
        "rpo_minutes": 240,
        "mtpd_hours": 72,
        "owner": "Data Analytics",
        "upstreams": ["Transaction Database"],
        "downstreams": ["Fraud Detection Engine"],
        "dr_strategy": "Backup restore from S3 (RTO 24h)",
        "last_dr_test": "2024-03-10",
        "last_dr_result": "PASS — Restore completed in 19h",
        "compliance": ["GDPR"],
        "annual_revenue_usd": 0,
        "customers_affected": 0,
    },
}

# Track DR capacity consumption across failover calls (module-level state)
_dr_capacity_consumed: dict = {}


# ---------------------------------------------------------------------------
# 1. analyze_security_event
# ---------------------------------------------------------------------------

class AnalyzeSecurityEventTool(BaseTool):
    name: str = "analyze_security_event"
    description: str = (
        "Analyzes a security event description using threat intelligence to extract IOCs, "
        "map to MITRE ATT&CK, determine severity (NIST P1-P5), identify blast radius, "
        "and recommend containment actions. Supports: ransomware, DDoS, data breach, "
        "insider threat, supply chain compromise, cloud misconfiguration."
    )

    def _run(self, event_description: str) -> str:
        # Real-world BCM concept: Triage using threat intelligence before escalating
        event_type = _detect_event_type(event_description)
        intel = THREAT_INTEL[event_type]
        seed = _seed_from_str(event_description)

        # Extract basic IOCs from free text (simulated NLP extraction)
        iocs = []
        if "ip" in event_description.lower() or "address" in event_description.lower():
            iocs.append(f"Suspicious IP: 185.{seed % 255}.{(seed >> 8) % 255}.{(seed >> 16) % 255}")
        if "hash" in event_description.lower() or "file" in event_description.lower():
            iocs.append(f"Malware hash (SHA256): {hashlib.sha256(event_description.encode()).hexdigest()}")
        if not iocs:
            iocs = ["No explicit IOCs in description — automated SIEM correlation required"]

        # Affected infrastructure components based on event type
        affected_infra = {
            "ransomware": ["Transaction Database", "Core Banking API", "File servers", "Backup agents"],
            "ddos": ["Mobile Banking App", "Customer Portal", "CDN edge nodes"],
            "data_breach": ["Transaction Database", "Customer PII store", "Identity & Auth Service"],
            "insider_threat": ["Data Warehouse", "Transaction Database", "Audit log system"],
            "supply_chain": ["Online Transfers", "Payment gateway integration", "Fraud Detection Engine"],
            "cloud_misconfiguration": ["S3 data bucket: finserve-customer-data-prod", "IAM roles"],
        }.get(event_type, ["Unknown — investigation required"])

        result = {
            "analysis_timestamp": datetime.utcnow().isoformat() + "Z",
            "event_type_detected": event_type,
            "severity": intel["severity"],
            "severity_rationale": f"NIST {intel['severity']}: Immediate response required — financial and regulatory exposure confirmed",
            "attack_vector": intel["attack_vector"],
            "iocs_extracted": iocs,
            "mitre_attack": {
                "tactics": intel["mitre_tactics"],
                "techniques": intel["mitre_techniques"],
            },
            "cve_references": intel["cve_refs"] if intel["cve_refs"] else ["No known CVEs — zero-day or TTP-based attack"],
            "affected_infrastructure": affected_infra,
            "blast_radius": intel["blast_radius"],
            "lateral_movement_suspected": intel["lateral_movement_suspected"],
            "containment_actions": intel["containment_actions"],
            "escalation_required": intel["severity"] in ("P1", "P2"),
            "bcm_plan_activation": intel["severity"] == "P1",
        }
        return json.dumps(result, indent=2)


# ---------------------------------------------------------------------------
# 2. calculate_impact
# ---------------------------------------------------------------------------

class CalculateImpactTool(BaseTool):
    name: str = "calculate_impact"
    description: str = (
        "Calculates multi-dimensional business impact for a given service outage. "
        "Models non-linear financial degradation over time (cascading failures, SLA penalties, "
        "regulatory fines). Accounts for time-of-day, day-of-week, dependency chains, "
        "and regulatory exposure (PCI-DSS, SOX, GDPR)."
    )

    def _run(self, service: str, outage_duration_hours: float = 1.0) -> str:
        # Real-world BCM concept: BIA uses time-based degradation curves —
        # cascading failures and penalty accumulation make extended outages
        # disproportionately expensive (non-linear cost model).
        svc = SERVICE_CATALOG.get(service)
        if not svc:
            # Fuzzy match
            for k in SERVICE_CATALOG:
                if service.lower() in k.lower():
                    svc = SERVICE_CATALOG[k]
                    service = k
                    break
        if not svc:
            return json.dumps({"error": f"Service '{service}' not found in catalog. Known services: {list(SERVICE_CATALOG.keys())}"})

        now = datetime.utcnow()
        is_peak = 8 <= now.hour <= 20
        is_friday_evening = now.weekday() == 4 and now.hour >= 17
        is_weekend = now.weekday() >= 5

        # Peak multiplier — a Friday evening outage is the worst case
        peak_multiplier = 1.0
        if is_friday_evening:
            peak_multiplier = 2.2  # highest severity — approaching weekend, no staff
        elif is_peak and not is_weekend:
            peak_multiplier = 1.5
        elif is_weekend:
            peak_multiplier = 1.3

        # Non-linear degradation curve:
        # Hour 1: base rate; Hour 4: 3x due to cascading failures, SLA breach, customer churn
        t = max(0.25, outage_duration_hours)
        if t <= 1:
            degradation_factor = 1.0
        elif t <= 2:
            degradation_factor = 1.5
        elif t <= 4:
            degradation_factor = 2.2
        else:
            degradation_factor = 3.0  # Full crisis mode: regulatory fines accumulate

        hourly_revenue = svc["annual_revenue_usd"] / 8760 if svc["annual_revenue_usd"] else 5000
        direct_revenue_loss = hourly_revenue * t * degradation_factor * peak_multiplier

        # SLA penalty: typical bank SLA has 0.5% of monthly contract per hour over threshold
        sla_penalty_per_hour = svc["annual_revenue_usd"] * 0.005 / 12
        sla_hours_breached = max(0, t - svc["rto_hours"])
        sla_penalty_total = sla_penalty_per_hour * sla_hours_breached * degradation_factor

        # Regulatory fine exposure
        reg_fines = {}
        if "PCI-DSS" in svc["compliance"]:
            reg_fines["PCI-DSS"] = {
                "regulation": "PCI-DSS v4.0 Req 12.10",
                "fine_range": "$5,000–$100,000/month",
                "exposure": round(50_000 * min(t / 4, 1), 0),
                "trigger": "Failure to maintain secure processing environment",
            }
        if "GDPR" in svc["compliance"]:
            reg_fines["GDPR"] = {
                "regulation": "GDPR Art. 83(4)",
                "fine_range": "Up to €10M or 2% of global annual turnover",
                "exposure": round(200_000 * min(t / 72, 1), 0),
                "trigger": "72-hour breach notification clock active if PII involved",
            }
        if "SOX" in svc["compliance"]:
            reg_fines["SOX"] = {
                "regulation": "SOX Section 404 / 906",
                "fine_range": "$1M–$5M + criminal liability",
                "exposure": round(100_000 * min(t / 24, 1), 0),
                "trigger": "Material weakness in financial reporting controls",
            }

        # Cascading degradation of downstream services
        downstream_impact = {}
        for ds in svc.get("downstreams", []):
            ds_svc = SERVICE_CATALOG.get(ds)
            if ds_svc:
                downstream_impact[ds] = {
                    "status": "Degraded at 40% capacity",
                    "estimated_revenue_loss_usd": round(
                        (ds_svc["annual_revenue_usd"] / 8760) * t * 0.6, 0
                    ),
                    "customers_affected": ds_svc["customers_affected"],
                }

        # Reputational damage score (1–10) increases with severity and customer count
        rep_score = min(10, round(
            (svc["customers_affected"] / 200_000) + (t * 0.5) + (2 if is_friday_evening else 0), 1
        ))

        # Customer churn probability (% of affected customers)
        churn_prob = min(15.0, round(rep_score * 0.8 + (t * 0.3), 1))

        result = {
            "service": service,
            "analysis_time_utc": now.isoformat() + "Z",
            "outage_duration_hours": t,
            "timing_context": {
                "is_peak_hours": is_peak,
                "is_friday_evening": is_friday_evening,
                "peak_multiplier": peak_multiplier,
                "degradation_factor": degradation_factor,
            },
            "financial_impact": {
                "direct_revenue_loss_usd": round(direct_revenue_loss, 0),
                "sla_penalty_exposure_usd": round(sla_penalty_total, 0),
                "regulatory_fine_exposure": reg_fines,
                "total_estimated_exposure_usd": round(
                    direct_revenue_loss + sla_penalty_total + sum(
                        v["exposure"] for v in reg_fines.values()
                    ), 0
                ),
            },
            "customer_impact": {
                "directly_affected": svc["customers_affected"],
                "reputational_damage_score": rep_score,
                "estimated_churn_probability_pct": churn_prob,
            },
            "cascade_impact": downstream_impact,
            "service_tier": svc["tier"],
            "rto_hours": svc["rto_hours"],
            "rpo_minutes": svc["rpo_minutes"],
            "recovery_priority": "IMMEDIATE" if svc["tier"] == 1 else "HIGH" if svc["tier"] == 2 else "STANDARD",
        }
        return json.dumps(result, indent=2)


# ---------------------------------------------------------------------------
# 3. failover_service
# ---------------------------------------------------------------------------

class FailoverServiceTool(BaseTool):
    name: str = "failover_service"
    description: str = (
        "Triggers automated failover to DR site for a named service. "
        "Returns pre-failover health check, data sync status, step-by-step execution log, "
        "post-failover validation, and any required manual interventions. "
        "Outcomes vary realistically: success, degraded mode, DR site impacted, or data loss within RPO."
    )

    def _run(self, service: str) -> str:
        # Real-world BCM concept: DR failover is never guaranteed to be clean.
        # Prior DR test results, replication lag, and capacity all affect outcomes.
        global _dr_capacity_consumed

        svc = SERVICE_CATALOG.get(service)
        if not svc:
            for k in SERVICE_CATALOG:
                if service.lower() in k.lower():
                    svc = SERVICE_CATALOG[k]
                    service = k
                    break
        if not svc:
            return json.dumps({"error": f"Service '{service}' not found"})

        seed = _seed_from_str(service)
        consumed = _dr_capacity_consumed.get(service, 0)

        # Determine outcome based on last DR test and capacity pressure
        last_test_result = svc["last_dr_result"]
        base_success_prob = 0.85 if "PASS" in last_test_result else 0.45

        # Capacity pressure degrades outcomes for repeated calls
        adjusted_prob = base_success_prob - (consumed * 0.2)
        outcome_roll = _seeded_float(seed + consumed, 0, 1)

        if outcome_roll <= adjusted_prob:
            outcome = "SUCCESS"
            status_msg = f"{service} successfully failed over to DR site"
        elif outcome_roll <= adjusted_prob + 0.1:
            outcome = "DEGRADED_MODE"
            status_msg = f"{service} operational in degraded mode — 60% capacity"
        elif outcome_roll <= adjusted_prob + 0.15:
            outcome = "DATA_LOSS_WITHIN_RPO"
            status_msg = f"{service} recovered — estimated {int(svc['rpo_minutes'] * 0.7)} min data loss (within RPO)"
        else:
            outcome = "FAILOVER_FAILED"
            status_msg = f"{service} failover FAILED — DR site also impacted or build failed"

        # Realistic timing by service complexity
        timing_map = {
            "Transaction Database": 45,
            "Core Banking API": 34,
            "Identity & Auth Service": 8,
            "Mobile Banking App": 12,
            "Fraud Detection Engine": 18,
            "Online Transfers": 25,
            "Customer Portal": 22,
            "Reconciliation Service": 90,
            "Data Warehouse": 960,
        }
        failover_minutes = timing_map.get(service, 30) + int(consumed * 10)

        replication_lag = _seeded_float(seed, 0.5, float(svc["rpo_minutes"]))

        steps = [
            {"step": 1, "action": "Pre-failover health check on DR site", "result": "OK — DR node responsive", "elapsed_min": 1},
            {"step": 2, "action": f"Verify replication lag ({replication_lag} min)", "result": "Within RPO threshold" if replication_lag <= svc["rpo_minutes"] else "⚠ RPO breach risk", "elapsed_min": 3},
            {"step": 3, "action": "Redirect DNS / load balancer to DR endpoint", "result": "DNS propagated — TTL 30s", "elapsed_min": 8},
            {"step": 4, "action": "Warm up application tier on DR", "result": "Cache primed — 85% hit rate", "elapsed_min": failover_minutes - 5},
            {"step": 5, "action": "Run post-failover smoke tests", "result": "PASS" if outcome != "FAILOVER_FAILED" else "FAIL — service unresponsive", "elapsed_min": failover_minutes},
        ]

        manual_interventions = []
        if outcome == "DEGRADED_MODE":
            manual_interventions.append("Manual scaling required — add 4 DR worker nodes")
        if outcome == "FAILOVER_FAILED":
            manual_interventions.append("ESCALATE: Engage DR vendor support — bridge call opened")
            manual_interventions.append("Consider cold standby restore from S3 (RTO +2h)")
        if replication_lag > svc["rpo_minutes"] * 0.8:
            manual_interventions.append("DBA review required — confirm transaction integrity at RPO boundary")

        _dr_capacity_consumed[service] = consumed + 1

        result = {
            "service": service,
            "failover_outcome": outcome,
            "outcome_message": status_msg,
            "pre_failover_health": {
                "primary_status": "DOWN",
                "dr_site_status": "READY" if outcome != "FAILOVER_FAILED" else "DEGRADED",
                "last_replication_lag_minutes": replication_lag,
                "dr_test_confidence": last_test_result,
            },
            "execution_steps": steps,
            "total_failover_time_minutes": failover_minutes,
            "rto_compliance": "MET" if failover_minutes <= svc["rto_hours"] * 60 else "BREACHED",
            "post_failover_validation": {
                "health_check": "PASS" if outcome in ("SUCCESS", "DATA_LOSS_WITHIN_RPO") else "FAIL",
                "minimum_viable_operation": outcome in ("SUCCESS", "DEGRADED_MODE", "DATA_LOSS_WITHIN_RPO"),
                "data_integrity_confirmed": outcome not in ("FAILOVER_FAILED",),
            },
            "manual_interventions_required": manual_interventions,
            "dr_capacity_pressure": f"{min(100, consumed * 25)}% consumed (call #{consumed + 1})",
        }
        return json.dumps(result, indent=2)


# ---------------------------------------------------------------------------
# 4. create_incident_record
# ---------------------------------------------------------------------------

class CreateIncidentRecordTool(BaseTool):
    name: str = "create_incident_record"
    description: str = (
        "Creates a formal ITIL 4 incident record with priority matrix, categorization, "
        "CI references, escalation path, SLA clock, and emergency change approval requirements."
    )

    def _run(self, summary: str, impact: str = "High", urgency: str = "High") -> str:
        # Real-world BCM concept: ITIL 4 priority matrix — Impact × Urgency
        # P1 = Critical (High×High), P2 = High (High×Medium), etc.
        priority_matrix = {
            ("High", "High"): ("P1", "Critical", 15),
            ("High", "Medium"): ("P2", "High", 60),
            ("Medium", "High"): ("P2", "High", 60),
            ("High", "Low"): ("P3", "Medium", 240),
            ("Medium", "Medium"): ("P3", "Medium", 240),
            ("Low", "High"): ("P3", "Medium", 240),
            ("Medium", "Low"): ("P4", "Low", 480),
            ("Low", "Medium"): ("P4", "Low", 480),
            ("Low", "Low"): ("P5", "Planning", 1440),
        }
        priority_code, priority_label, sla_minutes = priority_matrix.get(
            (impact, urgency), ("P2", "High", 60)
        )

        seed = _seed_from_str(summary)
        incident_id = f"INC{2024_0000 + (seed % 9000):07d}"
        now = datetime.utcnow()

        # ITIL categorization taxonomy
        event_type = _detect_event_type(summary)
        category_map = {
            "ransomware": ("Security", "Malware/Ransomware", "Crypto-locker"),
            "ddos": ("Availability", "Network", "DDoS Attack"),
            "data_breach": ("Security", "Unauthorized Access", "Data Exfiltration"),
            "insider_threat": ("Security", "Insider Threat", "Privileged Misuse"),
            "supply_chain": ("Security", "Third-Party", "Supply Chain Compromise"),
            "cloud_misconfiguration": ("Security", "Cloud", "IAM Misconfiguration"),
        }
        category, subcategory, detail = category_map.get(event_type, ("Security", "Other", "Unclassified"))

        escalation_path = {
            "P1": ["L1 NOC → L2 CIRT → CISO → CTO → CEO → Board Risk Committee"],
            "P2": ["L1 NOC → L2 CIRT → CISO → CTO"],
            "P3": ["L1 NOC → L2 On-Call Engineer → Service Owner"],
        }.get(priority_code, ["L1 NOC → Service Owner"])

        result = {
            "incident_id": incident_id,
            "created_at_utc": now.isoformat() + "Z",
            "priority": priority_code,
            "priority_label": priority_label,
            "sla_target_minutes": sla_minutes,
            "sla_breach_time_utc": (now + timedelta(minutes=sla_minutes)).isoformat() + "Z",
            "categorization": {
                "category": category,
                "subcategory": subcategory,
                "detail": detail,
            },
            "summary": summary,
            "impact": impact,
            "urgency": urgency,
            "affected_cis": [
                {"ci_name": "finserve-prod-dc-01", "ci_type": "Datacenter", "env": "Production"},
                {"ci_name": "finserve-db-primary", "ci_type": "Database", "env": "Production"},
                {"ci_name": "finserve-app-cluster", "ci_type": "Application Cluster", "env": "Production"},
            ],
            "assignment_group": "CIRT — Cyber Incident Response Team",
            "escalation_path": escalation_path,
            "related_records": {
                "problem_record": f"PRB{seed % 9999:05d} — Root cause investigation pending",
                "emergency_change": f"CHG-E-{seed % 9999:05d} — Awaiting e-CAB approval",
            },
            "bcm_plan_reference": "BCM-FIN-001 — FinServe Major Incident & Business Continuity Plan v3.2",
            "itil_lifecycle_stage": "Incident Identification → Logging → Categorization → Prioritization",
            "required_approvals": [
                "CISO approval for emergency change execution",
                "CTO sign-off for DR activation",
                "Legal counsel notification if data breach suspected",
            ] if priority_code == "P1" else ["Service owner approval"],
            "war_room_bridge": f"+1-800-FINSERVE x{seed % 9000 + 1000}" if priority_code in ("P1", "P2") else None,
        }
        return json.dumps(result, indent=2)


# ---------------------------------------------------------------------------
# 5. send_notification
# ---------------------------------------------------------------------------

class SendNotificationTool(BaseTool):
    name: str = "send_notification"
    description: str = (
        "Generates and sends audience-appropriate incident notifications. "
        "Supports: customers, executives, board, regulators, technical_teams, vendors. "
        "Each audience receives appropriately toned, detailed communication."
    )

    def _run(self, message: str, audience: str, incident_id: str = "INC-UNKNOWN", severity: str = "P1") -> str:
        # Real-world BCM concept: Communication is audience-layered.
        # Customers need empathy; regulators need legal precision; engineers need technical depth.
        now = datetime.utcnow()
        audience_lower = audience.lower().replace(" ", "_")

        templates = {
            "customers": {
                "channel": ["Status page (statuspage.io)", "Push notification", "Email"],
                "tone": "Empathetic, plain English, no jargon",
                "subject": "Service Update — We're on it",
                "body": (
                    f"We're aware that some of our services are currently unavailable. "
                    f"Our team is working around the clock to restore full service. "
                    f"As a workaround, you can use our 24/7 telephone banking: 0800-FINSERVE. "
                    f"We expect to provide an update within 30 minutes. "
                    f"We sincerely apologise for any inconvenience. Reference: {incident_id}"
                ),
                "eta_commitment": "Next update in 30 minutes",
            },
            "executives": {
                "channel": ["Encrypted email (CISO-distro)", "Executive SMS bridge", "War room bridge call"],
                "tone": "Business impact focused, decision-oriented",
                "subject": f"[MAJOR INCIDENT {severity}] Executive Briefing — {incident_id}",
                "body": (
                    f"SITUATION: {severity} incident declared at {now.strftime('%H:%M UTC')}. "
                    f"Core banking and payment services impacted. Estimated financial exposure: "
                    f"$500K–$2M depending on duration. CIRT activated. DR failover in progress. "
                    f"DECISION REQUIRED: Board Risk Committee notification if duration exceeds 2 hours. "
                    f"NEXT BRIEFING: {(now + timedelta(minutes=30)).strftime('%H:%M UTC')}"
                ),
                "decision_points": [
                    "Approve emergency change budget (up to $200K)",
                    "Authorise regulatory notification if data breach confirmed",
                    "Media statement sign-off if outage exceeds 4 hours",
                ],
            },
            "board": {
                "channel": ["Encrypted email to Board Secretary", "Board Risk Committee notification"],
                "tone": "Governance and risk posture focused",
                "subject": f"Board Risk Notification — {severity} Incident {incident_id}",
                "body": (
                    f"The Board is informed that a {severity} incident is in progress. "
                    f"This notification is issued per BCM-FIN-001 §8.3 (Board Escalation Policy). "
                    f"Current risk posture: ELEVATED. Regulatory notification timelines are being managed. "
                    f"A formal incident report will be provided within 24 hours of resolution."
                ),
            },
            "regulators": {
                "channel": ["Secure email to FCA/PRA Operations", "Encrypted portal submission"],
                "tone": "Compliance-precise, legally reviewed, formal",
                "subject": f"Operational Incident Notification — {incident_id} [{now.strftime('%Y-%m-%d')}]",
                "body": (
                    f"FinServe Digital Bank hereby notifies the FCA/PRA of an operational disruption "
                    f"per SYSC 15A (Operational Resilience) and PCI-DSS 12.10.4. "
                    f"Incident reference: {incident_id}. Time of detection: {now.strftime('%Y-%m-%dT%H:%M:%SZ')}. "
                    f"GDPR Art. 33 notification will be submitted within 72 hours if personal data is involved. "
                    f"FFIEC BCM Handbook guidance is being followed for recovery sequencing."
                ),
                "regulatory_references": ["FCA SYSC 15A", "PCI-DSS 12.10", "GDPR Art. 33", "FFIEC BCM Handbook"],
                "notification_deadlines": {
                    "GDPR_breach_notification": "72 hours from detection",
                    "FCA_material_incident": "Within business hours of next working day",
                    "PCI_DSS_card_brand_notification": "Within 24 hours if card data involved",
                },
            },
            "technical_teams": {
                "channel": ["PagerDuty alert (P1 broadcast)", "Slack #incident-response", "War room bridge"],
                "tone": "Technical, precise, runbook-referenced",
                "subject": f"[P1 INCIDENT] {incident_id} — Action Required",
                "body": (
                    f"INCIDENT: {incident_id} | SEVERITY: {severity} | DECLARED: {now.strftime('%H:%M UTC')}\n"
                    f"SITUATION: {message}\n"
                    f"RUNBOOKS: RB-DR-001 (DR Activation), RB-SEC-005 (CIRT Containment), RB-COMMS-003 (Stakeholder Comms)\n"
                    f"WAR ROOM: Join bridge now. On-call CISO: +1-555-CISO-NOW\n"
                    f"ESCALATION: If no CIRT response in 15 min → auto-page VP Engineering"
                ),
                "runbook_references": ["RB-DR-001", "RB-SEC-005", "RB-NET-002", "RB-COMMS-003"],
                "on_call_contacts": ["CISO: +1-555-0100", "VP Engineering: +1-555-0101", "DBA Lead: +1-555-0102"],
            },
            "vendors": {
                "channel": ["Vendor emergency contact", "Contractual SLA notification email"],
                "tone": "Contractual, professional, SLA-focused",
                "subject": f"Incident Coordination Request — {incident_id}",
                "body": (
                    f"FinServe is experiencing a {severity} incident affecting services dependent on your platform. "
                    f"Per our SLA Agreement §12 (Incident Coordination), we request immediate escalation "
                    f"and a dedicated support bridge. Your SLA response time commitment is currently at risk. "
                    f"Please confirm incident acknowledgement and provide ETA within 30 minutes."
                ),
                "contractual_references": ["MSA §12 — Incident Response", "SLA Schedule B — Critical Incident Definition"],
            },
        }

        # Match audience
        template = None
        for key in templates:
            if key in audience_lower:
                template = templates[key]
                break
        if not template:
            template = templates["technical_teams"]

        result = {
            "notification_id": f"NOTIF-{_seed_from_str(message + audience) % 99999:05d}",
            "sent_at_utc": now.isoformat() + "Z",
            "audience": audience,
            "incident_id": incident_id,
            "channels": template["channel"],
            "tone": template["tone"],
            "subject": template["subject"],
            "message_body": template["body"],
            "status": "DELIVERED",
            "delivery_confirmation": f"Confirmed delivery to {audience} distribution list at {now.strftime('%H:%M:%S UTC')}",
            **{k: v for k, v in template.items() if k not in ("channel", "tone", "subject", "body")},
        }
        return json.dumps(result, indent=2)


# ---------------------------------------------------------------------------
# 6. get_service_catalog
# ---------------------------------------------------------------------------

class ServiceCatalogTool(BaseTool):
    name: str = "get_service_catalog"
    description: str = (
        "Returns FinServe's full production service catalog with RTO, RPO, MTPD, "
        "service tiers, dependency chains, DR strategies, last DR test results, "
        "compliance requirements, and service owners."
    )

    def _run(self, tier_filter: Optional[str] = None, service_name: Optional[str] = None) -> str:
        # Real-world BCM concept: Service catalog is the foundation of BIA.
        # Tier 1 = mission critical, Tier 2 = important, Tier 3 = standard.
        catalog = SERVICE_CATALOG

        if service_name:
            results = {k: v for k, v in catalog.items() if service_name.lower() in k.lower()}
        elif tier_filter:
            tier_num = int(tier_filter) if tier_filter.isdigit() else None
            results = {k: v for k, v in catalog.items() if tier_num is None or v["tier"] == tier_num}
        else:
            results = catalog

        summary = {
            "retrieved_at_utc": datetime.utcnow().isoformat() + "Z",
            "total_services": len(results),
            "tier_1_critical": sum(1 for v in results.values() if v["tier"] == 1),
            "tier_2_important": sum(1 for v in results.values() if v["tier"] == 2),
            "tier_3_standard": sum(1 for v in results.values() if v["tier"] == 3),
            "services": results,
        }
        return json.dumps(summary, indent=2)


# ---------------------------------------------------------------------------
# 7. log_lesson
# ---------------------------------------------------------------------------

class LogLessonTool(BaseTool):
    name: str = "log_lesson"
    description: str = (
        "Logs a post-incident lesson learned using proper PIR (Post-Incident Review) structure. "
        "Categorizes as process/technology/people issue, identifies root cause vs contributing factors, "
        "generates SMART remediation items, and references NIST CSF / ISO 22301 / ITIL 4."
    )

    def _run(self, lesson: str, category: str = "process", timeline_event: str = "") -> str:
        # Real-world BCM concept: ISO 22301 §10.2 requires documented continual improvement.
        # Lessons must be actionable — not just observations.
        seed = _seed_from_str(lesson)
        now = datetime.utcnow()

        category = category.lower()
        if category not in ("process", "technology", "people"):
            category = "process"

        framework_mapping = {
            "process": {
                "iso_22301": "§10.2 Nonconformity and corrective action",
                "nist_csf": "RC.IM-1: Recovery plans incorporate lessons learned",
                "itil_4": "Continual Improvement practice — Service Value Chain activity",
            },
            "technology": {
                "iso_22301": "§8.4 Business continuity procedures",
                "nist_csf": "PR.IP-2: Cybersecurity in the system development life cycle",
                "itil_4": "Problem Management — Known Error Database entry",
            },
            "people": {
                "iso_22301": "§7.2 Competence / §7.3 Awareness",
                "nist_csf": "PR.AT-1: All users informed and trained",
                "itil_4": "Workforce and Talent Management practice",
            },
        }

        remediation_items = [
            {
                "item_id": f"REM-{seed % 9000 + 1000:04d}",
                "action": f"Implement automated detection for: {lesson[:60]}",
                "owner": "CIRT Lead",
                "due_date": (now + timedelta(days=30)).strftime("%Y-%m-%d"),
                "priority": "High",
                "success_metric": "Zero recurrence in next 90 days",
            },
            {
                "item_id": f"REM-{(seed + 1) % 9000 + 1000:04d}",
                "action": "Update DR runbook to address identified gap",
                "owner": "Platform Engineering Lead",
                "due_date": (now + timedelta(days=14)).strftime("%Y-%m-%d"),
                "priority": "Critical",
                "success_metric": "Runbook reviewed and tested in next scheduled DR exercise",
            },
            {
                "item_id": f"REM-{(seed + 2) % 9000 + 1000:04d}",
                "action": "Schedule tabletop exercise to validate improved procedure",
                "owner": "BCM Manager",
                "due_date": (now + timedelta(days=60)).strftime("%Y-%m-%d"),
                "priority": "Medium",
                "success_metric": "Tabletop exercise conducted with >80% team participation",
            },
        ]

        result = {
            "pir_entry_id": f"PIR-{seed % 9999:05d}",
            "logged_at_utc": now.isoformat() + "Z",
            "lesson": lesson,
            "category": category,
            "timeline_event_reference": timeline_event or "General incident timeline",
            "root_cause": f"Root cause: {category.capitalize()} failure — {lesson[:80]}",
            "contributing_factors": [
                "Insufficient monitoring alert thresholds",
                "DR runbook not updated post last infrastructure change",
                "On-call escalation path not clearly defined for this scenario",
            ],
            "framework_references": framework_mapping[category],
            "remediation_items": remediation_items,
            "pir_review_date": (now + timedelta(days=7)).strftime("%Y-%m-%d"),
            "pir_owner": "BCM Manager / CISO",
            "status": "OPEN — Remediation tracking started",
        }
        return json.dumps(result, indent=2)


# ---------------------------------------------------------------------------
# 8. check_service_health (NEW)
# ---------------------------------------------------------------------------

class CheckServiceHealthTool(BaseTool):
    name: str = "check_service_health"
    description: str = (
        "Simulates querying the monitoring stack (Datadog/PagerDuty/Grafana) for a service. "
        "Returns: status (up/degraded/down), latency percentiles (p50/p95/p99), error rate, "
        "throughput, CPU/memory utilization, active alerts, last deployment, and on-call engineer."
    )

    def _run(self, service_name: str) -> str:
        # Real-world BCM concept: Observability triad — metrics, logs, traces.
        # p95/p99 latency spikes often precede full outage by minutes.
        seed = _seed_from_str(service_name)

        # Simulate degradation patterns — some services cascade
        degradation_services = {
            "Mobile Banking App": "degraded",
            "Online Transfers": "degraded",
            "Reconciliation Service": "down",
            "Data Warehouse": "degraded",
        }
        status = degradation_services.get(service_name, "up")

        base_p50 = _seeded_float(seed, 45, 120)
        base_p95 = base_p50 * _seeded_float(seed + 1, 2.0, 3.5)
        base_p99 = base_p95 * _seeded_float(seed + 2, 1.5, 2.5)

        if status == "degraded":
            base_p50 *= 3.2
            base_p95 *= 5.0
            base_p99 *= 8.0
            error_rate = _seeded_float(seed + 3, 12.0, 35.0)
            cpu_pct = _seeded_float(seed + 4, 78.0, 95.0)
        elif status == "down":
            base_p50 = 0
            error_rate = 100.0
            cpu_pct = 0.0
        else:
            error_rate = _seeded_float(seed + 3, 0.01, 0.5)
            cpu_pct = _seeded_float(seed + 4, 15.0, 55.0)

        active_alerts = []
        if status == "degraded":
            active_alerts = [
                {"alert_id": f"ALT-{seed % 9999:05d}", "severity": "critical", "message": f"{service_name} p99 latency > 5s threshold", "firing_since": "12 minutes"},
                {"alert_id": f"ALT-{(seed+1) % 9999:05d}", "severity": "warning", "message": f"{service_name} error rate > 10%", "firing_since": "8 minutes"},
            ]
        elif status == "down":
            active_alerts = [
                {"alert_id": f"ALT-{seed % 9999:05d}", "severity": "critical", "message": f"{service_name} health check FAILING", "firing_since": "23 minutes"},
                {"alert_id": f"ALT-{(seed+1) % 9999:05d}", "severity": "critical", "message": f"{service_name} no traffic — possible network isolation", "firing_since": "21 minutes"},
            ]

        on_call_engineers = ["Alice Chen (CIRT)", "Bob Okonkwo (Platform)", "Sunita Patel (Security)", "James Reyes (DBA)"]

        result = {
            "service": service_name,
            "queried_at_utc": datetime.utcnow().isoformat() + "Z",
            "monitoring_sources": ["Datadog APM", "PagerDuty", "Grafana Cloud"],
            "status": status.upper(),
            "metrics": {
                "latency_ms": {
                    "p50": round(base_p50, 1),
                    "p95": round(base_p95, 1),
                    "p99": round(base_p99, 1),
                },
                "error_rate_pct": error_rate,
                "throughput_rpm": 0 if status == "down" else _seeded_float(seed + 5, 200, 5000),
                "cpu_utilization_pct": cpu_pct,
                "memory_utilization_pct": _seeded_float(seed + 6, 40, 85) if status != "down" else 0.0,
            },
            "active_alerts": active_alerts,
            "alert_count": len(active_alerts),
            "last_deployment": {
                "timestamp_utc": (datetime.utcnow() - timedelta(hours=_seeded_float(seed + 7, 2, 72))).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "deployed_by": "ci-pipeline-main",
                "commit": hashlib.sha256(service_name.encode()).hexdigest()[:8],
            },
            "on_call_engineer": _seeded_choice(seed + 8, on_call_engineers),
        }
        return json.dumps(result, indent=2)


# ---------------------------------------------------------------------------
# 9. query_cmdb (NEW)
# ---------------------------------------------------------------------------

class QueryCMDBTool(BaseTool):
    name: str = "query_cmdb"
    description: str = (
        "Queries the FinServe Configuration Management Database (CMDB). "
        "Returns configuration items (CIs), relationships, owner teams, environments, "
        "last change date, and compliance status. Supports query by service name or CI type."
    )

    def _run(self, query: str, query_type: str = "service") -> str:
        # Real-world BCM concept: CMDB is the single source of truth for infrastructure relationships.
        # Without CMDB, incident responders cannot determine blast radius quickly.
        cmdb_records = {
            "finserve-prod-db-01": {
                "ci_type": "Database Server",
                "hostname": "finserve-prod-db-01.internal.finserve.com",
                "environment": "Production",
                "owner_team": "Data Platform Engineering",
                "related_services": ["Transaction Database", "Core Banking API"],
                "relationships": {
                    "runs_on": "VMware ESXi cluster — DC1-RACK-12",
                    "replicates_to": "finserve-dr-db-01.dr.finserve.com",
                    "backed_up_by": "Veeam B&R — S3 target finserve-backups-prod",
                },
                "last_change_date": "2024-11-28",
                "last_change_ref": "CHG-2024-4892 — DB patch MS-SQL-KB5032679",
                "compliance_status": "COMPLIANT",
                "compliance_frameworks": ["PCI-DSS", "SOX"],
                "patch_level": "Current (patched 2024-11-28)",
            },
            "finserve-app-cluster": {
                "ci_type": "Kubernetes Cluster",
                "hostname": "finserve-prod-k8s.internal.finserve.com",
                "environment": "Production",
                "owner_team": "Platform Engineering",
                "related_services": ["Mobile Banking App", "Customer Portal", "Online Transfers"],
                "relationships": {
                    "hosted_on": "AWS EKS — us-east-1",
                    "ingress": "AWS ALB + Cloudflare",
                    "secrets_store": "HashiCorp Vault — vault.internal.finserve.com",
                },
                "last_change_date": "2024-12-01",
                "last_change_ref": "CHG-2024-5001 — K8s node upgrade 1.28→1.29",
                "compliance_status": "COMPLIANT",
                "compliance_frameworks": ["PCI-DSS", "ISO 27001"],
                "patch_level": "Current",
            },
            "finserve-paybridge-integration": {
                "ci_type": "Third-Party Integration",
                "hostname": "api.paybridge.io",
                "environment": "Production",
                "owner_team": "Payments Engineering",
                "related_services": ["Online Transfers", "Fraud Detection Engine"],
                "relationships": {
                    "vendor": "PayBridge Ltd",
                    "contract_ref": "MSA-PAYBRIDGE-2022-001",
                    "sla_tier": "Gold (99.95% uptime SLA)",
                    "fallback": "FinancePay API (secondary processor)",
                },
                "last_change_date": "2024-09-15",
                "last_change_ref": "CHG-2024-3455 — API version upgrade v2→v3",
                "compliance_status": "UNDER REVIEW — Vendor audit pending",
                "compliance_frameworks": ["PCI-DSS"],
                "patch_level": "Vendor-managed",
            },
        }

        # Find matching CIs
        query_lower = query.lower()
        matching = {}
        for ci_name, ci_data in cmdb_records.items():
            if (query_lower in ci_name.lower() or
                    query_lower in ci_data.get("ci_type", "").lower() or
                    any(query_lower in s.lower() for s in ci_data.get("related_services", []))):
                matching[ci_name] = ci_data

        if not matching:
            matching = cmdb_records  # Return all if no match

        return json.dumps({
            "query": query,
            "query_type": query_type,
            "queried_at_utc": datetime.utcnow().isoformat() + "Z",
            "results_count": len(matching),
            "configuration_items": matching,
        }, indent=2)


# ---------------------------------------------------------------------------
# 10. execute_runbook (NEW)
# ---------------------------------------------------------------------------

class ExecuteRunbookTool(BaseTool):
    name: str = "execute_runbook"
    description: str = (
        "Executes a predefined operational runbook. Returns step-by-step results "
        "with some steps succeeding and others requiring manual intervention. "
        "Available runbooks: RB-DR-001, RB-SEC-005, RB-NET-002, RB-COMMS-003, RB-CRED-004, RB-DNS-006."
    )

    def _run(self, runbook_id: str, parameters: str = "") -> str:
        # Real-world BCM concept: Runbooks encode institutional knowledge and must be
        # exercised regularly. Steps may fail — manual intervention is expected for
        # complex DR scenarios.
        runbooks = {
            "RB-DR-001": {
                "name": "DR Site Activation — Full Failover",
                "steps": [
                    ("Verify DR site readiness (health check)", "AUTOMATED", True),
                    ("Confirm replication lag within RPO threshold", "AUTOMATED", True),
                    ("Notify senior leadership of DR activation", "AUTOMATED", True),
                    ("Switch DNS records to DR endpoints (TTL 30s)", "AUTOMATED", True),
                    ("Validate application tier startup on DR", "AUTOMATED", True),
                    ("Run smoke test suite (500 critical paths)", "AUTOMATED", False),  # manual
                    ("Confirm transaction processing resumed", "MANUAL", False),
                    ("Update incident record with DR status", "AUTOMATED", True),
                ],
            },
            "RB-SEC-005": {
                "name": "Security Containment — Network Isolation",
                "steps": [
                    ("Identify affected host IPs from SIEM alert", "AUTOMATED", True),
                    ("Apply ACL block at perimeter firewall", "AUTOMATED", True),
                    ("Move affected hosts to quarantine VLAN", "AUTOMATED", True),
                    ("Revoke active sessions for compromised accounts", "AUTOMATED", True),
                    ("Trigger forensic memory snapshot", "AUTOMATED", True),
                    ("Preserve disk image for evidence (do NOT power off)", "MANUAL", False),  # manual
                    ("Notify CIRT Lead and Legal", "AUTOMATED", True),
                    ("Update CMDB — mark CIs as QUARANTINED", "AUTOMATED", True),
                ],
            },
            "RB-NET-002": {
                "name": "DDoS Mitigation — Traffic Scrubbing Activation",
                "steps": [
                    ("Confirm DDoS signature in traffic analytics", "AUTOMATED", True),
                    ("Activate Cloudflare Under Attack Mode", "AUTOMATED", True),
                    ("Apply rate limiting: >500 req/s per IP → block", "AUTOMATED", True),
                    ("Black-hole suspicious ASNs via BGP community 65535:666", "AUTOMATED", True),
                    ("Scale up scrubbing capacity (+8 nodes)", "AUTOMATED", False),  # manual
                    ("Monitor traffic baseline recovery", "MANUAL", False),
                    ("Confirm service restoration via health checks", "AUTOMATED", True),
                ],
            },
            "RB-CRED-004": {
                "name": "Emergency Credential Rotation",
                "steps": [
                    ("Enumerate all credentials for affected service account", "AUTOMATED", True),
                    ("Generate new credentials via HashiCorp Vault", "AUTOMATED", True),
                    ("Rotate database passwords (zero-downtime rotation)", "AUTOMATED", True),
                    ("Update Kubernetes secrets", "AUTOMATED", True),
                    ("Rotate API keys in secret store", "AUTOMATED", True),
                    ("Invalidate all active JWT tokens (force re-auth)", "AUTOMATED", True),
                    ("Verify no old credentials remain in config files", "MANUAL", False),  # manual
                    ("Audit log review — confirm no credential reuse", "MANUAL", False),
                ],
            },
            "RB-DNS-006": {
                "name": "DNS Failover — DR Endpoint Switch",
                "steps": [
                    ("Confirm primary site unresponsive (3/3 health checks)", "AUTOMATED", True),
                    ("Update DNS A records to DR IP addresses", "AUTOMATED", True),
                    ("Reduce TTL to 30 seconds", "AUTOMATED", True),
                    ("Verify propagation via DNS checkers (8 regions)", "AUTOMATED", True),
                    ("Validate SSL certificates on DR endpoints", "AUTOMATED", True),
                    ("Confirm CDN cache purge for DR switchover", "AUTOMATED", False),  # manual
                    ("Monitor DNS resolution from 10 global PoPs", "AUTOMATED", True),
                ],
            },
            "RB-COMMS-003": {
                "name": "Stakeholder Communication — Major Incident Protocol",
                "steps": [
                    ("Declare incident on status page (internal first)", "AUTOMATED", True),
                    ("Page on-call engineer and CISO via PagerDuty", "AUTOMATED", True),
                    ("Open war room bridge call", "AUTOMATED", True),
                    ("Send executive notification (encrypted email)", "AUTOMATED", True),
                    ("Publish customer-facing status page update", "AUTOMATED", True),
                    ("Prepare regulator notification draft (Legal review)", "MANUAL", False),  # manual
                    ("Send 30-minute update cycle reminder", "AUTOMATED", True),
                ],
            },
        }

        rb = runbooks.get(runbook_id.upper(), runbooks.get("RB-DR-001"))
        now = datetime.utcnow()
        seed = _seed_from_str(runbook_id + parameters)

        execution_log = []
        manual_steps = []
        t = now
        all_automated_passed = True

        for i, (step_desc, step_type, auto_success) in enumerate(rb["steps"], 1):
            elapsed = _seeded_float(seed + i, 10, 120)
            t += timedelta(seconds=elapsed)
            if step_type == "MANUAL" or not auto_success:
                status = "MANUAL_INTERVENTION_REQUIRED"
                manual_steps.append(f"Step {i}: {step_desc}")
                all_automated_passed = False
            else:
                status = "PASS"

            execution_log.append({
                "step": i,
                "description": step_desc,
                "type": step_type,
                "status": status,
                "timestamp_utc": t.isoformat() + "Z",
                "elapsed_seconds": round(elapsed),
            })

        result = {
            "runbook_id": runbook_id,
            "runbook_name": rb["name"],
            "execution_id": f"EXEC-{seed % 99999:05d}",
            "started_at_utc": now.isoformat() + "Z",
            "completed_at_utc": t.isoformat() + "Z",
            "total_duration_seconds": round((t - now).total_seconds()),
            "parameters": parameters,
            "execution_log": execution_log,
            "automated_steps_passed": all_automated_passed,
            "manual_interventions_required": manual_steps,
            "overall_status": "COMPLETED_WITH_MANUAL_STEPS" if manual_steps else "FULLY_AUTOMATED_SUCCESS",
        }
        return json.dumps(result, indent=2)


# ---------------------------------------------------------------------------
# 11. check_compliance_status (NEW)
# ---------------------------------------------------------------------------

class CheckComplianceStatusTool(BaseTool):
    name: str = "check_compliance_status"
    description: str = (
        "Returns FinServe's current compliance posture against PCI-DSS, SOX, GDPR, SOC 2, ISO 27001. "
        "Identifies controls impacted by the current incident and regulatory notification deadlines."
    )

    def _run(self, incident_type: str = "general") -> str:
        # Real-world BCM concept: During an incident, compliance obligations don't pause.
        # GDPR's 72-hour clock, PCI-DSS card brand notification, and FCA reporting
        # all run concurrently with technical recovery efforts.
        now = datetime.utcnow()
        event_type = _detect_event_type(incident_type)

        compliance_posture = {
            "PCI_DSS": {
                "version": "v4.0",
                "overall_status": "COMPLIANT",
                "last_assessment": "2024-09-30 (QSA audit)",
                "next_assessment_due": "2025-09-30",
                "impacted_requirements": [
                    "Req 12.10 — Incident Response Plan must be activated",
                    "Req 10.7 — Audit log failures must be addressed immediately",
                ] if event_type in ("ransomware", "data_breach") else ["No PCI-DSS controls directly impacted"],
                "card_brand_notification_required": event_type in ("data_breach", "supply_chain"),
                "notification_deadline": "Within 24 hours to Visa/Mastercard" if event_type in ("data_breach", "supply_chain") else "N/A",
            },
            "SOX": {
                "version": "Sarbanes-Oxley Act 2002",
                "overall_status": "COMPLIANT",
                "last_assessment": "2024-10-31 (internal audit)",
                "next_assessment_due": "2025-10-31",
                "impacted_controls": [
                    "ITGC-01 — Change management controls (emergency change required)",
                    "ITGC-04 — Business continuity controls being exercised",
                ] if event_type in ("ransomware", "cascading_failure") else ["No SOX controls directly impacted"],
                "material_weakness_risk": event_type in ("ransomware", "cascading_failure"),
                "cfo_notification_required": event_type in ("ransomware", "cascading_failure"),
            },
            "GDPR": {
                "regulation": "EU GDPR 2016/679",
                "overall_status": "COMPLIANT",
                "dpo": "Dr. Maria Schneider (DPO@finserve.com)",
                "supervisory_authority": "ICO (UK) / local DPA",
                "breach_notification_required": event_type in ("data_breach", "insider_threat", "supply_chain"),
                "notification_deadline_hours": 72,
                "notification_deadline_utc": (now + timedelta(hours=72)).isoformat() + "Z",
                "impacted_articles": [
                    "Art. 33 — Notification of breach to supervisory authority (72h)",
                    "Art. 34 — Communication to data subjects (if high risk)",
                ] if event_type in ("data_breach", "insider_threat") else ["No GDPR breach notification triggered"],
                "estimated_data_subjects_affected": "2,300,000" if event_type in ("data_breach", "insider_threat") else "0",
            },
            "SOC_2": {
                "type": "SOC 2 Type II",
                "overall_status": "COMPLIANT",
                "last_report_period": "2024-01-01 to 2024-12-31",
                "auditor": "KPMG LLP",
                "trust_service_criteria_impacted": [
                    "CC7.1 — Threat detection mechanisms",
                    "CC7.2 — Monitoring for anomalies",
                    "A1.2 — Availability — system capacity and performance",
                ] if event_type != "cloud_misconfiguration" else ["CC6.3 — Logical access controls"],
            },
            "ISO_27001": {
                "standard": "ISO/IEC 27001:2022",
                "overall_status": "CERTIFIED",
                "certification_body": "BSI Group",
                "valid_until": "2026-03-15",
                "impacted_controls": [
                    "A.5.26 — Response to information security incidents",
                    "A.5.30 — ICT readiness for business continuity",
                    "A.8.15 — Logging",
                ],
            },
        }

        # Determine active notification obligations
        active_deadlines = []
        if compliance_posture["GDPR"]["breach_notification_required"]:
            active_deadlines.append({
                "framework": "GDPR Art. 33",
                "action": "Notify supervisory authority (ICO)",
                "deadline_utc": compliance_posture["GDPR"]["notification_deadline_utc"],
                "urgency": "CRITICAL",
            })
        if compliance_posture["PCI_DSS"]["card_brand_notification_required"]:
            active_deadlines.append({
                "framework": "PCI-DSS 12.10.4",
                "action": "Notify card brands (Visa/Mastercard)",
                "deadline_utc": (now + timedelta(hours=24)).isoformat() + "Z",
                "urgency": "CRITICAL",
            })
        if compliance_posture["SOX"]["cfo_notification_required"]:
            active_deadlines.append({
                "framework": "SOX Section 302",
                "action": "Notify CFO — potential material disclosure",
                "deadline_utc": (now + timedelta(hours=4)).isoformat() + "Z",
                "urgency": "HIGH",
            })

        return json.dumps({
            "checked_at_utc": now.isoformat() + "Z",
            "incident_type": incident_type,
            "compliance_posture": compliance_posture,
            "active_notification_deadlines": active_deadlines,
            "overall_compliance_risk": "HIGH" if active_deadlines else "MEDIUM",
        }, indent=2)


# ---------------------------------------------------------------------------
# 12. assess_vendor_impact (NEW)
# ---------------------------------------------------------------------------

class AssessVendorImpactTool(BaseTool):
    name: str = "assess_vendor_impact"
    description: str = (
        "Evaluates impact on/from third-party vendors and partners. "
        "Returns affected contracts, SLA status, vendor communication status, "
        "alternative availability, and contractual penalty exposure."
    )

    def _run(self, incident_description: str) -> str:
        now = datetime.utcnow()
        event_type = _detect_event_type(incident_description)
        seed = _seed_from_str(incident_description)

        vendor_registry = [
            {
                "vendor": "PayBridge Ltd",
                "service": "Payment Processing API",
                "contract_ref": "MSA-PAYBRIDGE-2022-001",
                "sla_uptime": "99.95%",
                "current_sla_status": "BREACHED" if event_type in ("supply_chain", "ddos") else "NOMINAL",
                "sla_penalty_per_hour": 15_000,
                "alternative": "FinancePay (secondary processor) — 30-min activation",
                "contact": "PayBridge Incident Hotline: +44-20-7946-0100",
                "communication_status": "Notified — awaiting acknowledgement" if event_type == "supply_chain" else "Not notified",
                "impact_assessment": "HIGH — all payment transactions at risk" if event_type in ("supply_chain", "ddos") else "LOW",
            },
            {
                "vendor": "AWS",
                "service": "Cloud Infrastructure (EKS, RDS, S3)",
                "contract_ref": "AWS-ENT-FINSERVE-2021",
                "sla_uptime": "99.99% per service SLA",
                "current_sla_status": "DEGRADED" if event_type == "ddos" else "NOMINAL",
                "sla_penalty_per_hour": 0,  # AWS gives credits not cash
                "alternative": "Azure DR environment (warm standby, 60-min activation)",
                "contact": "AWS Enterprise Support: TAM escalation active",
                "communication_status": "TAM engaged" if event_type == "ddos" else "Not engaged",
                "impact_assessment": "HIGH — hosting platform" if event_type == "ddos" else "LOW",
            },
            {
                "vendor": "Cloudflare",
                "service": "DDoS Protection / WAF / CDN",
                "contract_ref": "CF-ENT-FINSERVE-2023",
                "sla_uptime": "100% SLA",
                "current_sla_status": "ACTIVE",
                "sla_penalty_per_hour": 5_000,
                "alternative": "Akamai Kona Site Defender (emergency provisioning 4h)",
                "contact": "Cloudflare Enterprise SOC: +1-650-319-8930",
                "communication_status": "Activated" if event_type == "ddos" else "Standby",
                "impact_assessment": "CRITICAL — primary DDoS mitigation" if event_type == "ddos" else "LOW",
            },
        ]

        # Contractual penalty calculation
        total_penalty_exposure = sum(
            v["sla_penalty_per_hour"] for v in vendor_registry if v["current_sla_status"] in ("BREACHED", "DEGRADED")
        )

        return json.dumps({
            "assessed_at_utc": now.isoformat() + "Z",
            "incident_type": event_type,
            "vendor_assessments": vendor_registry,
            "summary": {
                "vendors_impacted": sum(1 for v in vendor_registry if v["current_sla_status"] != "NOMINAL"),
                "total_sla_penalty_exposure_per_hour_usd": total_penalty_exposure,
                "vendors_with_alternatives": sum(1 for v in vendor_registry if v["alternative"]),
                "vendors_notified": sum(1 for v in vendor_registry if "Notified" in v["communication_status"] or "engaged" in v["communication_status"].lower() or "Activated" in v["communication_status"]),
            },
        }, indent=2)


# ---------------------------------------------------------------------------
# 13. coordinate_war_room (NEW)
# ---------------------------------------------------------------------------

class CoordinateWarRoomTool(BaseTool):
    name: str = "coordinate_war_room"
    description: str = (
        "Sets up and manages an incident war room / bridge call. "
        "Tracks participants, decisions made, action items, event timeline, and escalation triggers."
    )

    def _run(self, incident_id: str, action: str = "setup", update: str = "") -> str:
        now = datetime.utcnow()
        seed = _seed_from_str(incident_id)

        # Simulated war room state (would be persistent in a real system)
        participants = [
            {"name": "CISO — Sarah Mitchell", "joined_at": (now - timedelta(minutes=12)).strftime("%H:%M UTC"), "role": "Incident Commander"},
            {"name": "VP Engineering — Tom Bradley", "joined_at": (now - timedelta(minutes=10)).strftime("%H:%M UTC"), "role": "Technical Lead"},
            {"name": "DBA Lead — James Reyes", "joined_at": (now - timedelta(minutes=8)).strftime("%H:%M UTC"), "role": "Database SME"},
            {"name": "Legal Counsel — Emma Watson", "joined_at": (now - timedelta(minutes=5)).strftime("%H:%M UTC"), "role": "Legal / Regulatory"},
            {"name": "Communications Lead — Rachel Kim", "joined_at": (now - timedelta(minutes=3)).strftime("%H:%M UTC"), "role": "Comms"},
        ]

        decisions = [
            {"decision": "Declare P1 Major Incident — BCM Plan BCM-FIN-001 activated", "made_by": "CISO", "time": (now - timedelta(minutes=11)).strftime("%H:%M UTC")},
            {"decision": "Approve DR failover for Core Banking API and Transaction Database", "made_by": "CISO + VP Engineering", "time": (now - timedelta(minutes=9)).strftime("%H:%M UTC")},
            {"decision": "Engage Legal — GDPR breach notification clock confirmed running", "made_by": "CISO + Legal", "time": (now - timedelta(minutes=7)).strftime("%H:%M UTC")},
            {"decision": "30-minute stakeholder update cycle approved", "made_by": "Communications Lead", "time": (now - timedelta(minutes=4)).strftime("%H:%M UTC")},
        ]

        action_items = [
            {"item": "Complete forensic snapshot of affected systems", "owner": "CIRT Team", "due": (now + timedelta(minutes=30)).strftime("%H:%M UTC"), "status": "IN PROGRESS"},
            {"item": "Draft customer status page update (plain English)", "owner": "Rachel Kim", "due": (now + timedelta(minutes=15)).strftime("%H:%M UTC"), "status": "PENDING"},
            {"item": "Prepare GDPR breach notification draft", "owner": "Legal / DPO", "due": (now + timedelta(hours=4)).strftime("%H:%M UTC"), "status": "PENDING"},
            {"item": "Validate DR failover completion", "owner": "James Reyes", "due": (now + timedelta(minutes=45)).strftime("%H:%M UTC"), "status": "IN PROGRESS"},
        ]

        escalation_triggers_hit = []
        if "P1" in incident_id or seed % 3 == 0:
            escalation_triggers_hit.append("BCM Plan activation threshold met — P1 declared")
        if seed % 2 == 0:
            escalation_triggers_hit.append("30-minute SLA warning — executive escalation required")

        timeline = [
            {"time": (now - timedelta(minutes=15)).strftime("%H:%M UTC"), "event": "Monitoring alert fired — anomalous traffic detected"},
            {"time": (now - timedelta(minutes=13)).strftime("%H:%M UTC"), "event": "NOC engineer confirmed outage — war room bridge opened"},
            {"time": (now - timedelta(minutes=12)).strftime("%H:%M UTC"), "event": "CISO joined bridge — P1 declared"},
            {"time": (now - timedelta(minutes=9)).strftime("%H:%M UTC"), "event": "DR failover approved and initiated"},
            {"time": (now - timedelta(minutes=5)).strftime("%H:%M UTC"), "event": "Legal engaged — breach notification assessment started"},
            {"time": now.strftime("%H:%M UTC"), "event": f"War room update: {update}" if update else "War room active — recovery in progress"},
        ]

        result = {
            "war_room_id": f"WR-{seed % 9999:05d}",
            "incident_id": incident_id,
            "bridge_number": f"+1-800-FINSERVE x{seed % 9000 + 1000}",
            "bridge_opened_at_utc": (now - timedelta(minutes=13)).isoformat() + "Z",
            "action": action,
            "participants": participants,
            "participant_count": len(participants),
            "decisions_made": decisions,
            "action_items": action_items,
            "open_action_items": sum(1 for ai in action_items if ai["status"] != "COMPLETED"),
            "escalation_triggers_hit": escalation_triggers_hit,
            "incident_timeline": timeline,
            "next_update_due": (now + timedelta(minutes=30)).strftime("%H:%M UTC"),
            "incident_commander": "CISO — Sarah Mitchell",
        }
        return json.dumps(result, indent=2)


# ---------------------------------------------------------------------------
# Instantiate all tools for import
# ---------------------------------------------------------------------------

analyze_security_event = AnalyzeSecurityEventTool()
calculate_impact = CalculateImpactTool()
failover_service = FailoverServiceTool()
create_incident_record = CreateIncidentRecordTool()
send_notification = SendNotificationTool()
get_service_catalog = ServiceCatalogTool()
log_lesson = LogLessonTool()
check_service_health = CheckServiceHealthTool()
query_cmdb = QueryCMDBTool()
execute_runbook = ExecuteRunbookTool()
check_compliance_status = CheckComplianceStatusTool()
assess_vendor_impact = AssessVendorImpactTool()
coordinate_war_room = CoordinateWarRoomTool()

"""
FinServe BCM/ITSM Simulation — Main Entry Point
Instructor: Set EVENT_SCENARIO before each live session.
"""

import os
from dotenv import load_dotenv
from src.bcm_crew import create_bcm_crew
from simulation_engine import SimulationEngine

load_dotenv()

# ---------------------------------------------------------------------------
# INSTRUCTOR: Set this to one of the scenario keys below before each session
# ---------------------------------------------------------------------------
EVENT_SCENARIO = "ransomware"  # Options: ransomware | cloud_outage_ddos | data_breach | insider_threat | supply_chain | cascading_failure

EVENTS = {
    "ransomware": (
        "A ransomware attack (LockBit 3.0 variant) has encrypted the primary data centre. "
        "The Transaction Database and Core Banking API are completely offline. "
        "Mobile Banking and Online Transfers are down for all 2.1M customers. "
        "Backups are potentially compromised — ransom note found on file servers. "
        "No confirmed data exfiltration yet, but lateral movement indicators are present in SIEM."
    ),

    "cloud_outage_ddos": (
        "AWS us-east-1 is experiencing a multi-AZ availability event simultaneously with a "
        "volumetric DDoS attack (peak 2.4 Tbps, UDP flood + HTTPS layer 7 attack). "
        "All FinServe services hosted in us-east-1 are degraded or unreachable. "
        "Cloudflare WAF is partially mitigating but the attack is evolving. "
        "DR region eu-west-1 is unaffected. Customer-facing latency >30 seconds."
    ),

    "data_breach": (
        "A database containing 2.3 million customer records (full PII including names, addresses, "
        "dates of birth, and payment card data) was accessed by an unauthorised party. "
        "The breach vector appears to be a compromised service account (svc-reporting-prod) "
        "exploiting CVE-2023-34362 (MOVEit Transfer SQL injection). "
        "Exfiltration is confirmed via anomalous egress traffic patterns detected in Cloudflare logs — "
        "approximately 4.7GB transferred to an external IP in Eastern Europe over 6 hours. "
        "The GDPR 72-hour notification clock has started. PCI-DSS card brand notification required."
    ),

    "insider_threat": (
        "A privileged database administrator (username: jreyes-dba) has been detected "
        "systematically exporting large volumes of customer financial data to personal Dropbox storage. "
        "DLP alerts flagged the activity. Audit logs confirm the exports span the past 3 weeks — "
        "estimated 1.8 million customer records affected including account balances and transaction history. "
        "The DBA has unrestricted access to all production databases. "
        "HR and Legal must be engaged before any account action. "
        "GDPR breach notification required — data subjects are high-net-worth private banking customers."
    ),

    "supply_chain": (
        "FinServe's critical third-party payment processor, PayBridge Ltd, has disclosed a "
        "compromise of their API gateway infrastructure. The attack vector was a malicious update "
        "to their authentication library (supply chain compromise). "
        "All transactions processed through PayBridge's system in the last 48 hours may be affected — "
        "approximately 890,000 transactions totalling £340M in value. "
        "Card data for those transactions may have been captured by the attacker. "
        "FinServe must immediately assess: suspend PayBridge integration, notify card schemes, "
        "activate backup processor FinancePay, and determine customer notification scope."
    ),

    "cascading_failure": (
        "A failed database migration during a scheduled maintenance window has corrupted the "
        "Transaction Database transaction ledger. The automated rollback procedure failed due to "
        "a schema mismatch introduced in the migration script. "
        "The corruption is now propagating downstream — the Reconciliation Service is processing "
        "corrupt data and generating incorrect financial statements. "
        "Online Transfers are suspended as a precautionary measure. "
        "The Core Banking API is serving stale cached data. "
        "Estimated affected transactions: 47,000 over a 3-hour window. "
        "SOX financial reporting controls are at risk. DBA Lead is on-call but has limited "
        "experience with this specific database version."
    ),
}

# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------

event_description = EVENTS[EVENT_SCENARIO]

print("=" * 80)
print(f"  FINSERVE BCM/ITSM SIMULATION — SCENARIO: {EVENT_SCENARIO.upper()}")
print("=" * 80)
print(f"\nEvent Description:\n{event_description}\n")
print("=" * 80)
print("  Activating BCM Crew...")
print("=" * 80 + "\n")

crew = create_bcm_crew()
result = crew.kickoff(inputs={"event_description": event_description})

print("\n" + "=" * 80)
print("  FINAL INCIDENT RESPONSE OUTPUT FROM CREW AGENTS:")
print("=" * 80)
print(result)
print("=" * 80)

# Auto-grade using simulation engine
engine = SimulationEngine()
score = engine.evaluate(result, EVENT_SCENARIO)

print(f"\n{'=' * 80}")
print(f"  SIMULATION ENGINE SCORE — SCENARIO: {EVENT_SCENARIO.upper()}")
print(f"{'=' * 80}")
print(f"  Overall KPI Score: {score['overall_kpi_score']}%")
print(f"  Grade: {score.get('grade', 'N/A')}")
print(f"{'=' * 80}\n")

"""
BCM/ITSM Task Definitions for FinServe Incident Response Simulation.
Tasks follow a sequential pipeline where each agent's output feeds the next.
Framework references: ITIL 4, ISO 22301, NIST CSF, MITRE ATT&CK, PCI-DSS, GDPR.
"""

from crewai import Task
from src.agents import create_agents

# Create all agents once — shared across task definitions
agents = create_agents()

incident_classifier = agents[0]
secops_analyst      = agents[1]
impact_analyst      = agents[2]
change_manager      = agents[3]
recovery_engineer   = agents[4]
comms_agent         = agents[5]


# ---------------------------------------------------------------------------
# Task 1: Incident Classification & Triage
# Agent: Incident Classification Specialist
# ---------------------------------------------------------------------------
task_classify = Task(
    description=(
        "You are responding to the following event: {event_description}\n\n"
        "Follow the ITIL 4 incident triage methodology:\n"
        "1. Query check_service_health for all Tier 1 services to confirm which are impacted.\n"
        "2. Use query_cmdb to traverse the CI relationships and determine the full blast radius.\n"
        "3. Classify the event as: STANDARD INCIDENT / MAJOR INCIDENT / CRISIS using the NIST P1-P5 "
        "severity scale and the ITIL 4 priority matrix (Impact × Urgency).\n"
        "4. Determine whether BCM Plan BCM-FIN-001 activation criteria are met "
        "(activate if P1, or if >2 Tier-1 services are impacted).\n"
        "5. Create a formal ITIL 4 incident record using create_incident_record with the appropriate "
        "impact and urgency levels.\n"
        "6. Define the escalation path and war room bridge requirements.\n\n"
        "Reference: ITIL 4 Incident Management Practice, BCM-FIN-001 §4 (BCM Activation Criteria)"
    ),
    agent=incident_classifier,
    expected_output=(
        "A structured incident classification report containing:\n"
        "- Incident ID (from create_incident_record)\n"
        "- Severity classification (P1/P2/P3 with NIST rationale)\n"
        "- Incident type: STANDARD / MAJOR / CRISIS\n"
        "- BCM plan activation decision (YES/NO with justification)\n"
        "- Confirmed affected services with current health status (from check_service_health)\n"
        "- CI blast radius from CMDB traversal\n"
        "- Escalation path (who must be notified in what order)\n"
        "- SLA breach timeline (when P1 SLA will be breached if unresolved)\n"
        "- War room bridge details"
    ),
)


# ---------------------------------------------------------------------------
# Task 2: Security Containment & Forensic Preservation
# Agent: SecOps Analyst
# Context: Uses classification output to scope containment actions
# ---------------------------------------------------------------------------
task_secops_containment = Task(
    description=(
        "Based on the incident classification in the previous task output, perform security containment.\n\n"
        "Event: {event_description}\n\n"
        "Follow the CIRT containment protocol:\n"
        "1. Use analyze_security_event to perform threat intelligence analysis — identify attack vector, "
        "MITRE ATT&CK mapping, IOCs, and lateral movement indicators.\n"
        "2. Use query_cmdb to identify all CIs that must be isolated or preserved.\n"
        "3. Execute the appropriate containment runbook:\n"
        "   - For ransomware/malware: RB-SEC-005 (Network Isolation)\n"
        "   - For credential compromise: RB-CRED-004 (Credential Rotation)\n"
        "   - For DDoS: RB-NET-002 (DDoS Mitigation)\n"
        "4. Use check_service_health to confirm containment is effective (affected systems should show "
        "status changes post-containment).\n"
        "5. Document all containment actions with timestamps for legal chain-of-custody.\n"
        "6. Identify which systems are safe for the Recovery Engineer to begin restoring.\n\n"
        "CRITICAL: Do NOT power off affected systems without Legal sign-off. "
        "Forensic snapshot must precede any recovery action.\n\n"
        "Reference: MITRE ATT&CK for Financial Services, NIST SP 800-61r2 (Incident Handling Guide), "
        "CIRT Playbook CP-001"
    ),
    agent=secops_analyst,
    context=[task_classify],
    expected_output=(
        "A structured containment and forensic report containing:\n"
        "- Threat intelligence analysis (attack type, MITRE ATT&CK tactics/techniques, CVE refs)\n"
        "- IOCs extracted and confirmed\n"
        "- Lateral movement assessment (YES/NO with evidence)\n"
        "- List of isolated/quarantined systems (CI names, isolation method, timestamp)\n"
        "- Runbook execution results (which steps passed, which required manual intervention)\n"
        "- Forensic evidence preserved (types of snapshots taken, storage location)\n"
        "- Containment effectiveness assessment\n"
        "- List of systems cleared for recovery operations\n"
        "- Eradication steps recommended before recovery"
    ),
)


# ---------------------------------------------------------------------------
# Task 3: Business Impact Analysis
# Agent: Business Impact Analyst
# Context: Uses classification + containment output for scoped BIA
# ---------------------------------------------------------------------------
task_impact_analysis = Task(
    description=(
        "Produce a formal Business Impact Analysis (BIA) for this incident. "
        "Base your analysis on the incident classification and containment scope from prior task outputs.\n\n"
        "Event: {event_description}\n\n"
        "Follow FinServe's BIA methodology:\n"
        "1. Use get_service_catalog to retrieve the full service catalog with RTO/RPO/MTPD values.\n"
        "2. Use calculate_impact for each affected Tier-1 service, modelling non-linear time-based "
        "degradation (run at 1h, 2h, and 4h intervals to show the cost escalation curve).\n"
        "3. Map cascading impacts: identify which downstream Tier-2/3 services are degraded and by "
        "what percentage.\n"
        "4. Use check_compliance_status to identify all active regulatory notification deadlines and "
        "controls impacted (PCI-DSS, GDPR, SOX).\n"
        "5. Use assess_vendor_impact to identify affected third-party vendors, SLA exposure, and "
        "alternative vendor activation options.\n"
        "6. Produce a prioritised recovery sequence with financial justification.\n\n"
        "Reference: BIA Methodology BIA-FIN-002, ITIL 4 Service Continuity Management, "
        "ISO 22301 §8.3 (Business Impact Analysis)"
    ),
    agent=impact_analyst,
    context=[task_classify, task_secops_containment],
    expected_output=(
        "A formal BIA report containing:\n"
        "- Direct financial exposure (revenue loss per hour, SLA penalties, regulatory fine risk)\n"
        "- Time-based cost escalation table (1h vs 2h vs 4h financial exposure)\n"
        "- Cascade impact map (Tier 1 → Tier 2 → Tier 3 degradation percentages)\n"
        "- Regulatory compliance status and active notification deadlines with exact UTC timestamps\n"
        "- Vendor impact assessment (impacted SLAs, penalty exposure, alternative activation status)\n"
        "- Customer impact (number affected, reputational damage score, churn probability)\n"
        "- Prioritised recovery order (service name, priority rank, financial justification, RTO target)\n"
        "- Total estimated financial exposure if incident continues for 4 hours"
    ),
)


# ---------------------------------------------------------------------------
# Task 4: Emergency Change Management
# Agent: Change & Release Manager
# Context: Uses BIA output to govern the specific changes needed for recovery
# ---------------------------------------------------------------------------
task_emergency_change = Task(
    description=(
        "Govern all emergency changes required to recover from this incident. "
        "Reference the BIA prioritised recovery sequence and containment actions from prior tasks.\n\n"
        "Event: {event_description}\n\n"
        "Follow the Emergency Change Management procedure ECM-001:\n"
        "1. Use query_cmdb to identify all CIs that will be modified by the proposed recovery actions.\n"
        "2. For each proposed change (failover, DNS switch, credential rotation, runbook execution):\n"
        "   a. Conduct a rapid 5-minute virtual e-CAB risk assessment\n"
        "   b. Document: change description, risk rating (Low/Medium/High/Critical), "
        "   rollback plan, and required approvals\n"
        "   c. Simulate e-CAB approval (CISO + CTO sign-off required for P1 changes)\n"
        "3. Use check_compliance_status to confirm that proposed changes do not introduce new "
        "compliance violations (especially SOX ITGC controls).\n"
        "4. Use execute_runbook to simulate a controlled test of the highest-risk change before "
        "full execution.\n"
        "5. Define the post-implementation review schedule (within 24 hours of resolution).\n\n"
        "Reference: ITIL 4 Change Enablement Practice, ECM-001 Emergency Change Procedure, "
        "SOX ITGC Change Management Controls"
    ),
    agent=change_manager,
    context=[task_classify, task_secops_containment, task_impact_analysis],
    expected_output=(
        "An emergency change governance report containing:\n"
        "- List of all emergency changes proposed (one per recovery action)\n"
        "- For each change: change ID, description, risk rating, rollback plan, approval status\n"
        "- e-CAB approval record (who approved, timestamp, conditions)\n"
        "- Compliance impact assessment (which SOX/PCI controls are touched by each change)\n"
        "- Runbook test execution results for highest-risk change\n"
        "- Approved change execution sequence with dependencies\n"
        "- Post-implementation review schedule\n"
        "- Any changes rejected or deferred with justification"
    ),
)


# ---------------------------------------------------------------------------
# Task 5: Service Recovery Execution
# Agent: Recovery Engineer
# Context: Uses BIA priority order + approved changes to execute recovery
# ---------------------------------------------------------------------------
task_recovery = Task(
    description=(
        "Execute the prioritised service recovery plan. "
        "All failover and recovery actions must align with the approved emergency changes from the "
        "Change Manager's output. Do not begin recovery on any system still flagged as "
        "'not cleared for recovery' by the SecOps Analyst.\n\n"
        "Event: {event_description}\n\n"
        "Follow the structured recovery methodology:\n"
        "PHASE 1 — DR Readiness:\n"
        "  1. Use check_service_health on all DR endpoints to verify they are clean and ready.\n"
        "  2. Use query_cmdb to confirm DR CIs have not been affected by the incident.\n\n"
        "PHASE 2 — Prioritised Failover (Tier 1 first):\n"
        "  3. Use failover_service for each affected service in BIA priority order.\n"
        "  4. For database failovers, execute RB-DR-001 runbook and confirm replication lag "
        "  is within RPO before cutting over.\n"
        "  5. For DNS-based failovers, execute RB-DNS-006.\n\n"
        "PHASE 3 — Validation:\n"
        "  6. After each failover, use check_service_health to confirm minimum viable operation.\n"
        "  7. Confirm RTO compliance for each service: flag any services that breached their RTO.\n\n"
        "PHASE 4 — Stability & Lessons:\n"
        "  8. Monitor for 30 minutes of stable operation before declaring recovery complete.\n"
        "  9. Use log_lesson for each significant finding (DR gaps, runbook issues, timing surprises).\n\n"
        "Reference: DR Runbooks RB-DR-001, RB-DNS-006, ISO 22301 §8.4 (BCM Procedures), "
        "ITIL 4 Service Continuity Management"
    ),
    agent=recovery_engineer,
    context=[task_classify, task_secops_containment, task_impact_analysis, task_emergency_change],
    expected_output=(
        "A comprehensive recovery execution report containing:\n"
        "- DR readiness assessment results for all targeted DR endpoints\n"
        "- Failover execution log for each service (outcome, timing, RTO compliance)\n"
        "- Service-by-service validation results (health check post-failover, minimum viable operation)\n"
        "- RTO compliance summary: which services met their RTO, which breached it\n"
        "- RPO compliance summary: any data loss detected, within or outside RPO window\n"
        "- Overall recovery status (COMPLETE / PARTIAL / FAILED)\n"
        "- Stability monitoring results (30-min clean operation confirmed)\n"
        "- Lessons learned entries (structured PIR items with owners and due dates)\n"
        "- Recommended eradication steps before declaring full service restoration"
    ),
)


# ---------------------------------------------------------------------------
# Task 6: Stakeholder Communications
# Agent: Stakeholder Communicator
# Context: Consumes all prior outputs to deliver accurate, timely communications
# ---------------------------------------------------------------------------
task_communications = Task(
    description=(
        "Manage all stakeholder communications for this incident from start to resolution. "
        "Your communications must be based on confirmed facts from the prior task outputs — "
        "do not speculate or communicate unverified information.\n\n"
        "Event: {event_description}\n\n"
        "Follow the Crisis Communications Protocol CC-001:\n"
        "1. Use coordinate_war_room to set up the incident war room and establish the single source "
        "of truth for the incident.\n"
        "2. Send notifications in this mandatory sequence (internal before external):\n"
        "   a. Technical teams — full technical context, runbook references, on-call contacts\n"
        "   b. Executives — business impact summary, decision points, financial exposure\n"
        "   c. Board (if P1 and duration >2h) — governance notification per BCM-FIN-001 §8.3\n"
        "   d. Regulators — formal notification per applicable regulatory requirements\n"
        "   e. Customers — empathetic, plain English, workaround instructions\n"
        "   f. Vendors — SLA/contractual coordination\n"
        "3. Use check_compliance_status to confirm all regulatory notification deadlines and "
        "ensure comms are dispatched before each deadline.\n"
        "4. Maintain a 30-minute update cadence for all active stakeholder groups.\n"
        "5. Draft the post-incident summary communication for all audiences.\n\n"
        "Reference: Crisis Communications Protocol CC-001, GDPR Art. 33/34, "
        "PCI-DSS 12.10.4, FCA SYSC 15A, FFIEC BCM Handbook"
    ),
    agent=comms_agent,
    context=[task_classify, task_secops_containment, task_impact_analysis, task_emergency_change, task_recovery],
    expected_output=(
        "A complete stakeholder communications package containing:\n"
        "- War room setup confirmation (participants, bridge number, incident commander)\n"
        "- Full set of drafted notifications for each audience (customers, executives, board, "
        "regulators, technical teams, vendors)\n"
        "- Delivery confirmation and channel used for each notification\n"
        "- Regulatory notification status (GDPR/PCI-DSS/FCA deadlines tracked, met/missed)\n"
        "- Communication timeline (sequence and timestamps of all notifications sent)\n"
        "- 30-minute update log (summary of each update cycle)\n"
        "- Post-incident summary communication draft\n"
        "- Any communication risks identified (e.g., conflicting messaging, missed audience)"
    ),
)

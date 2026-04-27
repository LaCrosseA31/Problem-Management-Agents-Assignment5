"""
Problem Management Task Definitions for FinServe Digital Bank.
Five sequential tasks with context chaining — each task builds on prior outputs.
Pipeline: Detection → Classification → Root Cause → Known Error → Change Proposal
"""

from crewai import Task
from src.agents import create_agents

# Create all agents once — shared across task definitions
agents = create_agents()

trend_analyst = agents[0]
cmdb_correlator = agents[1]
root_cause_investigator = agents[2]
known_error_author = agents[3]
change_proposer = agents[4]


# ---------------------------------------------------------------------------
# Task 1: Problem Detection — Trend Analysis
# Agent: Trend Analyst
# No context dependencies (first in pipeline)
# ---------------------------------------------------------------------------
task_detect_patterns = Task(
    description=(
        "Identify ALL recurring incident patterns in FinServe's Q1 2026 incident data.\n\n"
        "STEP 1 (MANDATORY FIRST ACTION): Call the analyze_all_patterns tool with no arguments.\n"
        "This tool reads all three CSV files and returns a comprehensive pre-digested analysis\n"
        "of every pattern cluster. It does all the heavy lifting for you.\n\n"
        "STEP 2: Review the output from analyze_all_patterns. It will show you the top\n"
        "pattern clusters, each with:\n"
        "- Service name and error code\n"
        "- Incident count and IDs\n"
        "- Temporal signals (day-of-week clustering, month-start clustering)\n"
        "- CMDB context (tier, infrastructure, notes)\n"
        "- Correlated changes\n"
        "- Resolution note keywords\n\n"
        "STEP 3: List ALL patterns that have 3 or more incidents. There should be at least\n"
        "4 distinct patterns. For each one, summarize:\n"
        "- Pattern ID, service, error code, incident count\n"
        "- Key temporal signal (e.g., 'clusters on Tuesdays' or 'clusters at month start')\n"
        "- Key CMDB note (e.g., 'batch reconciliation', 'shared connection pool')\n"
        "- Related changes\n\n"
        "DO NOT stop at 2 patterns. Report ALL patterns with 3+ incidents."
    ),
    agent=trend_analyst,
    expected_output=(
        "A structured report listing ALL candidate pattern clusters (expect 4). For each:\n"
        "- Pattern ID (PAT-001 through PAT-004)\n"
        "- Service name, error code, incident count, incident IDs\n"
        "- Priority distribution\n"
        "- Temporal signals\n"
        "- CMDB notes summary\n"
        "- Related changes\n"
        "- Initial hypothesis"
    ),
)


# ---------------------------------------------------------------------------
# Task 2: Problem Logging & Classification — CMDB Correlation
# Agent: CMDB Correlator
# Context: Receives pattern clusters from Task 1
# ---------------------------------------------------------------------------
task_correlate_cmdb = Task(
    description=(
        "Enrich EACH pattern from the Trend Analyst with CMDB and change log data.\n"
        "The Trend Analyst identified up to 4 patterns. Process ALL of them.\n\n"
        "For EACH pattern:\n"
        "1. Use query_cmdb with ci_name set to the service name to get CI details.\n"
        "2. Use query_changes with ci_id to find all changes for that CI.\n"
        "3. Use map_dependencies with ci_id to find shared infrastructure.\n"
        "4. Use create_problem_record with the pattern details to formally log it.\n\n"
        "Create one Problem Record per pattern. Use these fields for create_problem_record:\n"
        "- pattern_id: the pattern ID from the Trend Analyst (e.g., PAT-001)\n"
        "- title: a descriptive title for the problem\n"
        "- severity: Critical, High, Medium, or Low\n"
        "- affected_cis: the CI ID\n"
        "- linked_incidents: comma-separated incident IDs\n"
        "- description: summary with CMDB evidence\n\n"
        "IMPORTANT: You MUST create a Problem Record for every pattern. Do not skip any."
    ),
    agent=cmdb_correlator,
    context=[task_detect_patterns],
    expected_output=(
        "An enriched report with Problem Records. For each pattern:\n"
        "- Problem Record with problem_id, title, severity, linked incidents\n"
        "- CMDB details: tier, infrastructure, notes\n"
        "- Related changes and their risk levels\n"
        "- Shared infrastructure findings"
    ),
)


# ---------------------------------------------------------------------------
# Task 3: Root Cause Analysis
# Agent: Root Cause Investigator
# Context: Receives pattern data + CMDB enrichment from Tasks 1 & 2
# ---------------------------------------------------------------------------
task_root_cause = Task(
    description=(
        "Determine the root cause for EACH problem identified by the CMDB Correlator.\n\n"
        "For EACH problem:\n"
        "1. Use five_whys_analysis with service name and error code to get a framework.\n"
        "2. Use cross_reference with the service name to get combined data.\n"
        "3. Write a specific root cause statement backed by evidence.\n\n"
        "Your root cause must reference concrete evidence:\n"
        "- Specific change IDs (e.g., CHG0042) and what they did\n"
        "- CMDB notes (e.g., 'batch reconciliation runs Tue 22:00 UTC')\n"
        "- Resolution note patterns (e.g., 'same restart workaround every time')\n"
        "- Shared infrastructure details (e.g., 'shared db-ledger-prod pool')\n\n"
        "IMPORTANT: Produce a root cause for ALL problems. Do not skip any."
    ),
    agent=root_cause_investigator,
    context=[task_detect_patterns, task_correlate_cmdb],
    expected_output=(
        "A root cause report for each problem containing:\n"
        "- Problem ID\n"
        "- Five Whys chain with evidence\n"
        "- Root cause statement (specific, causal, evidence-backed)\n"
        "- Key evidence references (change IDs, CMDB notes)"
    ),
)


# ---------------------------------------------------------------------------
# Task 4: Known Error Documentation
# Agent: Known Error Author
# Context: Receives root cause analysis from Tasks 1, 2 & 3
# ---------------------------------------------------------------------------
task_known_errors = Task(
    description=(
        "Create a Known Error Record for EACH root cause from the Root Cause Investigator.\n\n"
        "For EACH root cause, call create_known_error with these fields:\n"
        "- problem_id: the Problem Record ID (e.g., PRB-001)\n"
        "- title: descriptive title of the Known Error\n"
        "- root_cause: the confirmed root cause statement\n"
        "- workaround: step-by-step instructions for L1 support (be specific)\n"
        "- permanent_fix: technical description of the permanent solution\n"
        "- affected_ci: the CI ID (e.g., CI-1042)\n"
        "- linked_incidents: comma-separated incident IDs\n\n"
        "Each call to create_known_error saves a JSON file to the output/ directory.\n"
        "IMPORTANT: Create one Known Error per root cause. Do not skip any."
    ),
    agent=known_error_author,
    context=[task_detect_patterns, task_correlate_cmdb, task_root_cause],
    expected_output=(
        "Known Error Records saved to output/ directory (one JSON file per Known Error).\n"
        "Each record contains: ke_id, problem_id, title, root_cause, workaround,\n"
        "permanent_fix, affected_ci, linked_incidents."
    ),
)


# ---------------------------------------------------------------------------
# Task 5: Change Proposals (RFCs)
# Agent: Change Proposer
# Context: Receives all prior task outputs
# ---------------------------------------------------------------------------
task_change_proposals = Task(
    description=(
        "Create an RFC for EACH Known Error's permanent fix.\n\n"
        "For EACH Known Error, call create_rfc with these fields:\n"
        "- known_error_id: the Known Error ID (e.g., KE-001)\n"
        "- title: descriptive title for the change\n"
        "- description: what will be changed and why\n"
        "- risk_level: Low, Medium, High, or Critical\n"
        "- test_plan: pre-change, change, and post-change validation steps\n"
        "- rollback_plan: how to revert if the change fails\n"
        "- implementation_schedule: when to implement (avoid peak hours)\n\n"
        "Each call to create_rfc saves a JSON file to the output/ directory.\n"
        "IMPORTANT: Create one RFC per Known Error. Do not skip any."
    ),
    agent=change_proposer,
    context=[task_detect_patterns, task_correlate_cmdb, task_root_cause, task_known_errors],
    expected_output=(
        "RFCs saved to output/ directory (one JSON file per RFC).\n"
        "Each record contains: rfc_id, known_error_id, title, change_type,\n"
        "description, risk_assessment, test_plan, rollback_plan, implementation_schedule."
    ),
)

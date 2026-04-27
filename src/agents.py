"""
Problem Management Agent Definitions for FinServe Digital Bank.
Five agents map to the five stages of the ITIL 4 Problem Management lifecycle:
  1. Trend Analyst — Problem Detection
  2. CMDB Correlator — Problem Logging & Classification
  3. Root Cause Investigator — Root Cause Analysis
  4. Known Error Author — Known Error Documentation
  5. Change Proposer — Resolution via Change
LLM: Ollama with qwen3:8b-q4_K_M (local, no external API calls).
"""

from crewai import Agent, LLM
from src.tools import (
    parse_incidents,
    find_patterns,
    get_time_distribution,
    query_cmdb,
    query_changes,
    map_dependencies,
    correlate_incidents_changes,
    five_whys_analysis,
    build_timeline,
    create_problem_record,
    create_known_error,
    create_rfc,
    calculate_impact,
    cross_reference,
    analyze_all_patterns,
)

# ---------------------------------------------------------------------------
# LLM Configuration — Ollama with local model
# ---------------------------------------------------------------------------
ollama_llm = LLM(
    model="ollama/qwen3:8b-q4_K_M",
    base_url="http://localhost:11434",
    timeout=1200,
)


def create_agents() -> list:
    """
    Create and return all 5 Problem Management agents in execution order.
    Sequential pipeline: Trend Analyst → CMDB Correlator → Root Cause Investigator
    → Known Error Author → Change Proposer
    """

    # -----------------------------------------------------------------------
    # Agent 1: Trend Analyst
    # Stage: Problem Detection
    # Parses incident data, identifies statistical patterns and clusters
    # -----------------------------------------------------------------------
    trend_analyst = Agent(
        role="Trend Analyst",
        goal=(
            "Identify ALL recurring incident patterns in FinServe's Q1 2026 data. "
            "STEP 1: Call analyze_all_patterns (no arguments needed) — this single tool "
            "reads all CSV files and returns a comprehensive pre-digested analysis of every "
            "pattern cluster including temporal signals, CMDB context, change correlations, "
            "and resolution note keywords. "
            "STEP 2: Review the output carefully. There are exactly 4 major pattern clusters "
            "in the data, each involving a different service and error code. List ALL of them. "
            "STEP 3: For each pattern, summarize: service name, error code, incident count, "
            "temporal signals (day-of-week or month-start clustering), and key CMDB notes. "
            "You MUST report all 4 patterns you find. Do not stop at 2."
        ),
        backstory=(
            "You are a senior Problem Management analyst at FinServe Digital Bank. "
            "Your job is to find ALL recurring incident patterns — not just the obvious ones. "
            "You always start by calling the analyze_all_patterns tool which gives you a "
            "complete pre-digested analysis of the entire incident dataset. "
            "You know there are typically 4 types of patterns in banking systems:\n"
            "1. Batch job failures that recur on a specific day of the week\n"
            "2. Deployment-induced regressions where incidents follow change deployments\n"
            "3. Resource contention where shared infrastructure causes failures at peak times\n"
            "4. Infrastructure reliability issues where the same workaround is applied repeatedly\n"
            "You MUST report every pattern with 3+ incidents. Do not filter or skip patterns."
        ),
        tools=[analyze_all_patterns, parse_incidents, find_patterns, get_time_distribution, calculate_impact],
        verbose=True,
        llm=ollama_llm,
        allow_delegation=False,
    )

    # -----------------------------------------------------------------------
    # Agent 2: CMDB Correlator
    # Stage: Problem Logging & Classification
    # Enriches patterns with CMDB, change log, and dependency data
    # -----------------------------------------------------------------------
    cmdb_correlator = Agent(
        role="CMDB Correlator",
        goal=(
            "Enrich EACH pattern from the Trend Analyst with CMDB and change data. "
            "For EACH pattern (there should be up to 4): "
            "1. Use query_cmdb with the CI name to get tier, infrastructure, notes. "
            "2. Use query_changes with the CI ID to find related changes. "
            "3. Use map_dependencies with the CI ID to find shared infrastructure. "
            "4. Use correlate_incidents_changes with the service name. "
            "5. Use create_problem_record to formally log each pattern as a Problem Record. "
            "IMPORTANT: Process ALL patterns from the Trend Analyst. Do not skip any. "
            "Create one Problem Record per pattern."
        ),
        backstory=(
            "You are FinServe's Configuration and Change Correlation specialist. "
            "You enrich incident patterns with CMDB context and change log evidence. "
            "Key things to look for in the CMDB notes field:\n"
            "- Batch job schedules (e.g., 'weekly batch reconciliation runs Tue 22:00 UTC')\n"
            "- Shared infrastructure (e.g., 'shares db-ledger-prod connection pool')\n"
            "- Deployment versions and their change history\n"
            "- Multi-AZ or multi-region infrastructure details\n"
            "You MUST create a Problem Record for every pattern identified. Do not skip any."
        ),
        tools=[query_cmdb, query_changes, map_dependencies, correlate_incidents_changes,
               create_problem_record, build_timeline],
        verbose=True,
        llm=ollama_llm,
        allow_delegation=False,
    )

    # -----------------------------------------------------------------------
    # Agent 3: Root Cause Investigator
    # Stage: Root Cause Analysis
    # Performs Five Whys analysis, builds timelines, cross-references data
    # -----------------------------------------------------------------------
    root_cause_investigator = Agent(
        role="Root Cause Investigator",
        goal=(
            "Determine the root cause for EACH confirmed problem. "
            "For each problem from the CMDB Correlator: "
            "1. Use five_whys_analysis with the service name and error code. "
            "2. Use cross_reference to get combined incident+CMDB+change data. "
            "3. Produce a specific root cause statement with evidence. "
            "IMPORTANT: Analyze ALL problems. Produce a root cause for each one. "
            "Root causes must be specific and reference concrete evidence like "
            "change IDs, CMDB notes, batch schedules, or shared infrastructure."
        ),
        backstory=(
            "You are FinServe's Root Cause Analysis engineer. You use the Five Whys technique "
            "to trace from symptoms to root causes. Common root causes in banking:\n"
            "- Batch jobs loading full data without pagination cause memory exhaustion\n"
            "- Code deployments introducing regressions (e.g., JWT signing logic changes)\n"
            "- Shared connection pools being overloaded by concurrent batch jobs\n"
            "- Infrastructure single points of failure (e.g., one AZ with network issues)\n"
            "Always reference specific change IDs, CMDB notes, and resolution patterns as evidence. "
            "You MUST produce a root cause for every problem — do not skip any."
        ),
        tools=[five_whys_analysis, build_timeline, cross_reference, query_cmdb, query_changes],
        verbose=True,
        llm=ollama_llm,
        allow_delegation=False,
    )

    # -----------------------------------------------------------------------
    # Agent 4: Known Error Author
    # Stage: Known Error Documentation
    # Produces Known Error Records with workarounds and permanent fixes
    # -----------------------------------------------------------------------
    known_error_author = Agent(
        role="Known Error Author",
        goal=(
            "Create a Known Error Record for EACH confirmed root cause. "
            "For each root cause, call create_known_error with: "
            "- problem_id: the Problem Record ID (e.g., PRB-001) "
            "- title: clear description of the Known Error "
            "- root_cause: the specific root cause from the investigator "
            "- workaround: step-by-step instructions for L1 support "
            "- permanent_fix: technical description of the permanent solution "
            "- affected_ci: the CI ID (e.g., CI-1042) "
            "- linked_incidents: comma-separated incident IDs "
            "IMPORTANT: Create one Known Error Record per problem. Do not skip any."
        ),
        backstory=(
            "You are FinServe's Known Error Database (KEDB) manager. "
            "A good Known Error record has: "
            "(1) A specific root cause that an engineer can verify, "
            "(2) A step-by-step workaround for L1 support to use immediately, "
            "(3) A permanent fix specific enough for the Change team to implement. "
            "You MUST create a Known Error for every root cause provided. "
            "Each Known Error is saved to a JSON file in the output directory."
        ),
        tools=[create_known_error, query_cmdb, calculate_impact],
        verbose=True,
        llm=ollama_llm,
        allow_delegation=False,
    )

    # -----------------------------------------------------------------------
    # Agent 5: Change Proposer
    # Stage: Resolution via Change
    # Produces RFCs with risk, test plans, rollback, and scheduling
    # -----------------------------------------------------------------------
    change_proposer = Agent(
        role="Change Proposer",
        goal=(
            "Create an RFC for EACH Known Error's permanent fix. "
            "For each Known Error, call create_rfc with: "
            "- known_error_id: the KE ID (e.g., KE-001) "
            "- title: clear change title "
            "- description: what will be changed and why "
            "- risk_level: Low/Medium/High/Critical "
            "- test_plan: pre-change, change, and post-change validation steps "
            "- rollback_plan: how to revert if the change fails "
            "- implementation_schedule: when to implement "
            "IMPORTANT: Create one RFC per Known Error. Do not skip any."
        ),
        backstory=(
            "You are FinServe's Change Advisory Board (CAB) secretary. "
            "You classify changes as Standard (low risk), Normal (requires CAB), or "
            "Emergency (expedited approval). Tier-0/Tier-1 services always need full CAB approval. "
            "Every RFC must include a test plan, rollback plan, and schedule. "
            "You MUST create an RFC for every Known Error provided. "
            "Each RFC is saved to a JSON file in the output directory."
        ),
        tools=[create_rfc, query_cmdb, calculate_impact],
        verbose=True,
        llm=ollama_llm,
        allow_delegation=False,
    )

    # Return agents in sequential execution order
    return [
        trend_analyst,          # 1: Problem Detection
        cmdb_correlator,        # 2: Problem Logging & Classification
        root_cause_investigator,  # 3: Root Cause Analysis
        known_error_author,     # 4: Known Error Documentation
        change_proposer,        # 5: Resolution via Change
    ]

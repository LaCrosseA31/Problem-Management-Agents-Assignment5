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
        "Analyze FinServe Digital Bank's Q1 2026 incident data to identify recurring patterns "
        "that indicate underlying problems requiring investigation.\n\n"
        "Execute the following steps:\n"
        "1. Use parse_incidents (with no filters) to load ALL incident records from the CSV file.\n"
        "2. Use find_patterns with min_frequency=3 to identify clusters of incidents that share "
        "   the same service, subcategory, and/or error code.\n"
        "3. For each identified pattern cluster, use get_time_distribution to check for "
        "   temporal patterns:\n"
        "   - Day-of-week clustering (e.g., incidents always on Tuesdays)\n"
        "   - Hour-of-day clustering (e.g., incidents always at night)\n"
        "   - Month-start clustering (e.g., incidents on days 1-3)\n"
        "4. Use calculate_impact to assess the severity of each pattern.\n\n"
        "Focus on finding patterns where:\n"
        "- The same service + error_code appears 3+ times\n"
        "- Incidents cluster on specific days of the week or time windows\n"
        "- Multiple P1-Critical incidents share a common cause\n"
        "- Resolution notes suggest the same fix is being applied repeatedly\n\n"
        "Provide statistical evidence for every pattern you identify."
    ),
    agent=trend_analyst,
    expected_output=(
        "A structured report containing 2-4 candidate pattern clusters. For each pattern:\n"
        "- Pattern ID (e.g., PAT-001)\n"
        "- Service and error code\n"
        "- Number of incidents and their IDs\n"
        "- Priority distribution (how many P1, P2, etc.)\n"
        "- Temporal analysis: day-of-week distribution, hour clustering, any periodicity\n"
        "- Statistical evidence: frequency, recurrence interval, impact metrics\n"
        "- Sample incident descriptions and resolution notes\n"
        "- Initial hypothesis about what might be causing this pattern"
    ),
)


# ---------------------------------------------------------------------------
# Task 2: Problem Logging & Classification — CMDB Correlation
# Agent: CMDB Correlator
# Context: Receives pattern clusters from Task 1
# ---------------------------------------------------------------------------
task_correlate_cmdb = Task(
    description=(
        "Take the candidate patterns identified by the Trend Analyst and enrich each one "
        "with data from the CMDB and change log.\n\n"
        "For EACH pattern identified in the previous task:\n"
        "1. Use query_cmdb to look up the affected CI by name or ID. Get the full record "
        "   including tier classification, infrastructure, and operational notes.\n"
        "2. Use query_changes to find ALL changes implemented on the affected CI. Pay special "
        "   attention to changes that were implemented shortly before incidents started.\n"
        "3. Use map_dependencies to identify:\n"
        "   - Upstream dependencies (what does this service depend on?)\n"
        "   - Downstream dependencies (what services depend on this one?)\n"
        "   - Shared infrastructure (do multiple CIs share the same database, connection pool, etc.?)\n"
        "4. Use correlate_incidents_changes with a 72-hour window to find changes that "
        "   occurred before each cluster of incidents.\n"
        "5. Use build_timeline to see how incidents and changes interleave over time.\n"
        "6. Create a formal Problem Record for each pattern using create_problem_record.\n\n"
        "Look for:\n"
        "- Changes that introduced regressions (incidents started after a deployment)\n"
        "- Shared infrastructure causing cascading issues (e.g., shared DB connection pool)\n"
        "- Infrastructure notes that explain why certain issues recur\n"
        "- Dependency chains that amplify the impact of a single CI failure"
    ),
    agent=cmdb_correlator,
    context=[task_detect_patterns],
    expected_output=(
        "An enriched pattern report with CMDB and change correlation data. For each pattern:\n"
        "- Problem Record (problem_id, title, severity, affected CIs, linked incidents)\n"
        "- CMDB CI details: tier, owner, infrastructure, version, notes\n"
        "- Dependency map: upstream CIs, downstream CIs, shared infrastructure\n"
        "- Correlated changes: which changes were deployed before incidents started\n"
        "- Timeline showing interleaving of changes and incidents\n"
        "- Classification: severity level and investigation priority\n"
        "- Key finding: what the CMDB and change data reveals about this pattern"
    ),
)


# ---------------------------------------------------------------------------
# Task 3: Root Cause Analysis
# Agent: Root Cause Investigator
# Context: Receives pattern data + CMDB enrichment from Tasks 1 & 2
# ---------------------------------------------------------------------------
task_root_cause = Task(
    description=(
        "Determine the root cause for each confirmed problem using structured analysis "
        "techniques. Build on the pattern data and CMDB correlations from previous tasks.\n\n"
        "For EACH problem record:\n"
        "1. Use five_whys_analysis to get a structured Five Whys framework populated with "
        "   CMDB evidence. Complete the full Five Whys chain — each 'why' must be supported "
        "   by evidence from the data.\n"
        "2. Use build_timeline to reconstruct the chronological sequence of events "
        "   (changes → incidents → resolutions) for the affected service.\n"
        "3. Use cross_reference to combine incident data, CMDB records, and change logs "
        "   into a single comprehensive view.\n\n"
        "Your root cause analysis must:\n"
        "- Be specific and causal (not vague like 'service was unreliable')\n"
        "- Reference specific changes, CMDB notes, or infrastructure details as evidence\n"
        "- Explain the complete causal chain from root cause to visible symptoms\n"
        "- Distinguish between the root cause and contributing factors\n\n"
        "Example of a good root cause:\n"
        "'The payment-gateway weekly batch reconciliation job (configured by CHG0042) loads "
        "full transaction data into memory without pagination. On Tuesdays at 22:00 UTC when "
        "the job runs, heap memory spikes cause OutOfMemoryError (ERR-5012), crashing the "
        "service. The change was classified as Standard/Low risk and skipped performance review.'\n\n"
        "Example of a bad root cause:\n"
        "'The payment gateway keeps crashing.' (too vague, no causal chain, no evidence)"
    ),
    agent=root_cause_investigator,
    context=[task_detect_patterns, task_correlate_cmdb],
    expected_output=(
        "A root cause analysis report for each problem. For each:\n"
        "- Problem ID reference\n"
        "- Five Whys chain (5 levels, each supported by evidence)\n"
        "- Root cause statement: specific, causal, evidence-backed\n"
        "- Contributing factors (secondary causes)\n"
        "- Evidence summary: which CMDB notes, change records, resolution notes support this\n"
        "- Causal chain: root cause → mechanism → symptom → incident\n"
        "- Confidence level: High/Medium/Low with justification"
    ),
)


# ---------------------------------------------------------------------------
# Task 4: Known Error Documentation
# Agent: Known Error Author
# Context: Receives root cause analysis from Tasks 1, 2 & 3
# ---------------------------------------------------------------------------
task_known_errors = Task(
    description=(
        "Create Known Error Records for each confirmed root cause. These records will be "
        "stored in the Known Error Database (KEDB) and used by the Service Desk.\n\n"
        "For EACH confirmed root cause from the Root Cause Investigator:\n"
        "1. Use create_known_error to produce a formal Known Error Record with:\n"
        "   - ke_id: Unique Known Error identifier\n"
        "   - problem_id: Link to the Problem Record\n"
        "   - root_cause: The confirmed root cause (specific and technical)\n"
        "   - workaround: Step-by-step instructions for incident responders to resolve "
        "     the issue quickly when it recurs. Must be actionable by L1 support.\n"
        "   - permanent_fix: Technical description of the change needed to eliminate "
        "     the root cause permanently\n"
        "   - affected_ci: Primary CI ID affected\n"
        "   - linked_incidents: All incident IDs related to this Known Error\n"
        "2. Use query_cmdb to confirm the CI details for accuracy.\n"
        "3. Use calculate_impact to document the business impact of each Known Error.\n\n"
        "The Known Error Record will be saved to a JSON file in the output/ directory.\n\n"
        "Workaround example (good):\n"
        "'1. SSH to payment-gateway pods. 2. Check heap usage with jstat. "
        "3. If heap >85%, restart pods with kubectl rollout restart. "
        "4. Monitor for 10 minutes to confirm memory stabilizes.'\n\n"
        "Workaround example (bad):\n"
        "'Restart the service.' (too vague, no specifics)"
    ),
    agent=known_error_author,
    context=[task_detect_patterns, task_correlate_cmdb, task_root_cause],
    expected_output=(
        "Known Error Records saved to output/ directory. For each Known Error:\n"
        "- ke_id: Unique identifier (e.g., KE-001)\n"
        "- problem_id: Link to Problem Record\n"
        "- title: Clear description of the Known Error\n"
        "- root_cause: Specific, confirmed root cause\n"
        "- workaround: Step-by-step instructions for L1 support (actionable)\n"
        "- permanent_fix: Technical change needed to eliminate the root cause\n"
        "- affected_ci: CI ID and name\n"
        "- linked_incidents: All related incident IDs\n"
        "- business_impact: Incident count, downtime hours, priority distribution"
    ),
)


# ---------------------------------------------------------------------------
# Task 5: Change Proposals (RFCs)
# Agent: Change Proposer
# Context: Receives all prior task outputs
# ---------------------------------------------------------------------------
task_change_proposals = Task(
    description=(
        "Produce formal Requests for Change (RFCs) for each Known Error's permanent fix. "
        "These RFCs will go through the Change Advisory Board (CAB) for approval.\n\n"
        "For EACH Known Error from the previous task:\n"
        "1. Use create_rfc to generate a formal RFC with:\n"
        "   - title: Clear change title\n"
        "   - description: Detailed description of what will be changed and why\n"
        "   - risk_level: Low/Medium/High/Critical with justification based on "
        "     the affected CI tier and potential blast radius\n"
        "   - test_plan: Specific tests to validate the change works:\n"
        "     * Pre-change validation (confirm current state)\n"
        "     * Change validation (confirm change applied correctly)\n"
        "     * Post-change monitoring (confirm no regressions)\n"
        "   - rollback_plan: Step-by-step procedure to revert if the change fails:\n"
        "     * Trigger criteria (when to roll back)\n"
        "     * Rollback steps (specific commands/actions)\n"
        "     * Validation (how to confirm rollback succeeded)\n"
        "   - implementation_schedule: When to implement, considering:\n"
        "     * Maintenance windows (avoid peak hours)\n"
        "     * Dependencies on other changes\n"
        "     * Change freeze periods\n"
        "2. Use query_cmdb to verify the CI tier and determine required approval level.\n"
        "3. Use calculate_impact to justify the business case for each change.\n\n"
        "The RFC will be saved to a JSON file in the output/ directory.\n\n"
        "Classify each change as:\n"
        "- Standard: Pre-approved, low risk, routine\n"
        "- Normal: Requires CAB approval, moderate risk\n"
        "- Emergency: Expedited approval for critical production issues"
    ),
    agent=change_proposer,
    context=[task_detect_patterns, task_correlate_cmdb, task_root_cause, task_known_errors],
    expected_output=(
        "RFCs saved to output/ directory. For each RFC:\n"
        "- rfc_id: Unique identifier (e.g., RFC-001)\n"
        "- known_error_id: Link to Known Error Record\n"
        "- title: Clear change title\n"
        "- change_type: Standard/Normal/Emergency\n"
        "- description: What will be changed and why\n"
        "- risk_assessment: Risk level with specific failure scenarios\n"
        "- test_plan: Pre-change, change, and post-change validation steps\n"
        "- rollback_plan: Trigger criteria, rollback steps, validation\n"
        "- implementation_schedule: Proposed timing with justification\n"
        "- approval_required_from: CAB members, service owner, technical lead\n"
        "- business_justification: Impact data supporting the change"
    ),
)

# Problem Management Agent System — Summary

## Overview

This project implements an agent-driven Problem Management system for FinServe Digital Bank using CrewAI with Ollama. Five specialized agents operate in a sequential pipeline that transforms raw Q1 2026 incident data into structured Problem Records, Known Error Records, and Requests for Change (RFCs), following the ITIL 4 Problem Management lifecycle.

## Patterns Discovered by the Agent System

The agent pipeline is designed to discover the following patterns hidden in the 141-record incident dataset:

### Pattern 1: Payment Gateway Memory Exhaustion (Weekly Batch Reconciliation)
- **Service:** payment-gateway (CI-1042)
- **Error Code:** ERR-5012
- **Incidents:** INC01001–INC01008 (8 incidents, most P1-Critical)
- **Temporal Pattern:** Incidents cluster on Tuesday evenings (22:00 UTC), aligning with the weekly batch reconciliation job configured by CHG0042.
- **Root Cause:** The batch reconciliation job loads full transaction data into memory without pagination or streaming. This causes OutOfMemoryError (heap exhaustion) every Tuesday when the job runs. CHG0042 was classified as Standard/Low risk and skipped performance review, so no load testing was performed.
- **CMDB Evidence:** CI-1042 notes confirm "weekly batch reconciliation runs Tue 22:00 UTC (CHG0042)."

### Pattern 2: Auth Service JWT/Token Validation Failures (Version Regressions)
- **Service:** auth-service (CI-1015)
- **Error Code:** ERR-4401
- **Incidents:** INC01009–INC01018 (10 incidents, mix of P1 and P3)
- **Temporal Pattern:** Incidents cluster after each auth-service deployment (CHG0078, CHG0079, CHG0091, CHG0095, CHG0102).
- **Root Cause:** Multiple auth-service version deployments (v2.14.0 through v2.14.3) introduced JWT signing logic regressions. Each deployment caused token validation failures that required hotfixes or rollbacks. The v2.14.0 deployment (CHG0078) changed JWT signing logic, introducing a regression that persisted across subsequent releases.
- **CMDB Evidence:** Change log shows 5 auth-service changes in Q1, each followed by authentication incidents.

### Pattern 3: Account Ledger Connection Pool Exhaustion (Month-End Batch Contention)
- **Service:** account-ledger (CI-1031)
- **Error Code:** ERR-3200
- **Incidents:** INC01019–INC01024 (6 incidents, all P1-Critical)
- **Temporal Pattern:** Incidents cluster on the 1st–3rd of each month, aligning with month-end batch processing.
- **Root Cause:** The reporting-engine (CI-1044) shares the db-ledger-prod connection pool with account-ledger. CHG0048 increased reporting query parallelism from 10 to 25 threads, consuming connections that account-ledger needs. During month-end batch runs (days 1-3), the shared pool is exhausted, blocking customer transactions.
- **CMDB Evidence:** CI-1044 notes confirm "shares db-ledger-prod connection pool with account-ledger" and CI-1031 notes confirm "max_pool_size=200."

### Pattern 4: Mobile API AZ-c Network Failures (Infrastructure Single Point of Failure)
- **Service:** mobile-api (CI-1088)
- **Error Code:** ERR-5040
- **Incidents:** INC01025–INC01031 (7 incidents, P2-High and P3-Medium)
- **Temporal Pattern:** Recurring sporadically but consistently affecting us-west-2 AZ-c only.
- **Root Cause:** The mobile-api multi-region deployment (CHG0085) deployed across AZ-a, AZ-b, and AZ-c in us-west-2, but AZ-c has a persistent network reliability issue. Incident resolution notes consistently show "shifted pods to AZ-a and AZ-b" or "rerouted away from AZ-c" — the same workaround every time, indicating no permanent fix has been applied.
- **CMDB Evidence:** CI-1088 infra shows "EKS us-east-1 + us-west-2 (multi-region)" with AZ-a, AZ-b, AZ-c.

## Tool Design and How It Enabled Discovery

The tool design follows a "real data processing" philosophy where tools read from actual CSV files at runtime rather than returning hardcoded data. This is the key upgrade from the BCM simulation project.

### File I/O Tools (CSV Reading — 7 tools)
1. **parse_incidents** — Reads `finserve_incidents_q1_2026.csv` with optional filters (service, priority, error code, date range). This is the entry point for all pattern analysis.
2. **find_patterns** — Reads the incident CSV and groups records by (service, subcategory, error_code) to surface clusters above a configurable frequency threshold. Uses three grouping strategies: exact match, service+error, and service+subcategory.
3. **get_time_distribution** — Reads the incident CSV and computes day-of-week, hour-of-day, and day-of-month distributions. Automatically flags temporal anomalies like Tuesday clustering or month-start clustering.
4. **query_cmdb** — Reads `finserve_cmdb.csv` to look up CI details including tier, infrastructure, dependencies, and operational notes. The notes field contains critical clues (batch schedules, shared pools).
5. **query_changes** — Reads `finserve_changes.csv` to find changes by CI or date range. Essential for correlating deployments with incident spikes.
6. **correlate_incidents_changes** — Reads both incident and change CSVs, finding changes within a configurable window before each incident. This is the primary tool for discovering change-induced patterns.
7. **build_timeline** — Reads both CSVs and constructs a chronological interleaving of incidents and changes, making causal sequences visible.

### File Output Tools (2 tools)
8. **create_known_error** — Writes Known Error Records as JSON files to the output/ directory.
9. **create_rfc** — Writes RFC documents as JSON files to the output/ directory.

### Analysis Tools (5 tools)
10. **map_dependencies** — Reads CMDB and walks the dependency graph to find upstream/downstream CIs and shared infrastructure.
11. **five_whys_analysis** — Reads all three CSVs to populate a Five Whys framework with evidence, guiding the Root Cause Investigator agent.
12. **cross_reference** — Combines incident, CMDB, and change data into a single comprehensive view for a service.
13. **create_problem_record** — Generates formal Problem Records with unique IDs, severity, and linked incidents.
14. **calculate_impact** — Computes business impact metrics from incident data (downtime hours, priority distribution, affected teams).

### Why This Design Works
The tools are designed so that agents can discover patterns autonomously:
- **find_patterns** surfaces clusters that humans might miss in 141 records
- **get_time_distribution** reveals temporal patterns (Tuesday evenings, month-start) that are invisible in raw data
- **correlate_incidents_changes** connects deployments to incident spikes
- **map_dependencies** reveals shared infrastructure (the connection pool issue)
- **CMDB notes** contain critical context (batch schedules, pool sizes) that explain why patterns exist

Each tool does real computation on CSV data rather than returning hardcoded results, ensuring the agents work with the actual data and produce evidence-based findings.

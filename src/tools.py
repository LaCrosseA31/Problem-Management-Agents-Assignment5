"""
Problem Management Tools for FinServe Digital Bank
Tools parse CSV data, query CMDB, correlate events, and produce structured outputs.
At least 3 tools perform real file I/O; tools use Pydantic models for input validation.
"""

import csv
import json
import os
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Optional

from crewai.tools import BaseTool
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Data file paths — set via environment or default to ./data/
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.environ.get("FINSERVE_DATA_DIR", os.path.join(BASE_DIR, "data"))
OUTPUT_DIR = os.environ.get("FINSERVE_OUTPUT_DIR", os.path.join(BASE_DIR, "output"))

INCIDENTS_CSV = os.path.join(DATA_DIR, "finserve_incidents_q1_2026.csv")
CMDB_CSV = os.path.join(DATA_DIR, "finserve_cmdb.csv")
CHANGES_CSV = os.path.join(DATA_DIR, "finserve_changes.csv")


def _load_csv(filepath: str) -> list[dict]:
    """Load a CSV file and return a list of dicts."""
    with open(filepath, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def _parse_dt(s: str) -> Optional[datetime]:
    """Parse a datetime string, returning None on failure."""
    try:
        return datetime.strptime(s.strip(), "%Y-%m-%d %H:%M")
    except (ValueError, AttributeError):
        return None


# ========================== Pydantic Input Models ==========================

class ParseIncidentsInput(BaseModel):
    service: Optional[str] = Field(None, description="Filter by service name (e.g. 'payment-gateway')")
    priority: Optional[str] = Field(None, description="Filter by priority (e.g. 'P1-Critical')")
    error_code: Optional[str] = Field(None, description="Filter by error code (e.g. 'ERR-5012')")
    date_from: Optional[str] = Field(None, description="Filter incidents from this date (YYYY-MM-DD)")
    date_to: Optional[str] = Field(None, description="Filter incidents up to this date (YYYY-MM-DD)")

class FindPatternsInput(BaseModel):
    min_frequency: int = Field(3, description="Minimum number of incidents to consider a cluster a pattern")

class TimeDistributionInput(BaseModel):
    service: Optional[str] = Field(None, description="Filter by service name")
    error_code: Optional[str] = Field(None, description="Filter by error code")
    subcategory: Optional[str] = Field(None, description="Filter by subcategory")

class QueryCmdbInput(BaseModel):
    ci_id: Optional[str] = Field(None, description="Configuration Item ID (e.g. 'CI-1042')")
    ci_name: Optional[str] = Field(None, description="CI name / service name (e.g. 'payment-gateway')")

class QueryChangesInput(BaseModel):
    ci_id: Optional[str] = Field(None, description="Filter changes by CI ID")
    date_from: Optional[str] = Field(None, description="Start date (YYYY-MM-DD)")
    date_to: Optional[str] = Field(None, description="End date (YYYY-MM-DD)")

class MapDependenciesInput(BaseModel):
    ci_id: str = Field(..., description="CI ID to map dependencies for (e.g. 'CI-1042')")

class CorrelateIncidentsChangesInput(BaseModel):
    service: Optional[str] = Field(None, description="Service name to correlate")
    ci_id: Optional[str] = Field(None, description="CI ID to correlate")
    window_hours: int = Field(72, description="Hours before incident to search for related changes")

class FiveWhysInput(BaseModel):
    pattern_description: str = Field(..., description="Description of the pattern to analyze")
    service: str = Field(..., description="Service name affected")
    error_code: Optional[str] = Field(None, description="Error code associated with pattern")
    ci_id: Optional[str] = Field(None, description="CI ID for CMDB cross-reference")

class BuildTimelineInput(BaseModel):
    service: Optional[str] = Field(None, description="Service name to build timeline for")
    ci_id: Optional[str] = Field(None, description="CI ID to build timeline for")

class CreateProblemRecordInput(BaseModel):
    pattern_id: str = Field(..., description="Unique pattern identifier (e.g. 'PAT-001')")
    title: str = Field(..., description="Problem title")
    severity: str = Field(..., description="Severity: Critical, High, Medium, Low")
    affected_cis: str = Field(..., description="Comma-separated CI IDs")
    linked_incidents: str = Field(..., description="Comma-separated incident IDs")
    description: str = Field(..., description="Problem description with evidence")

class CreateKnownErrorInput(BaseModel):
    problem_id: str = Field(..., description="Related problem record ID")
    title: str = Field(..., description="Known error title")
    root_cause: str = Field(..., description="Confirmed root cause")
    workaround: str = Field(..., description="Workaround for incident responders")
    permanent_fix: str = Field(..., description="Permanent fix description")
    affected_ci: str = Field(..., description="Primary affected CI ID")
    linked_incidents: str = Field(..., description="Comma-separated incident IDs")

class CreateRfcInput(BaseModel):
    known_error_id: str = Field(..., description="Related Known Error ID")
    title: str = Field(..., description="RFC title")
    description: str = Field(..., description="Detailed change description")
    risk_level: str = Field(..., description="Risk: Low, Medium, High, Critical")
    test_plan: str = Field(..., description="Testing requirements")
    rollback_plan: str = Field(..., description="Rollback procedure")
    implementation_schedule: str = Field(..., description="Proposed implementation timeline")

class CalculateImpactInput(BaseModel):
    service: str = Field(..., description="Service name to calculate impact for")
    incident_ids: Optional[str] = Field(None, description="Comma-separated incident IDs to scope impact")

class CrossReferenceInput(BaseModel):
    service: str = Field(..., description="Service name to cross-reference")
    error_code: Optional[str] = Field(None, description="Error code to cross-reference")

class AnalyzeAllPatternsInput(BaseModel):
    """No required inputs — runs comprehensive analysis on all data."""
    pass


# ========================== Tool 1: parse_incidents ==========================
# READS FROM CSV FILE

class ParseIncidentsTool(BaseTool):
    name: str = "parse_incidents"
    description: str = (
        "Reads the incident CSV file and returns structured records. "
        "Can filter by service, priority, error_code, and date range. "
        "Returns incident records with all fields from the CSV."
    )
    args_schema: type[BaseModel] = ParseIncidentsInput

    def _run(self, service: str = None, priority: str = None,
             error_code: str = None, date_from: str = None, date_to: str = None) -> str:
        incidents = _load_csv(INCIDENTS_CSV)

        if service:
            incidents = [i for i in incidents if service.lower() in i.get("service", "").lower()]
        if priority:
            incidents = [i for i in incidents if priority.lower() in i.get("priority", "").lower()]
        if error_code:
            incidents = [i for i in incidents if error_code.upper() == i.get("error_code", "").upper()]
        if date_from:
            incidents = [i for i in incidents if i.get("opened_at", "") >= date_from]
        if date_to:
            incidents = [i for i in incidents if i.get("opened_at", "")[:10] <= date_to]

        result = {
            "total_incidents": len(incidents),
            "filters_applied": {
                "service": service, "priority": priority,
                "error_code": error_code, "date_from": date_from, "date_to": date_to
            },
            "incidents": incidents
        }
        return json.dumps(result, indent=2)


# ========================== Tool 2: find_patterns ==========================
# READS FROM CSV FILE

class FindPatternsTool(BaseTool):
    name: str = "find_patterns"
    description: str = (
        "Groups incidents by service + subcategory + error_code and returns clusters "
        "above a frequency threshold. Also groups by service+error_code for broader "
        "patterns. Returns candidate problem patterns with temporal analysis."
    )
    args_schema: type[BaseModel] = FindPatternsInput

    def _run(self, min_frequency: int = 3) -> str:
        incidents = _load_csv(INCIDENTS_CSV)
        day_names = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]

        # Group by (service, error_code) — the strongest signal
        error_clusters = defaultdict(list)
        for inc in incidents:
            err = inc.get("error_code", "").strip()
            svc = inc.get("service", "").strip()
            if err and svc:
                error_clusters[(svc, err)].append(inc)

        patterns = []
        seen_incident_ids = set()

        for (svc, err), incs in sorted(error_clusters.items(), key=lambda x: len(x[1]), reverse=True):
            if len(incs) < min_frequency:
                continue

            ids = [i["incident_id"] for i in incs]
            priorities = Counter(i.get("priority", "") for i in incs)
            descriptions = list(set(i.get("short_description", "") for i in incs))
            resolutions = list(set(i.get("resolution_notes", "") for i in incs if i.get("resolution_notes", "").strip()))
            linked_changes = list(set(i.get("related_change", "") for i in incs if i.get("related_change", "").strip()))

            # Temporal analysis
            day_counts = Counter()
            hour_counts = Counter()
            dom_counts = Counter()
            for inc in incs:
                dt = _parse_dt(inc.get("opened_at", ""))
                if dt:
                    day_counts[day_names[dt.weekday()]] += 1
                    hour_counts[dt.hour] += 1
                    dom_counts[dt.day] += 1

            temporal_signals = []
            if day_counts:
                top_day, top_count = day_counts.most_common(1)[0]
                if top_count >= max(2, len(incs) * 0.3):
                    temporal_signals.append(f"CLUSTERS ON {top_day.upper()} ({top_count}/{len(incs)} incidents)")
            if hour_counts:
                peak_hours = [h for h, c in hour_counts.items() if c >= max(2, len(incs) * 0.25)]
                if peak_hours:
                    temporal_signals.append(f"Peak hours: {', '.join(f'{h:02d}:00' for h in sorted(peak_hours))}")
            month_start = sum(dom_counts.get(d, 0) for d in [1, 2, 3])
            if month_start >= max(2, len(incs) * 0.3):
                temporal_signals.append(f"CLUSTERS AT MONTH START (days 1-3): {month_start}/{len(incs)} incidents")

            # Track which incidents are in this pattern
            for iid in ids:
                seen_incident_ids.add(iid)

            patterns.append({
                "service": svc,
                "error_code": err,
                "incident_count": len(incs),
                "incident_ids": ids,
                "priority_distribution": dict(priorities),
                "p1_count": priorities.get("P1-Critical", 0),
                "date_range": f"{incs[0].get('opened_at', '')[:10]} to {incs[-1].get('opened_at', '')[:10]}",
                "descriptions": descriptions[:3],
                "resolution_notes": resolutions[:3],
                "related_changes": linked_changes,
                "temporal_signals": temporal_signals,
                "day_of_week": dict(day_counts),
                "subcategories": list(set(i.get("subcategory", "") for i in incs)),
            })

        return json.dumps({
            "total_incidents_analyzed": len(incidents),
            "patterns_found": len(patterns),
            "min_frequency_threshold": min_frequency,
            "patterns": patterns
        }, indent=2)


# ========================== Tool 3: get_time_distribution ==========================
# READS FROM CSV FILE

class GetTimeDistributionTool(BaseTool):
    name: str = "get_time_distribution"
    description: str = (
        "For a given set of incidents (filtered by service, error_code, or subcategory), "
        "returns day-of-week and hour-of-day distribution to reveal temporal patterns. "
        "Helps identify if incidents cluster on specific days or time windows."
    )
    args_schema: type[BaseModel] = TimeDistributionInput

    def _run(self, service: str = None, error_code: str = None, subcategory: str = None) -> str:
        incidents = _load_csv(INCIDENTS_CSV)

        if service:
            incidents = [i for i in incidents if service.lower() in i.get("service", "").lower()]
        if error_code:
            incidents = [i for i in incidents if error_code.upper() == i.get("error_code", "").upper()]
        if subcategory:
            incidents = [i for i in incidents if subcategory.lower() in i.get("subcategory", "").lower()]

        day_names = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
        day_dist = Counter()
        hour_dist = Counter()
        day_of_month_dist = Counter()

        for inc in incidents:
            dt = _parse_dt(inc.get("opened_at", ""))
            if dt:
                day_dist[day_names[dt.weekday()]] += 1
                hour_dist[dt.hour] += 1
                day_of_month_dist[dt.day] += 1

        resolution_times = []
        for inc in incidents:
            dt_o = _parse_dt(inc.get("opened_at", ""))
            dt_r = _parse_dt(inc.get("resolved_at", ""))
            if dt_o and dt_r:
                resolution_times.append((dt_r - dt_o).total_seconds() / 3600)

        sorted_days = {d: day_dist.get(d, 0) for d in day_names}
        sorted_hours = {f"{h:02d}:00": hour_dist.get(h, 0) for h in range(24)}

        temporal_notes = []
        if day_dist:
            max_day = max(day_dist, key=day_dist.get)
            if day_dist[max_day] >= max(2, len(incidents) * 0.3):
                temporal_notes.append(f"Strong clustering on {max_day} ({day_dist[max_day]}/{len(incidents)} incidents)")
        if hour_dist:
            peak_hours = [h for h, c in hour_dist.items() if c >= max(2, len(incidents) * 0.2)]
            if peak_hours:
                temporal_notes.append(f"Peak hours: {', '.join(f'{h:02d}:00' for h in sorted(peak_hours))}")
        month_start = sum(day_of_month_dist.get(d, 0) for d in [1, 2, 3])
        if month_start >= max(2, len(incidents) * 0.3):
            temporal_notes.append(f"Clustering at month start (days 1-3): {month_start}/{len(incidents)} incidents")

        return json.dumps({
            "filters": {"service": service, "error_code": error_code, "subcategory": subcategory},
            "incident_count": len(incidents),
            "day_of_week_distribution": sorted_days,
            "hour_of_day_distribution": sorted_hours,
            "day_of_month_distribution": dict(sorted(day_of_month_dist.items())),
            "temporal_notes": temporal_notes,
            "avg_resolution_hours": round(sum(resolution_times) / len(resolution_times), 2) if resolution_times else None,
            "incident_ids": [i["incident_id"] for i in incidents],
        }, indent=2)


# ========================== Tool 4: query_cmdb ==========================
# READS FROM CSV FILE

class QueryCmdbTool(BaseTool):
    name: str = "query_cmdb"
    description: str = (
        "Queries the FinServe CMDB CSV file. Looks up a CI by ID or name and returns "
        "its full record including tier, owner, infrastructure, dependencies, and notes."
    )
    args_schema: type[BaseModel] = QueryCmdbInput

    def _run(self, ci_id: str = None, ci_name: str = None) -> str:
        cmdb = _load_csv(CMDB_CSV)
        results = []

        for ci in cmdb:
            if ci_id and ci.get("ci_id", "").upper() == ci_id.upper():
                results.append(ci)
            elif ci_name and ci_name.lower() in ci.get("ci_name", "").lower():
                results.append(ci)

        if not results and not ci_id and not ci_name:
            results = cmdb

        return json.dumps({
            "query": {"ci_id": ci_id, "ci_name": ci_name},
            "results_count": len(results),
            "configuration_items": results,
        }, indent=2)


# ========================== Tool 5: query_changes ==========================
# READS FROM CSV FILE

class QueryChangesTool(BaseTool):
    name: str = "query_changes"
    description: str = (
        "Reads the change log CSV and returns changes filtered by CI ID or date range. "
        "Each record includes change ID, title, affected CI, risk level, and description."
    )
    args_schema: type[BaseModel] = QueryChangesInput

    def _run(self, ci_id: str = None, date_from: str = None, date_to: str = None) -> str:
        changes = _load_csv(CHANGES_CSV)

        if ci_id:
            changes = [c for c in changes if ci_id.upper() in c.get("ci_id", "").upper()]
        if date_from:
            changes = [c for c in changes if c.get("implemented_at", "") >= date_from]
        if date_to:
            changes = [c for c in changes if c.get("implemented_at", "")[:10] <= date_to]

        return json.dumps({
            "query": {"ci_id": ci_id, "date_from": date_from, "date_to": date_to},
            "results_count": len(changes),
            "changes": changes,
        }, indent=2)


# ========================== Tool 6: map_dependencies ==========================
# READS FROM CSV FILE

class MapDependenciesTool(BaseTool):
    name: str = "map_dependencies"
    description: str = (
        "Given a CI ID, walks the CMDB dependency graph and returns upstream and "
        "downstream CIs. Shows the full dependency chain for impact analysis."
    )
    args_schema: type[BaseModel] = MapDependenciesInput

    def _run(self, ci_id: str) -> str:
        cmdb = _load_csv(CMDB_CSV)
        ci_lookup = {ci["ci_id"]: ci for ci in cmdb}

        target = ci_lookup.get(ci_id.upper())
        if not target:
            return json.dumps({"error": f"CI '{ci_id}' not found in CMDB", "available_cis": list(ci_lookup.keys())})

        upstream_ids = [x.strip() for x in target.get("upstream_deps", "").split(",") if x.strip()]
        downstream_ids = [x.strip() for x in target.get("downstream_deps", "").split(",") if x.strip()]

        upstream_details = []
        for uid in upstream_ids:
            uci = ci_lookup.get(uid)
            if uci:
                upstream_details.append({
                    "ci_id": uid, "ci_name": uci.get("ci_name", ""),
                    "tier": uci.get("tier", ""), "ci_type": uci.get("ci_type", "")
                })

        downstream_details = []
        for did in downstream_ids:
            dci = ci_lookup.get(did)
            if dci:
                downstream_details.append({
                    "ci_id": did, "ci_name": dci.get("ci_name", ""),
                    "tier": dci.get("tier", ""), "ci_type": dci.get("ci_type", "")
                })

        # Find shared infrastructure — look for shared database or infra strings
        shared_infra = []
        target_infra = target.get("infra", "")
        target_notes = target.get("notes", "")
        for ci in cmdb:
            if ci["ci_id"] == ci_id:
                continue
            # Check infra overlap
            if target_infra and any(part.strip() in ci.get("infra", "") for part in target_infra.split("+") if len(part.strip()) > 5):
                shared_infra.append({
                    "ci_id": ci["ci_id"], "ci_name": ci.get("ci_name", ""),
                    "shared_resource": target_infra,
                    "other_infra": ci.get("infra", ""),
                    "other_notes": ci.get("notes", ""),
                })
            # Check notes for shared references (e.g., shared connection pool)
            if "db-ledger-prod" in target_notes and "db-ledger-prod" in ci.get("notes", ""):
                if not any(s["ci_id"] == ci["ci_id"] for s in shared_infra):
                    shared_infra.append({
                        "ci_id": ci["ci_id"], "ci_name": ci.get("ci_name", ""),
                        "shared_resource": "db-ledger-prod (shared database connection pool)",
                        "other_notes": ci.get("notes", ""),
                    })

        return json.dumps({
            "ci_id": ci_id,
            "ci_name": target.get("ci_name", ""),
            "tier": target.get("tier", ""),
            "infrastructure": target.get("infra", ""),
            "notes": target.get("notes", ""),
            "upstream_dependencies": upstream_details,
            "downstream_dependencies": downstream_details,
            "shared_infrastructure": shared_infra,
        }, indent=2)


# ========================== Tool 7: correlate_incidents_changes ==========================
# READS FROM BOTH CSV FILES

class CorrelateIncidentsChangesTool(BaseTool):
    name: str = "correlate_incidents_changes"
    description: str = (
        "For a set of incidents (by service or CI), finds changes that occurred within "
        "a configurable time window before each incident. Reveals change-induced patterns."
    )
    args_schema: type[BaseModel] = CorrelateIncidentsChangesInput

    def _run(self, service: str = None, ci_id: str = None, window_hours: int = 72) -> str:
        incidents = _load_csv(INCIDENTS_CSV)
        changes = _load_csv(CHANGES_CSV)

        if service:
            incidents = [i for i in incidents if service.lower() in i.get("service", "").lower()]
        if ci_id:
            incidents = [i for i in incidents if ci_id.upper() in i.get("ci_id", "").upper()]

        correlations = []
        for inc in incidents:
            inc_time = _parse_dt(inc.get("opened_at", ""))
            if not inc_time:
                continue

            linked_change = inc.get("related_change", "").strip()

            nearby_changes = []
            for chg in changes:
                chg_time = _parse_dt(chg.get("implemented_at", ""))
                if not chg_time:
                    continue

                delta = (inc_time - chg_time).total_seconds() / 3600
                if 0 <= delta <= window_hours:
                    nearby_changes.append({
                        "change_id": chg.get("change_id", ""),
                        "title": chg.get("title", ""),
                        "ci_id": chg.get("ci_id", ""),
                        "risk": chg.get("risk", ""),
                        "hours_before_incident": round(delta, 1),
                        "explicitly_linked": chg.get("change_id", "") == linked_change,
                    })

            if nearby_changes or linked_change:
                correlations.append({
                    "incident_id": inc.get("incident_id", ""),
                    "incident_time": inc.get("opened_at", ""),
                    "service": inc.get("service", ""),
                    "error_code": inc.get("error_code", ""),
                    "linked_change": linked_change,
                    "nearby_changes": nearby_changes,
                })

        return json.dumps({
            "query": {"service": service, "ci_id": ci_id, "window_hours": window_hours},
            "incidents_analyzed": len(incidents),
            "incidents_with_change_correlation": len(correlations),
            "correlations": correlations,
        }, indent=2)


# ========================== Tool 8: five_whys_analysis ==========================
# READS FROM ALL THREE CSV FILES

class FiveWhysTool(BaseTool):
    name: str = "five_whys_analysis"
    description: str = (
        "Given a pattern summary and context data, provides a structured Five Whys "
        "analysis template populated with CMDB and change log evidence. "
        "The agent should complete the causal chain using this framework."
    )
    args_schema: type[BaseModel] = FiveWhysInput

    def _run(self, pattern_description: str, service: str,
             error_code: str = None, ci_id: str = None) -> str:
        cmdb = _load_csv(CMDB_CSV)
        changes = _load_csv(CHANGES_CSV)
        incidents = _load_csv(INCIDENTS_CSV)

        ci_info = None
        if ci_id:
            for ci in cmdb:
                if ci.get("ci_id", "").upper() == ci_id.upper():
                    ci_info = ci
                    break
        if not ci_info:
            for ci in cmdb:
                if service.lower() in ci.get("ci_name", "").lower():
                    ci_info = ci
                    ci_id = ci.get("ci_id", "")
                    break

        related_changes = [c for c in changes if c.get("ci_id", "") == ci_id] if ci_id else []
        related_incidents = [i for i in incidents if service.lower() in i.get("service", "").lower()]
        if error_code:
            related_incidents = [i for i in related_incidents if i.get("error_code", "") == error_code]

        resolution_notes = list(set(
            i.get("resolution_notes", "") for i in related_incidents if i.get("resolution_notes", "").strip()
        ))

        return json.dumps({
            "five_whys_framework": {
                "pattern": pattern_description,
                "service": service,
                "error_code": error_code,
                "why_1": f"Why did {service} experience this pattern? — (Agent: analyze the error_code {error_code} and incident descriptions)",
                "why_2": "Why did that condition occur? — (Agent: check resolution_notes for clues)",
                "why_3": "Why was the system vulnerable to this? — (Agent: check CMDB notes and infrastructure)",
                "why_4": "Why was this not prevented by existing controls? — (Agent: check change log)",
                "why_5": "Why did the control gap exist? — (Agent: identify the process or design root cause)",
            },
            "supporting_evidence": {
                "cmdb_record": ci_info,
                "related_changes": related_changes,
                "incident_count": len(related_incidents),
                "resolution_notes_summary": resolution_notes[:5],
                "descriptions": list(set(i.get("short_description", "") for i in related_incidents))[:5],
            }
        }, indent=2)


# ========================== Tool 9: build_timeline ==========================
# READS FROM BOTH CSV FILES

class BuildTimelineTool(BaseTool):
    name: str = "build_timeline"
    description: str = (
        "Constructs a chronological timeline of incidents and changes for a given "
        "service or CI. Shows how incidents and changes interleave over time."
    )
    args_schema: type[BaseModel] = BuildTimelineInput

    def _run(self, service: str = None, ci_id: str = None) -> str:
        incidents = _load_csv(INCIDENTS_CSV)
        changes = _load_csv(CHANGES_CSV)
        cmdb = _load_csv(CMDB_CSV)

        # Resolve ci_id from service name if needed
        if service and not ci_id:
            for ci in cmdb:
                if service.lower() in ci.get("ci_name", "").lower():
                    ci_id = ci.get("ci_id", "")
                    break

        events = []

        for inc in incidents:
            if service and service.lower() not in inc.get("service", "").lower():
                continue
            if ci_id and ci_id.upper() not in inc.get("ci_id", "").upper():
                continue
            events.append({
                "timestamp": inc.get("opened_at", ""),
                "type": "INCIDENT",
                "id": inc.get("incident_id", ""),
                "priority": inc.get("priority", ""),
                "description": inc.get("short_description", ""),
                "error_code": inc.get("error_code", ""),
                "resolution": inc.get("resolution_notes", ""),
            })

        for chg in changes:
            if ci_id and ci_id.upper() != chg.get("ci_id", "").upper():
                continue
            events.append({
                "timestamp": chg.get("implemented_at", ""),
                "type": "CHANGE",
                "id": chg.get("change_id", ""),
                "risk": chg.get("risk", ""),
                "description": chg.get("title", ""),
                "details": chg.get("description", ""),
            })

        events.sort(key=lambda e: e.get("timestamp", ""))

        return json.dumps({
            "query": {"service": service, "ci_id": ci_id},
            "total_events": len(events),
            "timeline": events,
        }, indent=2)


# ========================== Tool 10: create_problem_record ==========================

class CreateProblemRecordTool(BaseTool):
    name: str = "create_problem_record"
    description: str = (
        "Generates a formal Problem Record with unique ID, severity, affected CIs, "
        "linked incidents, and status. Returns the structured record."
    )
    args_schema: type[BaseModel] = CreateProblemRecordInput

    def _run(self, pattern_id: str, title: str, severity: str,
             affected_cis: str, linked_incidents: str, description: str) -> str:
        problem_id = f"PRB-{pattern_id.replace('PAT-', '')}"
        record = {
            "problem_id": problem_id,
            "pattern_id": pattern_id,
            "title": title,
            "severity": severity,
            "status": "Under Investigation",
            "affected_cis": [ci.strip() for ci in affected_cis.split(",")],
            "linked_incidents": [inc.strip() for inc in linked_incidents.split(",")],
            "incident_count": len([inc.strip() for inc in linked_incidents.split(",") if inc.strip()]),
            "description": description,
            "created_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "itil_phase": "Problem Identification → Problem Control",
            "framework_reference": "ITIL 4 Problem Management Practice",
        }
        return json.dumps(record, indent=2)


# ========================== Tool 11: create_known_error ==========================
# WRITES TO FILE

class CreateKnownErrorTool(BaseTool):
    name: str = "create_known_error"
    description: str = (
        "Creates a Known Error Record with root cause, workaround, and permanent fix. "
        "Writes the record to a JSON file in the output directory."
    )
    args_schema: type[BaseModel] = CreateKnownErrorInput

    def _run(self, problem_id: str, title: str, root_cause: str,
             workaround: str, permanent_fix: str, affected_ci: str,
             linked_incidents: str) -> str:
        ke_id = f"KE-{problem_id.replace('PRB-', '')}"

        record = {
            "ke_id": ke_id,
            "problem_id": problem_id,
            "title": title,
            "status": "Known Error — Awaiting Permanent Fix",
            "root_cause": root_cause,
            "workaround": workaround,
            "permanent_fix": permanent_fix,
            "affected_ci": affected_ci,
            "linked_incidents": [inc.strip() for inc in linked_incidents.split(",") if inc.strip()],
            "created_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "kedb_reference": "ITIL 4 Known Error Database",
            "framework_reference": "ITIL 4 Error Control — Known Error Documentation",
        }

        os.makedirs(OUTPUT_DIR, exist_ok=True)
        filepath = os.path.join(OUTPUT_DIR, f"{ke_id}.json")
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(record, f, indent=2)

        return json.dumps({
            "message": f"Known Error Record {ke_id} created and saved to {filepath}",
            "record": record,
        }, indent=2)


# ========================== Tool 12: create_rfc ==========================
# WRITES TO FILE

class CreateRfcTool(BaseTool):
    name: str = "create_rfc"
    description: str = (
        "Generates a Request for Change (RFC) with description, risk assessment, "
        "test plan, rollback plan, and implementation schedule. Writes to file."
    )
    args_schema: type[BaseModel] = CreateRfcInput

    def _run(self, known_error_id: str, title: str, description: str,
             risk_level: str, test_plan: str, rollback_plan: str,
             implementation_schedule: str) -> str:
        rfc_id = f"RFC-{known_error_id.replace('KE-', '')}"

        change_type = "Normal"
        if risk_level.lower() in ("critical", "high"):
            change_type = "Normal (requires full CAB approval)"
        elif risk_level.lower() == "medium":
            change_type = "Normal"
        else:
            change_type = "Standard"

        record = {
            "rfc_id": rfc_id,
            "known_error_id": known_error_id,
            "title": title,
            "change_type": change_type,
            "status": "Draft — Awaiting CAB Approval",
            "description": description,
            "risk_assessment": {
                "risk_level": risk_level,
                "impact_if_failed": "Service degradation possible; rollback plan in place",
                "impact_if_not_implemented": "Recurring incidents will continue causing service disruption",
            },
            "test_plan": test_plan,
            "rollback_plan": rollback_plan,
            "implementation_schedule": implementation_schedule,
            "created_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "framework_reference": "ITIL 4 Change Enablement Practice",
            "approval_required_from": ["Change Advisory Board (CAB)", "Service Owner", "Technical Lead"],
        }

        os.makedirs(OUTPUT_DIR, exist_ok=True)
        filepath = os.path.join(OUTPUT_DIR, f"{rfc_id}.json")
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(record, f, indent=2)

        return json.dumps({
            "message": f"RFC {rfc_id} created and saved to {filepath}",
            "record": record,
        }, indent=2)


# ========================== Tool 13: calculate_impact ==========================
# READS FROM CSV FILE

class CalculateImpactTool(BaseTool):
    name: str = "calculate_impact"
    description: str = (
        "Computes business impact metrics for a pattern: total incident count, "
        "total downtime hours, priority distribution, affected services, and date spread."
    )
    args_schema: type[BaseModel] = CalculateImpactInput

    def _run(self, service: str, incident_ids: str = None) -> str:
        incidents = _load_csv(INCIDENTS_CSV)

        if incident_ids:
            id_list = [i.strip() for i in incident_ids.split(",")]
            filtered = [i for i in incidents if i.get("incident_id", "") in id_list]
        else:
            filtered = [i for i in incidents if service.lower() in i.get("service", "").lower()]

        if not filtered:
            return json.dumps({"error": f"No incidents found for service '{service}'"})

        total_downtime_hours = 0
        priority_counts = Counter()
        for inc in filtered:
            priority_counts[inc.get("priority", "")] += 1
            dt_o = _parse_dt(inc.get("opened_at", ""))
            dt_r = _parse_dt(inc.get("resolved_at", ""))
            if dt_o and dt_r:
                total_downtime_hours += (dt_r - dt_o).total_seconds() / 3600

        return json.dumps({
            "service": service,
            "total_incidents": len(filtered),
            "total_downtime_hours": round(total_downtime_hours, 2),
            "avg_downtime_hours": round(total_downtime_hours / len(filtered), 2) if filtered else 0,
            "priority_distribution": dict(priority_counts),
            "p1_critical_count": priority_counts.get("P1-Critical", 0),
            "date_range": f"{filtered[0].get('opened_at', '')[:10]} to {filtered[-1].get('opened_at', '')[:10]}",
            "incident_ids": [i["incident_id"] for i in filtered],
            "affected_teams": list(set(i.get("assigned_team", "") for i in filtered)),
        }, indent=2)


# ========================== Tool 14: cross_reference ==========================
# READS FROM ALL THREE CSV FILES

class CrossReferenceTool(BaseTool):
    name: str = "cross_reference"
    description: str = (
        "Cross-references incident data with CMDB and change log for a given service. "
        "Returns a comprehensive view combining incidents, CI details, and changes."
    )
    args_schema: type[BaseModel] = CrossReferenceInput

    def _run(self, service: str, error_code: str = None) -> str:
        incidents = _load_csv(INCIDENTS_CSV)
        cmdb = _load_csv(CMDB_CSV)
        changes = _load_csv(CHANGES_CSV)

        matched_incidents = [i for i in incidents if service.lower() in i.get("service", "").lower()]
        if error_code:
            matched_incidents = [i for i in matched_incidents if i.get("error_code", "") == error_code]

        ci_info = None
        ci_id = None
        for ci in cmdb:
            if service.lower() in ci.get("ci_name", "").lower():
                ci_info = ci
                ci_id = ci.get("ci_id", "")
                break

        related_changes = [c for c in changes if c.get("ci_id", "") == ci_id] if ci_id else []

        linked_change_ids = set()
        for inc in matched_incidents:
            rc = inc.get("related_change", "").strip()
            if rc:
                linked_change_ids.add(rc)
        linked_changes = [c for c in changes if c.get("change_id", "") in linked_change_ids]

        return json.dumps({
            "service": service,
            "error_code": error_code,
            "incident_count": len(matched_incidents),
            "incidents_summary": [{
                "id": i["incident_id"], "date": i.get("opened_at", ""),
                "priority": i.get("priority", ""), "description": i.get("short_description", ""),
                "resolution": i.get("resolution_notes", ""), "error_code": i.get("error_code", ""),
                "related_change": i.get("related_change", ""),
            } for i in matched_incidents],
            "cmdb_record": ci_info,
            "changes_for_ci": related_changes,
            "explicitly_linked_changes": linked_changes,
        }, indent=2)


# ========================== Tool 15: analyze_all_patterns ==========================
# READS FROM ALL THREE CSV FILES — comprehensive pre-digested analysis

class AnalyzeAllPatternsTool(BaseTool):
    name: str = "analyze_all_patterns"
    description: str = (
        "COMPREHENSIVE PATTERN ANALYSIS — call this FIRST. Reads all three CSV files "
        "(incidents, CMDB, changes) and performs deep analysis to identify the top "
        "recurring problem patterns. Returns a pre-digested summary for each pattern "
        "including: incident cluster, temporal signals, CMDB context, correlated changes, "
        "resolution note analysis, and root cause hints. This single tool call replaces "
        "the need for multiple separate parse/find/time calls."
    )
    args_schema: type[BaseModel] = AnalyzeAllPatternsInput

    def _run(self) -> str:
        incidents = _load_csv(INCIDENTS_CSV)
        cmdb = _load_csv(CMDB_CSV)
        changes = _load_csv(CHANGES_CSV)

        ci_lookup = {ci["ci_id"]: ci for ci in cmdb}
        chg_lookup = {c["change_id"]: c for c in changes}

        day_names = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]

        # ---- Cluster by (service, error_code) ----
        error_clusters = defaultdict(list)
        for inc in incidents:
            err = inc.get("error_code", "").strip()
            svc = inc.get("service", "").strip()
            if err and svc:
                error_clusters[(svc, err)].append(inc)

        # ---- Build pattern reports for significant clusters ----
        pattern_reports = []
        pat_num = 0

        for (svc, err), incs in sorted(error_clusters.items(), key=lambda x: len(x[1]), reverse=True):
            if len(incs) < 3:
                continue

            pat_num += 1
            ids = [i["incident_id"] for i in incs]
            priorities = Counter(i.get("priority", "") for i in incs)
            descriptions = list(set(i.get("short_description", "") for i in incs))
            resolutions = list(set(i.get("resolution_notes", "") for i in incs if i.get("resolution_notes", "").strip()))

            # Temporal analysis
            day_counts = Counter()
            hour_counts = Counter()
            dom_counts = Counter()
            for inc in incs:
                dt = _parse_dt(inc.get("opened_at", ""))
                if dt:
                    day_counts[day_names[dt.weekday()]] += 1
                    hour_counts[dt.hour] += 1
                    dom_counts[dt.day] += 1

            temporal_signals = []
            if day_counts:
                top_day, top_count = day_counts.most_common(1)[0]
                if top_count >= max(2, len(incs) * 0.3):
                    temporal_signals.append(f"CLUSTERS ON {top_day.upper()} ({top_count}/{len(incs)} incidents)")
            if hour_counts:
                peak_hours = [h for h, c in hour_counts.items() if c >= max(2, len(incs) * 0.25)]
                if peak_hours:
                    temporal_signals.append(f"Peak hours: {', '.join(f'{h:02d}:00' for h in sorted(peak_hours))}")
            month_start = sum(dom_counts.get(d, 0) for d in [1, 2, 3])
            if month_start >= max(2, len(incs) * 0.3):
                temporal_signals.append(f"CLUSTERS AT MONTH START (days 1-3): {month_start}/{len(incs)} incidents")

            # CMDB lookup
            ci_id = incs[0].get("ci_id", "")
            ci_info = ci_lookup.get(ci_id, {})

            # Change correlation
            linked_chg_ids = set()
            for inc in incs:
                rc = inc.get("related_change", "").strip()
                if rc:
                    linked_chg_ids.add(rc)
            linked_changes = [chg_lookup[cid] for cid in linked_chg_ids if cid in chg_lookup]
            ci_changes = [c for c in changes if c.get("ci_id", "") == ci_id]

            # Resolution note analysis — look for repeated patterns
            resolution_keywords = Counter()
            for rn in resolutions:
                for kw in ["restart", "rollback", "rolled back", "cache", "pool", "batch",
                           "memory", "connection", "pods", "AZ-", "hotfix", "token", "heap"]:
                    if kw.lower() in rn.lower():
                        resolution_keywords[kw] += 1

            # Shared infrastructure detection
            shared_infra = []
            if ci_info:
                for other_ci in cmdb:
                    if other_ci["ci_id"] == ci_id:
                        continue
                    ci_notes = ci_info.get("notes", "")
                    other_notes = other_ci.get("notes", "")
                    # Check for shared database references
                    if "db-ledger-prod" in ci_notes and "db-ledger-prod" in other_notes:
                        shared_infra.append(f"{other_ci['ci_name']} shares db-ledger-prod connection pool")

            # Downtime calculation
            total_downtime = 0.0
            for inc in incs:
                dt_o = _parse_dt(inc.get("opened_at", ""))
                dt_r = _parse_dt(inc.get("resolved_at", ""))
                if dt_o and dt_r:
                    total_downtime += (dt_r - dt_o).total_seconds() / 3600

            report = {
                "pattern_id": f"PAT-{pat_num:03d}",
                "service": svc,
                "error_code": err,
                "ci_id": ci_id,
                "incident_count": len(incs),
                "incident_ids": ids,
                "p1_critical_count": priorities.get("P1-Critical", 0),
                "priority_distribution": dict(priorities),
                "total_downtime_hours": round(total_downtime, 1),
                "descriptions": descriptions[:3],
                "resolution_notes": resolutions[:3],
                "resolution_keywords": dict(resolution_keywords) if resolution_keywords else {},
                "temporal_signals": temporal_signals,
                "day_of_week": dict(day_counts),
                "hour_distribution": {f"{h:02d}:00": c for h, c in sorted(hour_counts.items())},
                "day_of_month": dict(sorted(dom_counts.items())),
                "cmdb": {
                    "ci_name": ci_info.get("ci_name", ""),
                    "tier": ci_info.get("tier", ""),
                    "infra": ci_info.get("infra", ""),
                    "notes": ci_info.get("notes", ""),
                    "owner": ci_info.get("owner", ""),
                } if ci_info else None,
                "linked_changes": [{
                    "change_id": c.get("change_id", ""),
                    "title": c.get("title", ""),
                    "risk": c.get("risk", ""),
                    "description": c.get("description", ""),
                } for c in linked_changes],
                "all_ci_changes": [{
                    "change_id": c.get("change_id", ""),
                    "title": c.get("title", ""),
                    "risk": c.get("risk", ""),
                    "implemented_at": c.get("implemented_at", ""),
                    "description": c.get("description", ""),
                } for c in ci_changes],
                "shared_infrastructure": shared_infra,
            }
            pattern_reports.append(report)

        return json.dumps({
            "analysis_summary": f"Analyzed {len(incidents)} incidents across {len(set(i['service'] for i in incidents))} services. Found {len(pattern_reports)} significant patterns (3+ recurring incidents with same service+error_code).",
            "total_incidents": len(incidents),
            "total_patterns": len(pattern_reports),
            "patterns": pattern_reports,
        }, indent=2)


# ========================== Instantiate all tools ==========================

parse_incidents = ParseIncidentsTool()
find_patterns = FindPatternsTool()
get_time_distribution = GetTimeDistributionTool()
query_cmdb = QueryCmdbTool()
query_changes = QueryChangesTool()
map_dependencies = MapDependenciesTool()
correlate_incidents_changes = CorrelateIncidentsChangesTool()
five_whys_analysis = FiveWhysTool()
build_timeline = BuildTimelineTool()
create_problem_record = CreateProblemRecordTool()
create_known_error = CreateKnownErrorTool()
create_rfc = CreateRfcTool()
calculate_impact = CalculateImpactTool()
cross_reference = CrossReferenceTool()
analyze_all_patterns = AnalyzeAllPatternsTool()

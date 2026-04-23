"""
FinServe BCM/ITSM Simulation Engine — Evaluation & Scoring
Grades the crew's incident response output against gold-standard BCM/ITSM criteria.
Scoring covers: classification, containment, BIA, change management, recovery, communications,
and scenario-specific requirements.
"""

from __future__ import annotations


class SimulationEngine:
    """
    Evaluates the crew's final output against BCM/ITSM gold standards.
    Each dimension is scored 0–100; the overall KPI is a weighted average.
    """

    # Scoring dimension weights (must sum to 1.0)
    WEIGHTS = {
        "incident_classification":      0.15,
        "containment_effectiveness":    0.20,
        "business_impact_analysis":     0.15,
        "change_management_compliance": 0.10,
        "service_recovery":             0.20,
        "stakeholder_communications":   0.15,
        "regulatory_compliance":        0.05,
    }

    def evaluate(self, final_plan, scenario: str) -> dict:
        """
        Evaluate the crew output against all scoring dimensions.

        Args:
            final_plan: CrewAI result object or string output from crew.kickoff()
            scenario: One of ransomware | cloud_outage_ddos | data_breach |
                      insider_threat | supply_chain | cascading_failure

        Returns:
            dict with individual dimension scores, scenario bonuses, and overall KPI
        """
        plan_lower = str(final_plan).lower()

        scores = {}

        # -------------------------------------------------------------------
        # Dimension 1: Incident Classification (15%)
        # Checks: severity assigned, incident type declared, BCM plan referenced,
        # ITIL lifecycle followed, SLA clock mentioned
        # -------------------------------------------------------------------
        classification_checks = [
            ("severity assigned (p1/p2/p3)",          any(x in plan_lower for x in ["p1", "p2", "p3", "priority 1", "priority 2", "critical incident"])),
            ("major incident or crisis declared",     any(x in plan_lower for x in ["major incident", "crisis", "bcm", "bcm-fin-001", "bcm plan"])),
            ("incident id created",                   any(x in plan_lower for x in ["inc", "incident id", "incident record", "itil 4 incident"])),
            ("escalation path defined",               any(x in plan_lower for x in ["escalation", "ciso", "cto", "board", "escalate"])),
            ("sla clock referenced",                  any(x in plan_lower for x in ["sla", "sla breach", "response time", "sla clock"])),
            ("service health checked",                any(x in plan_lower for x in ["service health", "check_service_health", "health check", "monitoring"])),
            ("cmdb queried for blast radius",         any(x in plan_lower for x in ["cmdb", "configuration item", "ci ", "blast radius", "query_cmdb"])),
        ]
        scores["incident_classification"] = self._score_checks(classification_checks)

        # -------------------------------------------------------------------
        # Dimension 2: Containment Effectiveness (20%)
        # Checks: forensic evidence preserved, systems isolated, MITRE ATT&CK referenced,
        # runbook executed, chain-of-custody maintained
        # -------------------------------------------------------------------
        containment_checks = [
            ("forensic evidence preserved",           any(x in plan_lower for x in ["forensic", "snapshot", "evidence", "preserve", "chain-of-custody", "disk image"])),
            ("systems isolated / quarantined",        any(x in plan_lower for x in ["isolat", "quarantin", "vlan", "network isolation", "rb-sec-005"])),
            ("mitre att&ck referenced",               any(x in plan_lower for x in ["mitre", "att&ck", "ttp", "tactic", "technique", "ta00", "t1"])),
            ("iocs identified",                       any(x in plan_lower for x in ["ioc", "indicator of compromise", "hash", "ip address", "anomalous"])),
            ("lateral movement assessed",             any(x in plan_lower for x in ["lateral movement", "lateral", "pivot", "spread", "propagat"])),
            ("runbook executed for containment",      any(x in plan_lower for x in ["runbook", "rb-sec", "rb-net", "rb-cred", "execute_runbook"])),
            ("systems cleared for recovery",          any(x in plan_lower for x in ["cleared for recovery", "safe to restore", "eradication", "clean environment"])),
            ("legal / cirt notified",                 any(x in plan_lower for x in ["legal", "cirt", "counsel", "chain of custody", "hr and legal"])),
        ]
        scores["containment_effectiveness"] = self._score_checks(containment_checks)

        # -------------------------------------------------------------------
        # Dimension 3: Business Impact Analysis (15%)
        # Checks: financial modelling, cascade impacts, regulatory refs, vendor impact
        # -------------------------------------------------------------------
        bia_checks = [
            ("financial exposure calculated",         any(x in plan_lower for x in ["revenue loss", "financial exposure", "financial impact", "$", "usd", "£", "million"])),
            ("time-based degradation modelled",       any(x in plan_lower for x in ["1 hour", "2 hour", "4 hour", "1h", "2h", "4h", "escalat", "non-linear", "degradation"])),
            ("cascade impact mapped",                 any(x in plan_lower for x in ["cascade", "downstream", "dependency", "tier 1", "tier-1", "degraded at"])),
            ("rto / rpo referenced",                  any(x in plan_lower for x in ["rto", "rpo", "recovery time", "recovery point", "mtpd"])),
            ("regulatory exposure assessed",          any(x in plan_lower for x in ["pci", "gdpr", "sox", "regulatory", "compliance", "fine", "penalty"])),
            ("vendor impact assessed",                any(x in plan_lower for x in ["vendor", "third-party", "paybridge", "sla penalty", "assess_vendor"])),
            ("prioritised recovery order produced",   any(x in plan_lower for x in ["priorit", "recovery order", "recover first", "tier 1 first", "priority order"])),
        ]
        scores["business_impact_analysis"] = self._score_checks(bia_checks)

        # -------------------------------------------------------------------
        # Dimension 4: Change Management Compliance (10%)
        # Checks: emergency change documented, e-CAB approval, risk assessed,
        # rollback planned, CMDB updated, PIR scheduled
        # -------------------------------------------------------------------
        change_checks = [
            ("emergency change record created",       any(x in plan_lower for x in ["emergency change", "e-cab", "ecab", "chg-e", "emergency cab", "change record"])),
            ("risk rating assigned",                  any(x in plan_lower for x in ["risk rating", "risk: high", "risk: critical", "change risk", "low risk", "medium risk"])),
            ("rollback plan defined",                 any(x in plan_lower for x in ["rollback", "roll back", "revert", "undo", "fallback plan"])),
            ("approvals obtained (ciso/cto)",         any(x in plan_lower for x in ["ciso", "cto", "approval", "approved", "authoris", "sign-off"])),
            ("compliance controls checked",           any(x in plan_lower for x in ["sox itgc", "itgc", "change control", "sox control", "compliance control"])),
            ("post-implementation review planned",    any(x in plan_lower for x in ["post-implementation", "pir", "post implementation", "review within 24", "retrospective"])),
        ]
        scores["change_management_compliance"] = self._score_checks(change_checks)

        # -------------------------------------------------------------------
        # Dimension 5: Service Recovery (20%)
        # Checks: DR readiness assessed, failovers executed, RTO met, RPO met,
        # data integrity confirmed, stability monitoring
        # -------------------------------------------------------------------
        recovery_checks = [
            ("dr readiness assessed before failover", any(x in plan_lower for x in ["dr readiness", "dr site", "dr endpoint", "dr clean", "verify dr"])),
            ("failover executed",                     any(x in plan_lower for x in ["failover", "failed over", "failover_service", "dr failover", "fail over"])),
            ("tier-1 services recovered",             any(x in plan_lower for x in ["mobile banking", "online transfers", "core banking", "transaction database", "fraud detection"])),
            ("rto compliance checked",                any(x in plan_lower for x in ["rto", "within 4 hours", "rto met", "rto breached", "recovery time objective"])),
            ("rpo compliance checked",                any(x in plan_lower for x in ["rpo", "15 minutes", "rpo met", "data loss", "recovery point"])),
            ("post-failover health check run",        any(x in plan_lower for x in ["post-failover", "health check", "smoke test", "validation", "minimum viable"])),
            ("data integrity confirmed",              any(x in plan_lower for x in ["data integrity", "data loss", "replication lag", "zero data loss", "integrity confirmed"])),
            ("stability monitoring done",             any(x in plan_lower for x in ["stability", "30 minute", "stable operation", "monitor", "post-recovery"])),
            ("lessons logged",                        any(x in plan_lower for x in ["lesson", "log_lesson", "pir", "post-incident", "continual improvement"])),
        ]
        scores["service_recovery"] = self._score_checks(recovery_checks)

        # -------------------------------------------------------------------
        # Dimension 6: Stakeholder Communications (15%)
        # Checks: internal first, audience layering, all audiences covered,
        # regulatory notifications sent, 30-min cadence, war room established
        # -------------------------------------------------------------------
        comms_checks = [
            ("war room established",                  any(x in plan_lower for x in ["war room", "bridge call", "coordinate_war_room", "incident bridge", "war_room"])),
            ("customer notification sent",            any(x in plan_lower for x in ["customer notification", "customer update", "customer message", "customer communication"])),
            ("executive notification sent",           any(x in plan_lower for x in ["executive", "exec briefing", "vp ", "cto", "ciso", "board"])),
            ("regulator notification sent",           any(x in plan_lower for x in ["regulator", "fca", "pra", "ico", "supervisory authority", "regulatory notification"])),
            ("technical team notification sent",      any(x in plan_lower for x in ["technical team", "pagerduty", "on-call", "engineer notification", "#incident-response"])),
            ("vendor notification sent",              any(x in plan_lower for x in ["vendor", "third-party notification", "paybridge", "aws", "cloudflare"])),
            ("audience-appropriate tone",             any(x in plan_lower for x in ["plain english", "empathetic", "no jargon", "compliance-focused", "business impact", "tone"])),
            ("30-minute update cadence",              any(x in plan_lower for x in ["30 minute", "30-minute", "update cadence", "regular update", "every 30"])),
        ]
        scores["stakeholder_communications"] = self._score_checks(comms_checks)

        # -------------------------------------------------------------------
        # Dimension 7: Regulatory Compliance (5%)
        # Checks: specific regulations cited, deadlines tracked, notifications timed
        # -------------------------------------------------------------------
        regulatory_checks = [
            ("gdpr art 33 referenced",                any(x in plan_lower for x in ["gdpr", "art 33", "art. 33", "72 hour", "72-hour", "ico", "data protection"])),
            ("pci-dss 12.10 referenced",              any(x in plan_lower for x in ["pci-dss", "pci dss", "12.10", "card brand", "visa", "mastercard"])),
            ("sox referenced (if applicable)",        any(x in plan_lower for x in ["sox", "sarbanes", "itgc", "material weakness", "financial reporting"])),
            ("notification deadlines tracked",        any(x in plan_lower for x in ["deadline", "72 hour", "24 hour", "notification window", "clock", "ffiec"])),
            ("regulatory framework cited",            any(x in plan_lower for x in ["ffiec", "fca sysc", "iso 22301", "nist csf", "nist sp 800", "regulatory framework"])),
        ]
        scores["regulatory_compliance"] = self._score_checks(regulatory_checks)

        # -------------------------------------------------------------------
        # Scenario-specific bonuses (up to +15 points on overall)
        # -------------------------------------------------------------------
        scenario_bonus = self._score_scenario_bonus(plan_lower, scenario)

        # -------------------------------------------------------------------
        # Framework mastery bonus (up to +5 points)
        # References to professional frameworks demonstrate depth of knowledge
        # -------------------------------------------------------------------
        framework_mentions = [
            "itil 4", "iso 22301", "nist csf", "nist sp 800-61", "mitre att&ck",
            "three ways", "calms", "devops", "drii", "cbcp", "cissp", "gcih",
            "ffiec bcm", "pci-dss v4", "gdpr", "sox section 404",
        ]
        framework_hits = sum(1 for f in framework_mentions if f in plan_lower)
        framework_bonus = min(5, framework_hits)

        # -------------------------------------------------------------------
        # Weighted overall KPI score
        # -------------------------------------------------------------------
        weighted_score = sum(
            scores[dim] * weight for dim, weight in self.WEIGHTS.items()
        )
        overall = min(100, round(weighted_score + scenario_bonus + framework_bonus, 1))

        # Grade assignment
        grade = self._assign_grade(overall)

        result = {
            "scenario": scenario,
            "dimension_scores": {k: round(v, 1) for k, v in scores.items()},
            "scenario_bonus": scenario_bonus,
            "framework_mastery_bonus": framework_bonus,
            "overall_kpi_score": overall,
            "grade": grade,
            # Legacy compatibility fields
            "rto_met": any(x in plan_lower for x in ["rto met", "within 4 hours", "under 240 minutes", "rto achieved"]),
            "rpo_met": any(x in plan_lower for x in ["rpo met", "15 minutes", "rpo 15m", "recovery point 15", "zero data loss"]),
            "services_restored_pct": 95 if scores["service_recovery"] >= 80 else 70 if scores["service_recovery"] >= 50 else 40,
            "customer_impact_score": round(100 - (100 - scores["stakeholder_communications"]) * 0.6, 1),
            "total_recovery_cost": 98_000 if scores["service_recovery"] >= 80 else 520_000,
        }

        # Print detailed breakdown
        print("\n" + "=" * 80)
        print("  SIMULATION ENGINE EVALUATION — GOLD STANDARD SCORING")
        print("=" * 80)
        print(f"  Scenario: {scenario.upper()}")
        print()
        print("  DIMENSION SCORES:")
        for dim, score in result["dimension_scores"].items():
            weight_pct = int(self.WEIGHTS[dim] * 100)
            bar = "█" * int(score / 10) + "░" * (10 - int(score / 10))
            print(f"  [{bar}] {score:5.1f}/100  ({weight_pct}% weight)  {dim.replace('_', ' ').title()}")
        print()
        print(f"  Scenario Bonus:         +{scenario_bonus} pts")
        print(f"  Framework Mastery:      +{framework_bonus} pts")
        print(f"  Overall KPI Score:       {overall}%")
        print(f"  Grade:                   {grade}")
        print("=" * 80)

        return result

    # -----------------------------------------------------------------------
    # Helper methods
    # -----------------------------------------------------------------------

    @staticmethod
    def _score_checks(checks: list) -> float:
        """Convert a list of (label, bool) tuples into a 0–100 score."""
        if not checks:
            return 0.0
        passed = sum(1 for _, result in checks if result)
        return round((passed / len(checks)) * 100, 1)

    @staticmethod
    def _assign_grade(score: float) -> str:
        if score >= 90:
            return "A — Exemplary BCM Response"
        elif score >= 80:
            return "B — Proficient"
        elif score >= 70:
            return "C — Developing"
        elif score >= 60:
            return "D — Below Standard"
        else:
            return "F — Significant Gaps"

    @staticmethod
    def _score_scenario_bonus(plan_lower: str, scenario: str) -> float:
        """
        Award scenario-specific bonus points for addressing the unique
        requirements of each incident type.
        Max: 15 points per scenario.
        """
        bonus_checks = {
            "ransomware": [
                # Ransomware: Containment, forensics, backup validation, no ransom advice
                any(x in plan_lower for x in ["encrypt", "lockbit", "ransom"]),
                any(x in plan_lower for x in ["backup", "offline backup", "rb-dr-001", "restore"]),
                any(x in plan_lower for x in ["lateral movement", "propagat", "spread"]),
                any(x in plan_lower for x in ["forensic snapshot", "disk image", "preserve"]),
                # Must NOT recommend paying ransom
                "pay the ransom" not in plan_lower and "ransom payment" not in plan_lower,
            ],
            "cloud_outage_ddos": [
                any(x in plan_lower for x in ["ddos", "volumetric", "flood", "scrubbing"]),
                any(x in plan_lower for x in ["cloudflare", "waf", "rate limit", "bgp"]),
                any(x in plan_lower for x in ["eu-west", "dr region", "failover to"]),
                any(x in plan_lower for x in ["aws", "eks", "multi-az"]),
                any(x in plan_lower for x in ["rb-net-002", "traffic", "mitigation"]),
            ],
            "data_breach": [
                any(x in plan_lower for x in ["gdpr", "72 hour", "art. 33", "ico", "dpo"]),
                any(x in plan_lower for x in ["pci", "card brand", "visa", "mastercard"]),
                any(x in plan_lower for x in ["2.3 million", "2,300,000", "exfiltrat", "pii"]),
                any(x in plan_lower for x in ["service account", "svc-reporting", "moveit", "cve-2023"]),
                any(x in plan_lower for x in ["breach notification", "data subject", "notification letter"]),
            ],
            "insider_threat": [
                any(x in plan_lower for x in ["hr", "human resources", "legal counsel", "legal hold"]),
                any(x in plan_lower for x in ["dba", "jreyes", "privileged", "database administrator"]),
                any(x in plan_lower for x in ["dropbox", "personal cloud", "dlp", "data loss prevention"]),
                any(x in plan_lower for x in ["audit log", "forensic image", "chain of custody"]),
                # HR must be engaged before account action
                any(x in plan_lower for x in ["hr and legal", "legal before", "coordinate with hr"]),
            ],
            "supply_chain": [
                any(x in plan_lower for x in ["paybridge", "payment processor", "api gateway"]),
                any(x in plan_lower for x in ["suspend", "disconnect", "api integration"]),
                any(x in plan_lower for x in ["financepay", "backup processor", "alternative processor"]),
                any(x in plan_lower for x in ["890,000 transaction", "340m", "card scheme", "card brand"]),
                any(x in plan_lower for x in ["vendor notification", "paybridge notification", "pci 12.10"]),
            ],
            "cascading_failure": [
                any(x in plan_lower for x in ["corruption", "corrupt", "transaction ledger"]),
                any(x in plan_lower for x in ["rollback", "schema", "migration", "db migration"]),
                any(x in plan_lower for x in ["reconciliation", "downstream", "cascade", "propagat"]),
                any(x in plan_lower for x in ["sox", "financial reporting", "material weakness", "itgc"]),
                any(x in plan_lower for x in ["47,000", "3-hour", "stale cache", "core banking"]),
            ],
        }

        checks_for_scenario = bonus_checks.get(scenario, [])
        if not checks_for_scenario:
            return 0.0
        passed = sum(1 for check in checks_for_scenario if check)
        return round((passed / len(checks_for_scenario)) * 15, 1)

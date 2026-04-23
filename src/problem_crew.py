"""
Problem Management Crew Assembly for FinServe Digital Bank.
Sequential process: Detection → Classification → Root Cause → Known Error → Change Proposal
"""

from crewai import Crew, Process
from src.agents import create_agents
from src.tasks import (
    task_detect_patterns,
    task_correlate_cmdb,
    task_root_cause,
    task_known_errors,
    task_change_proposals,
)


def create_problem_crew() -> Crew:
    """
    Assemble the Problem Management crew with 5 agents and 5 tasks in sequential order.
    Each task passes context to the next, implementing the ITIL 4 Problem Management lifecycle:
      1. Problem Detection (Trend Analyst)
      2. Problem Logging & Classification (CMDB Correlator)
      3. Root Cause Analysis (Root Cause Investigator)
      4. Known Error Documentation (Known Error Author)
      5. Resolution via Change (Change Proposer)
    """
    agents = create_agents()

    return Crew(
        agents=agents,
        tasks=[
            task_detect_patterns,     # 1: Trend Analyst — identify patterns
            task_correlate_cmdb,      # 2: CMDB Correlator — enrich with CI/change data
            task_root_cause,          # 3: Root Cause Investigator — determine root causes
            task_known_errors,        # 4: Known Error Author — document KE records
            task_change_proposals,    # 5: Change Proposer — produce RFCs
        ],
        process=Process.sequential,
        verbose=True,
        memory=False,
        cache=True,
    )

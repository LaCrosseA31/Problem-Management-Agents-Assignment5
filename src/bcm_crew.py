"""
BCM Crew Assembly for FinServe Incident Response Simulation.
Sequential process: Classification → SecOps → BIA → Change Management → Recovery → Communications
"""

from crewai import Crew, Process
from src.agents import create_agents
from src.tasks import (
    task_classify,
    task_secops_containment,
    task_impact_analysis,
    task_emergency_change,
    task_recovery,
    task_communications,
)


def create_bcm_crew() -> Crew:
    """
    Assemble the full BCM crew with all 6 agents and 6 tasks in sequential order.
    Each task feeds context into the next, modelling a real incident response pipeline.
    """
    agents = create_agents()

    return Crew(
        agents=agents,
        tasks=[
            task_classify,             # 1: Incident Classification Specialist
            task_secops_containment,   # 2: SecOps Analyst — containment & forensics
            task_impact_analysis,      # 3: Business Impact Analyst — BIA
            task_emergency_change,     # 4: Change & Release Manager — e-CAB governance
            task_recovery,             # 5: Recovery Engineer — DR failover & validation
            task_communications,       # 6: Stakeholder Communicator — all channels
        ],
        process=Process.sequential,
        verbose=True,
        memory=False,
        cache=True,
    )

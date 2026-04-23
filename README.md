# FinServe Digital Bank – BCM Agent Simulation (CrewAI)

Starter repo for the **Agent-Driven Business Continuity Management Challenge**.

**What students do:**
- Customize the 4 agents in `src/agents.py`
- Refine tasks & tools
- Run `python main.py` when the instructor triggers a live event
- Their agents automatically detect, assess, recover, and communicate

**Frameworks practiced:** ITIL 4 Service Continuity, DevOps CALMS + Three Ways, Agent-Based Modeling principles.

## Setup (students + instructor)
1. `git clone https://github.com/YOUR-USERNAME/itsm-devops-bcm-crewai-starter.git`
2. `cd itsm-devops-bcm-crewai-starter`
3. `pip install -r requirements.txt`
4. Copy `.env.example` → `.env` and add your API key (instructor will provide a shared Groq or OpenAI key)
5. Run: `python main.py`

Instructor runs surprise events by editing `EVENT_SCENARIO` in `main.py`.
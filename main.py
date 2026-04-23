"""
FinServe Problem Management — Main Entry Point
Loads CSV data paths, runs the Problem Management crew, and saves the final report.
"""

import os
from dotenv import load_dotenv
from src.problem_crew import create_problem_crew

load_dotenv()

# ---------------------------------------------------------------------------
# Data paths (tools resolve these automatically from BASE_DIR)
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
OUTPUT_DIR = os.path.join(BASE_DIR, "output")

# Ensure output directory exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Set environment variables for tools
os.environ["FINSERVE_DATA_DIR"] = DATA_DIR
os.environ["FINSERVE_OUTPUT_DIR"] = OUTPUT_DIR

# ---------------------------------------------------------------------------
# Verify data files exist
# ---------------------------------------------------------------------------
required_files = [
    os.path.join(DATA_DIR, "finserve_incidents_q1_2026.csv"),
    os.path.join(DATA_DIR, "finserve_cmdb.csv"),
    os.path.join(DATA_DIR, "finserve_changes.csv"),
]

for filepath in required_files:
    if not os.path.exists(filepath):
        print(f"ERROR: Required data file not found: {filepath}")
        print("Please ensure all CSV files are in the data/ directory.")
        exit(1)

# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------

print("=" * 80)
print("  FINSERVE PROBLEM MANAGEMENT — AGENT-DRIVEN ANALYSIS")
print("  From Incident Noise to Root Cause Intelligence")
print("=" * 80)
print(f"\nData directory: {DATA_DIR}")
print(f"Output directory: {OUTPUT_DIR}")
print(f"\nData files:")
for f in required_files:
    print(f"  - {os.path.basename(f)}")
print("\n" + "=" * 80)
print("  Activating Problem Management Crew...")
print("  Pipeline: Detection → Classification → Root Cause → Known Error → RFC")
print("=" * 80 + "\n")

crew = create_problem_crew()
result = crew.kickoff()

print("\n" + "=" * 80)
print("  FINAL PROBLEM MANAGEMENT REPORT:")
print("=" * 80)
print(result)
print("=" * 80)

# Save final report to output directory
report_path = os.path.join(OUTPUT_DIR, "problem_management_report.md")
with open(report_path, "w", encoding="utf-8") as f:
    f.write("# FinServe Problem Management Report — Q1 2026\n\n")
    f.write("## Agent-Driven Analysis Results\n\n")
    f.write(str(result))

print(f"\nFull report saved to: {report_path}")
print(f"\nOutput files generated in: {OUTPUT_DIR}")

# List generated output files
if os.path.exists(OUTPUT_DIR):
    output_files = os.listdir(OUTPUT_DIR)
    if output_files:
        print("\nGenerated output files:")
        for fname in sorted(output_files):
            print(f"  - {fname}")
    else:
        print("\nNo output files generated.")

print("\n" + "=" * 80)
print("  Problem Management analysis complete.")
print("=" * 80)

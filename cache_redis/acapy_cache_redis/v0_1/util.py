from acapy_agent.protocols.problem_report.v1_0.message import (
    ProblemReport as report,
)


def ProblemReport(description: dict):
    try:
        return report(description=description)
    except TypeError:
        return report(explain_ltxt=description["en"])

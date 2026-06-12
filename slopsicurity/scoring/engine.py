"""Scoring engine: aggregates findings into a total score and letter grade."""
from dataclasses import dataclass
from enum import Enum
from typing import List

from slopsicurity.scanners.base import ScanResult, Finding


class Grade(str, Enum):
    A_PLUS = "A+"
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"

    @property
    def description(self) -> str:
        return {
            "A+": "Excellent — industry-leading security posture",
            "A":  "Strong — most best practices followed",
            "B":  "Good — a few gaps worth addressing",
            "C":  "Fair — notable issues present",
            "D":  "Poor — significant vulnerabilities exposed",
            "F":  "Critical — serious security failures",
        }[self.value]

    @property
    def color(self) -> str:
        return {
            "A+": "\033[92m",  # bright green
            "A":  "\033[92m",
            "B":  "\033[93m",  # yellow
            "C":  "\033[93m",
            "D":  "\033[91m",  # red
            "F":  "\033[91m",
        }[self.value]


@dataclass
class ScoreReport:
    url: str
    total_score: int
    max_score: int
    percentage: float
    grade: Grade
    scan_results: List[ScanResult]

    @property
    def all_findings(self) -> List[Finding]:
        findings = []
        for sr in self.scan_results:
            findings.extend(sr.findings)
        return findings

    @property
    def failures(self) -> List[Finding]:
        return [f for f in self.all_findings if not f.passed and f.max_score > 0]

    @property
    def passes(self) -> List[Finding]:
        return [f for f in self.all_findings if f.passed and f.max_score > 0]


def _assign_grade(pct: float) -> Grade:
    if pct >= 95:
        return Grade.A_PLUS
    elif pct >= 80:
        return Grade.A
    elif pct >= 65:
        return Grade.B
    elif pct >= 50:
        return Grade.C
    elif pct >= 30:
        return Grade.D
    else:
        return Grade.F


def score_results(url: str, scan_results: List[ScanResult]) -> ScoreReport:
    total = sum(sr.score for sr in scan_results)
    maximum = sum(sr.max_score for sr in scan_results)
    pct = (total / maximum * 100) if maximum > 0 else 0.0
    grade = _assign_grade(pct)
    return ScoreReport(
        url=url,
        total_score=total,
        max_score=maximum,
        percentage=round(pct, 1),
        grade=grade,
        scan_results=scan_results,
    )

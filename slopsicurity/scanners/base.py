"""Base scanner class all scanners inherit from."""
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Finding:
    """A single security finding from a scanner."""
    check_id: str          # e.g. "ssl_valid"
    category: str          # e.g. "SSL/TLS"
    label: str             # Human-readable name
    passed: bool
    score: int             # Points earned
    max_score: int         # Max possible points
    detail: str            # What was found
    recommendation: Optional[str] = None  # What to do if failed


@dataclass
class ScanResult:
    """Output from a single scanner module."""
    scanner_name: str
    findings: list[Finding] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def score(self) -> int:
        return sum(f.score for f in self.findings)

    @property
    def max_score(self) -> int:
        return sum(f.max_score for f in self.findings)


class BaseScanner:
    """All scanners extend this."""
    name: str = "base"

    def __init__(self, target: str, session):
        """
        Args:
            target: The URL being scanned (normalized, e.g. https://example.com)
            session: A requests.Session for HTTP calls
        """
        self.target = target
        self.session = session

    def run(self) -> ScanResult:
        raise NotImplementedError

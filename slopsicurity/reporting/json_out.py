"""JSON report serializer."""
import json
import re
from slopsicurity.scoring.engine import ScoreReport
from slopsicurity.reporting.snippets import get_snippet


def _detected_servers(report: ScoreReport) -> set:
    """
    Build a normalised set of server/framework keys from the tech scanner findings.
    These keys match the server priority list in snippets.py.
    """
    servers: set[str] = set()
    for sr in report.scan_results:
        if sr.scanner_name != "Technology Detection":
            continue
        for f in sr.findings:
            # check_id format: tech_nginx, tech_apache, tech_cloudflare, tech_django, etc.
            if not f.check_id.startswith("tech_"):
                continue
            key = f.check_id.removeprefix("tech_")
            # Normalise multi-word names
            key = re.sub(r'[^a-z0-9]', '_', key).strip('_')
            servers.add(key)
    return servers


def report_to_json(report: ScoreReport, indent: int = 2) -> str:
    servers = _detected_servers(report)

    data = {
        "url": report.url,
        "score": {
            "total":             report.total_score,
            "max":               report.max_score,
            "percentage":        report.percentage,
            "grade":             report.grade.value,
            "grade_description": report.grade.description,
        },
        "scanners":       [],
        "recommendations": [],
    }

    for sr in report.scan_results:
        data["scanners"].append({
            "name":      sr.scanner_name,
            "score":     sr.score,
            "max_score": sr.max_score,
            "error":     sr.error,
            "findings": [
                {
                    "check_id":       f.check_id,
                    "category":       f.category,
                    "label":          f.label,
                    "passed":         f.passed,
                    "score":          f.score,
                    "max_score":      f.max_score,
                    "detail":         f.detail,
                    "recommendation": f.recommendation,
                }
                for f in sr.findings
            ],
        })

    for f in sorted(report.failures, key=lambda x: -x.max_score):
        data["recommendations"].append({
            "check_id":      f.check_id,
            "label":         f.label,
            "impact_points": f.max_score,
            "recommendation": f.recommendation,
            "code_snippet":  get_snippet(f.check_id, servers),
        })

    return json.dumps(data, indent=indent)

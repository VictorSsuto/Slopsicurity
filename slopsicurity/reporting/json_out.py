"""JSON report serializer."""
import json
from slopsicurity.scoring.engine import ScoreReport


def report_to_json(report: ScoreReport, indent: int = 2) -> str:
    data = {
        "url": report.url,
        "score": {
            "total": report.total_score,
            "max": report.max_score,
            "percentage": report.percentage,
            "grade": report.grade.value,
            "grade_description": report.grade.description,
        },
        "scanners": [],
        "recommendations": [],
    }

    for sr in report.scan_results:
        scanner_data = {
            "name": sr.scanner_name,
            "score": sr.score,
            "max_score": sr.max_score,
            "error": sr.error,
            "findings": [
                {
                    "check_id": f.check_id,
                    "category": f.category,
                    "label": f.label,
                    "passed": f.passed,
                    "score": f.score,
                    "max_score": f.max_score,
                    "detail": f.detail,
                    "recommendation": f.recommendation,
                }
                for f in sr.findings
            ],
        }
        data["scanners"].append(scanner_data)

    for f in sorted(report.failures, key=lambda x: -x.max_score):
        data["recommendations"].append({
            "check_id": f.check_id,
            "label": f.label,
            "impact_points": f.max_score,
            "recommendation": f.recommendation,
        })

    return json.dumps(data, indent=indent)

"""Rich terminal scoreboard output."""
from slopsicurity.scoring.engine import ScoreReport, Grade

RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
WHITE  = "\033[97m"


def _bar(score: int, max_score: int, width: int = 20) -> str:
    if max_score == 0:
        return " " * width
    filled = int(round(score / max_score * width))
    return "█" * filled + "░" * (width - filled)


def _check_icon(passed: bool) -> str:
    return f"{GREEN}✔{RESET}" if passed else f"{RED}✘{RESET}"


def print_report(report: ScoreReport) -> None:
    w = 70
    sep = "─" * w

    print(f"\n{BOLD}{CYAN}{'═' * w}{RESET}")
    print(f"{BOLD}{CYAN}  🛡  SLOPSICURITY — Security Scan Report{RESET}")
    print(f"{CYAN}{'═' * w}{RESET}")
    print(f"  Target : {WHITE}{report.url}{RESET}")
    print(f"  Score  : {BOLD}{report.grade.color}{report.total_score}/{report.max_score} "
          f"({report.percentage}%){RESET}")

    grade_color = report.grade.color
    print(f"  Grade  : {BOLD}{grade_color}{report.grade.value}{RESET}  "
          f"{DIM}{report.grade.description}{RESET}")
    print(f"  {_bar(report.total_score, report.max_score, 50)}")
    print(f"{CYAN}{'═' * w}{RESET}\n")

    # Group findings by scanner
    for sr in report.scan_results:
        if not sr.findings and not sr.error:
            continue
        print(f"{BOLD}{WHITE}  ▸ {sr.scanner_name}{RESET}")
        print(f"  {sep}")
        if sr.error:
            print(f"  {RED}  Error: {sr.error}{RESET}")
        for f in sr.findings:
            if f.max_score == 0:
                # Informational
                print(f"  {DIM}ℹ  {f.label}: {f.detail}{RESET}")
                continue
            icon = _check_icon(f.passed)
            pts = f"{GREEN}+{f.score}{RESET}" if f.passed else f"{RED}+0/{f.max_score}{RESET}"
            print(f"  {icon}  {f.label:<45} {pts}")
            print(f"     {DIM}{f.detail}{RESET}")
        print()

    # Recommendations section
    failures = report.failures
    if failures:
        print(f"{BOLD}{RED}  ⚠  Recommendations ({len(failures)} issue{'s' if len(failures) != 1 else ''}){RESET}")
        print(f"  {'═' * w}")
        for i, f in enumerate(sorted(failures, key=lambda x: -x.max_score), 1):
            impact = f"[{f.max_score} pts]"
            print(f"\n  {BOLD}{i}. {f.label} {DIM}{impact}{RESET}")
            print(f"     {DIM}→ {f.recommendation}{RESET}")
        print()

    # Summary footer
    n_pass = len(report.passes)
    n_fail = len(report.failures)
    print(f"{CYAN}{'═' * w}{RESET}")
    print(f"  {GREEN}✔ {n_pass} checks passed{RESET}   {RED}✘ {n_fail} checks failed{RESET}")
    print(f"{CYAN}{'═' * w}{RESET}\n")

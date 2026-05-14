import sys
from pathlib import Path

from pe_parser import analyze_pe
from heuristics import (
    analyze_imports,
    calculate_score,
    get_priority
)
from report import generate_report


def build_report_path(file_path):
    sample_name = Path(file_path).stem
    return f"reports/{sample_name}_report.md"


def main():

    if len(sys.argv) < 2:
        print("Usage: python main.py <exe>")
        return

    file_path = sys.argv[1]

    pe_info = analyze_pe(file_path)

    findings = analyze_imports(pe_info["imports"])

    score = calculate_score(findings)

    priority = get_priority(score)

    report = generate_report(
        file_path,
        pe_info,
        findings,
        score,
        priority
    )

    print(report)

    report_path = build_report_path(file_path)

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)

    print(f"\n[+] Report saved to {report_path}")


if __name__ == "__main__":
    main()
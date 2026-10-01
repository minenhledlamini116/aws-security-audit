"""Run all security checks against an AWS account and print a report."""
import argparse
import json
import sys

import boto3

from checks import ALL_CHECKS

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def run_audit(session):
    findings = []
    for check in ALL_CHECKS:
        try:
            findings.extend(check(session))
        except Exception as err:
            # A failed check (for example missing permissions) should not stop the audit.
            findings.append({
                "check": check.__name__,
                "resource": "-",
                "severity": "LOW",
                "detail": f"Check could not run: {err}",
            })
    return sorted(findings, key=lambda f: SEVERITY_ORDER[f["severity"]])


def print_report(findings):
    if not findings:
        print("No issues found.")
        return
    for f in findings:
        print(f"[{f['severity']}] {f['check']}: {f['resource']} - {f['detail']}")
    print(f"\n{len(findings)} finding(s).")


def main():
    parser = argparse.ArgumentParser(description="Audit an AWS account for common security issues")
    parser.add_argument("--profile", help="AWS profile name to use")
    parser.add_argument("--region", default="eu-west-1")
    parser.add_argument("--json", action="store_true", help="Print results as JSON")
    args = parser.parse_args()

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    findings = run_audit(session)

    if args.json:
        print(json.dumps(findings, indent=2))
    else:
        print_report(findings)

    # A non-zero exit code lets a pipeline fail when serious issues exist.
    sys.exit(1 if any(f["severity"] == "HIGH" for f in findings) else 0)


if __name__ == "__main__":
    main()

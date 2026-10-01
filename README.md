# AWS Security Audit

A small Python tool that scans an AWS account for common security mistakes and prints a prioritized report. It only reads from the account and never changes anything.

## What it checks

| Check | Severity | What it looks for |
|---|---|---|
| S3 public access | HIGH | Buckets that do not block all public access |
| Open SSH | HIGH | Security groups that allow SSH from anywhere on the internet |
| IAM MFA | MEDIUM | IAM users with no multi-factor login |

## Example output

```
[HIGH] s3_public_access: my-demo-bucket - Bucket does not block all public access
[HIGH] open_ssh: sg-0abc123 - Security group allows SSH from anywhere
[MEDIUM] iam_mfa: alice - User has no MFA device

3 finding(s).
```

## How it works

- `checks.py` holds one function per check. Each returns a list of findings.
- `audit.py` runs every check, sorts the results by severity, and prints a report.
- A failed check, for example from missing permissions, is reported and does not stop the rest.
- The exit code is 1 when a HIGH finding exists, so a pipeline can block a risky deployment.

## Run it

```
pip install -r requirements.txt
python audit.py --profile my-profile --region eu-west-1
```

Add `--json` for machine-readable output.

For least privilege, run it with a user or role that only has the AWS managed `SecurityAudit` policy.

## Tests

The tests use [moto](https://github.com/getmoto/moto) to fake AWS, so they cost nothing and touch no real account. Each check has one test for a bad setup that should be flagged and one for a safe setup that should pass.

```
pytest -v
```

GitHub Actions runs the tests on every push.

## Adding a check

1. Write a function in `checks.py` that takes a boto3 session and returns findings.
2. Add it to the `ALL_CHECKS` list.
3. Add a test for it.

## Ideas for next steps

- More checks, such as unencrypted EBS volumes and old access keys
- An HTML report
- Scheduled runs with Lambda and EventBridge

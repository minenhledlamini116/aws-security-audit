"""Security checks. Each check takes a boto3 session and returns a list of findings."""
from botocore.exceptions import ClientError


def finding(check, resource, severity, detail):
    return {"check": check, "resource": resource, "severity": severity, "detail": detail}


def check_s3_public_access(session):
    s3 = session.client("s3")
    findings = []
    for bucket in s3.list_buckets()["Buckets"]:
        name = bucket["Name"]
        try:
            cfg = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            fully_blocked = all(cfg.values())
        except ClientError:
            fully_blocked = False
        if not fully_blocked:
            findings.append(finding("s3_public_access", name, "HIGH",
                                    "Bucket does not block all public access"))
    return findings


def check_iam_mfa(session):
    iam = session.client("iam")
    findings = []
    for page in iam.get_paginator("list_users").paginate():
        for user in page["Users"]:
            name = user["UserName"]
            if not iam.list_mfa_devices(UserName=name)["MFADevices"]:
                findings.append(finding("iam_mfa", name, "MEDIUM", "User has no MFA device"))
    return findings


def check_open_ssh(session):
    ec2 = session.client("ec2")
    findings = []
    for sg in ec2.describe_security_groups()["SecurityGroups"]:
        for rule in sg["IpPermissions"]:
            open_to_world = any(r.get("CidrIp") == "0.0.0.0/0" for r in rule.get("IpRanges", []))
            from_port = rule.get("FromPort", 0)
            to_port = rule.get("ToPort", 65535)
            if open_to_world and from_port <= 22 <= to_port:
                findings.append(finding("open_ssh", sg["GroupId"], "HIGH",
                                        "Security group allows SSH from anywhere"))
    return findings


ALL_CHECKS = [check_s3_public_access, check_iam_mfa, check_open_ssh]

import boto3
from moto import mock_aws

from checks import check_iam_mfa, check_open_ssh, check_s3_public_access

REGION = "eu-west-1"


def make_session():
    return boto3.Session(
        region_name=REGION,
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )


@mock_aws
def test_s3_flags_bucket_without_public_access_block():
    s3 = make_session().client("s3")
    s3.create_bucket(
        Bucket="open-bucket",
        CreateBucketConfiguration={"LocationConstraint": REGION},
    )
    findings = check_s3_public_access(make_session())
    assert [f["resource"] for f in findings] == ["open-bucket"]


@mock_aws
def test_s3_passes_bucket_with_full_block():
    s3 = make_session().client("s3")
    s3.create_bucket(
        Bucket="safe-bucket",
        CreateBucketConfiguration={"LocationConstraint": REGION},
    )
    s3.put_public_access_block(
        Bucket="safe-bucket",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    assert check_s3_public_access(make_session()) == []


@mock_aws
def test_iam_flags_user_without_mfa():
    iam = make_session().client("iam")
    iam.create_user(UserName="alice")
    findings = check_iam_mfa(make_session())
    assert [f["resource"] for f in findings] == ["alice"]


@mock_aws
def test_open_ssh_is_flagged():
    ec2 = make_session().client("ec2")
    sg = ec2.create_security_group(GroupName="open-ssh", Description="test")
    ec2.authorize_security_group_ingress(
        GroupId=sg["GroupId"],
        IpPermissions=[{
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }],
    )
    findings = check_open_ssh(make_session())
    assert [f["resource"] for f in findings] == [sg["GroupId"]]


@mock_aws
def test_restricted_ssh_is_not_flagged():
    ec2 = make_session().client("ec2")
    sg = ec2.create_security_group(GroupName="closed-ssh", Description="test")
    ec2.authorize_security_group_ingress(
        GroupId=sg["GroupId"],
        IpPermissions=[{
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
        }],
    )
    assert check_open_ssh(make_session()) == []

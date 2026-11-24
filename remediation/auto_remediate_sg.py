"""
Auto-remediation Lambda: removes world-open SSH/RDP from Security Groups.

Triggered by EventBridge. Supports two event shapes:
  1. AWS Config   -> "Config Rules Compliance Change"
                     (detail.resourceId = sg-xxxx)
  2. Security Hub -> "Security Hub Findings - Imported"
                     (detail.findings[].Resources[].Id = arn:...:security-group/sg-xxxx)

Execution role needs:
  ec2:DescribeSecurityGroups, ec2:RevokeSecurityGroupIngress
  + AWSLambdaBasicExecutionRole (CloudWatch Logs)
"""
import json
import logging

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ec2 = boto3.client("ec2")

RISKY_PORTS = (22, 3389)  # SSH, RDP
OPEN_IPV4 = "0.0.0.0/0"
OPEN_IPV6 = "::/0"


def extract_sg_id(event):
    """Return the Security Group ID from a Config or Security Hub event."""
    detail = event.get("detail", {})

    # AWS Config event
    resource_id = detail.get("resourceId", "")
    if resource_id.startswith("sg-"):
        return resource_id

    # Security Hub (ASFF) event
    for finding in detail.get("findings", []):
        for resource in finding.get("Resources", []):
            arn = resource.get("Id", "")
            if ":security-group/sg-" in arn:
                return arn.split("/")[-1]

    return None


def exposes_risky_port(rule):
    """True if the rule covers SSH/RDP, including port ranges and all-traffic rules."""
    protocol = rule.get("IpProtocol")
    if protocol == "-1":  # all traffic: the API omits FromPort/ToPort
        return True
    if protocol != "tcp":
        return False
    low, high = rule.get("FromPort"), rule.get("ToPort")
    return low is not None and high is not None and any(low <= p <= high for p in RISKY_PORTS)


def build_revoke_request(rule):
    """Build a request that removes ONLY the world-open CIDRs from this rule,
    so legitimate entries in the same rule (e.g. an office IP) are kept."""
    request = {"IpProtocol": rule["IpProtocol"]}
    if "FromPort" in rule:
        request["FromPort"] = rule["FromPort"]
        request["ToPort"] = rule["ToPort"]

    if any(r.get("CidrIp") == OPEN_IPV4 for r in rule.get("IpRanges", [])):
        request["IpRanges"] = [{"CidrIp": OPEN_IPV4}]
    if any(r.get("CidrIpv6") == OPEN_IPV6 for r in rule.get("Ipv6Ranges", [])):
        request["Ipv6Ranges"] = [{"CidrIpv6": OPEN_IPV6}]

    return request if ("IpRanges" in request or "Ipv6Ranges" in request) else None


def lambda_handler(event, context):
    logger.info("Received event: %s", json.dumps(event))

    sg_id = extract_sg_id(event)
    if not sg_id:
        logger.info("No Security Group ID found - skipping")
        return {"status": "skipped"}

    try:
        sg = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]
    except ClientError as err:
        # e.g. InvalidGroup.NotFound if the SG was deleted before we ran
        logger.error("Cannot describe %s: %s", sg_id, err)
        return {"status": "error", "securityGroup": sg_id}

    remediated = 0
    for rule in sg.get("IpPermissions", []):
        if not exposes_risky_port(rule):
            continue

        request = build_revoke_request(rule)
        if request is None:
            continue

        try:
            ec2.revoke_security_group_ingress(GroupId=sg_id, IpPermissions=[request])
            remediated += 1
            logger.info("REMEDIATED %s: %s", sg_id, json.dumps(request))
        except ClientError as err:
            # Re-raise here instead if you want Lambda retries / a DLQ to catch failures
            logger.error("Failed to revoke on %s: %s", sg_id, err)

    return {"status": "ok", "securityGroup": sg_id, "rulesRemediated": remediated}

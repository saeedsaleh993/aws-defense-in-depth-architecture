# Secure Multi-Tier Architecture with GuardDuty, KMS & Security Hub

## Overview
This solution implements a **Defense-in-Depth** security architecture for a highly available, three-tier web application (Web, Application, and Data tiers) on AWS. Built in alignment with the **AWS Well-Architected Framework (Security Pillar)**, the architecture enforces encryption at rest and in transit, automated credential rotation, continuous threat detection, compliance auditing against CIS AWS Foundations Benchmarks, and automated incident response.

---

## Architecture Diagram

![Secure Multi-Tier Architecture](./architecture/secure-3tier-architecture.png)

---

## Security Layers & Key AWS Services

### 1. Network Isolation & Edge Protection
* **Amazon VPC (Multi-AZ):** Segmented into Public Subnets (ALB & NAT Gateways), Private Subnets (Application Tier EC2 instances), and Isolated Private Subnets (RDS Multi-AZ Database) across two Availability Zones.
* **AWS WAF & AWS Shield Standard:** Deployed at the edge in front of the Application Load Balancer (ALB) to mitigate DDoS attacks and block OWASP Top 10 threats (SQL Injection, Cross-Site Scripting).
* **AWS Systems Manager (Session Manager):** Replaces traditional SSH/RDP bastion hosts, allowing auditable shell access with zero inbound ports open (`0.0.0.0/0` blocked).

### 2. Identity, Governance & Encryption
* **AWS Organizations & SCPs:** Enforces organization-wide guardrails, including an explicit Service Control Policy (`deny-root-scp.json`) restricting root user actions.
* **IAM Least Privilege & Permission Boundaries:** Scopes EC2 instance profiles and Lambda execution roles strictly to required resources.
* **AWS KMS (Customer Managed Keys - CMKs):** Encrypts data at rest across Amazon RDS, EBS volumes, S3 audit buckets, and Secrets Manager.
* **AWS Secrets Manager:** Stores database credentials securely and executes automated 30-day credential rotation via AWS Lambda.

### 3. Threat Detection & Compliance Auditing
* **AWS CloudTrail:** Multi-region API activity logging delivered to an encrypted, versioned S3 bucket with log file integrity validation enabled.
* **Amazon GuardDuty:** Continuous threat intelligence monitoring for reconnaissance, compromised instances, and unusual API calls.
* **AWS Config:** Tracks configuration drift and evaluates resource compliance (e.g., detecting publicly accessible S3 buckets or unrestricted Security Groups).
* **AWS Security Hub:** Aggregates findings from GuardDuty and AWS Config into a single dashboard mapped to the **CIS AWS Foundations Benchmark**.

### 4. Automated Incident Response
* **Amazon EventBridge & AWS Lambda:** Captures high-severity Security Hub / AWS Config findings in real time and triggers a Python remediation function (`auto_remediate_sg.py`) to revoke unauthorized ingress rules automatically.

---

## Repository Structure

```text
├── architecture/       # High-resolution architecture diagram and draw.io source file
├── policies/           # IAM least-privilege policies, SCPs, and KMS key policies (JSON)
├── remediation/        # Python (Boto3) Lambda script for automated threat remediation
└── README.md           # Project documentation and deployment guide
```

---

## Deployment Walkthrough

1. **Network & Compute Foundation:**
   * Provision a VPC across 2 Availability Zones with Public, Private, and Isolated Subnets.
   * Deploy an Internet-facing ALB protected by an AWS WAF Web ACL.
   * Configure an Auto Scaling Group of EC2 instances in Private Subnets attached to an SSM-enabled IAM Role.
   * Launch a Multi-AZ RDS instance in Isolated Subnets encrypted with a KMS CMK.
2. **Secrets & Auditing Setup:**
   * Store RDS credentials in AWS Secrets Manager and enable automatic rotation.
   * Enable multi-region AWS CloudTrail with log file validation pointing to an encrypted S3 bucket.
3. **Security Monitoring & Remediation:**
   * Activate Amazon GuardDuty, AWS Config, and AWS Security Hub (CIS Benchmark standard).
   * Deploy the `auto_remediate_sg.py` Lambda function and connect it to an EventBridge rule filtering non-compliant Security Group events.

---

## Cost Management & Cleanup
To avoid ongoing AWS charges after testing and demonstration, terminate resources in reverse order:
1. Delete the Auto Scaling Group, ALB, and RDS Multi-AZ instance.
2. Release Elastic IPs and delete NAT Gateways.
3. Disable AWS Config recording, GuardDuty, and Security Hub.
4. Schedule deletion for KMS Customer Managed Keys (minimum 7-day waiting period) and delete S3 log buckets.

---

## Author
**Eng. Saeed Elsayed Saleh**  
Cloud & Network Security Engineer  
LinkedIn: [linkedin.com/in/saeed-saleh](https://www.linkedin.com/in/saeed-saleh)

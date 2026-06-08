# Cloud Security Lab

This repo is where I've been building out my practical AWS security skills, starting from the fundamentals and working up to something I'm genuinely proud of.

The project has two parts. The `lab/` directory is a series of hands-on labs I worked through to get comfortable with AWS security basics: hardening the root account, setting up IAM properly, enforcing MFA, and getting CloudTrail logging in place. That foundation matters because everything in CloudSweeper runs against a real AWS environment, and those labs are what made it possible.

The main project is **CloudSweeper**.

---

## What is CloudSweeper?

CloudSweeper is a cloud security framework I built to simulate realistic attacker behaviour in AWS, detect that behaviour using real telemetry, and automate an initial response. The whole thing runs against a live AWS account, not a sandbox, not mocked data.

The idea came from wanting to understand both sides of cloud security properly. It's one thing to know that IAM misconfiguration is dangerous. It's another to actually simulate an attacker exploiting it, watch the logs come in, and build a detection rule that catches it. That's what this project does.

---

## The three components

### 1. Attack Simulation Engine
A set of Python modules that simulate attacker techniques mapped to the [MITRE ATT&CK framework](https://attack.mitre.org/). Each technique makes real AWS API calls, the same calls a real attacker would make, so the logs it generates are authentic CloudTrail data and not fabricated events.

The techniques I've implemented so far:
- **IAM Reconnaissance** - mapping out users, roles, groups, and attached policies (T1087.004)
- **S3 Enumeration** - discovering buckets and checking access controls (T1530)
- **Privilege Escalation** - abusing PassRole and AssumeRole to move to a higher-privileged identity (T1484.001)

Every module is built on a shared base class, so adding new techniques later is straightforward.

### 2. Detection Engine
This is the defensive side. It pulls CloudTrail logs from S3, runs them through a set of detection rules, and produces structured alerts ranked by severity. Each alert maps back to the MITRE ATT&CK technique that triggered it, which makes the output actually useful rather than just a list of API calls.

The rules I've built target the exact techniques in the simulation engine: recon spikes, privilege escalation chains, and S3 enumeration patterns.

### 3. Response Automation Layer
Once an alert fires, the response layer decides what to do about it. I've kept this lean but functional: it can revoke compromised credentials, and it generates a structured incident report in both JSON and Markdown. Everything runs in dry-run mode by default so nothing touches live resources unless I explicitly turn it on.

---

## Live output

This is the IAM recon module running against my real AWS account. It mapped the full IAM landscape in one run: 2 users, 2 roles, 3 groups, group policy assignments, and the target user's group membership. 12 findings total, 10 API calls.

![IAM recon live output](docs/screenshots/iam_recon_findings.webp)

---

## Setup

```bash
git clone https://github.com/toluda17/Cloud-Security-Lab.git
cd Cloud-Security-Lab
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Open `.env` and fill in your AWS account ID and credentials. Then configure the AWS CLI:

```bash
aws configure
```

Verify your identity before running anything:

```bash
aws sts get-caller-identity
```

---

## Running the simulation

Each TTP module can be run individually. For example, to run the IAM recon simulation:

```python
from cloudsweeper.attack.iam_recon import IAMRecon

recon = IAMRecon()
result = recon.execute()

print('status:', result.status.value)
print('findings:', len(result.findings))
for f in result.findings:
    print(' -', f['type'], ':', f.get('username') or f.get('role_name') or f.get('group_name', ''))
```

---

## Lab foundations

Before any of this existed, I spent time getting the AWS environment into a state where it was actually worth attacking. The `lab/` directory documents that work:

- **Step 1** - Root account hardening: strong password, MFA, billing alerts, switching to an IAM admin user for day-to-day work
- **Step 2** - IAM foundations: group-based access control for Admins, Developers, and Auditors with least-privilege policies attached
- **Step 3** - MFA enforcement and credential hygiene: account-wide password policy, virtual MFA on all IAM users
- **Step 4** - Logging and monitoring: multi-region CloudTrail trail with log file validation, AWS Config recorder, S3 bucket with the right policies to accept logs from both services

The IAM structure and CloudTrail bucket from those labs are what CloudSweeper runs against. The `DemoDev` user created in Step 2 is the simulated attacker identity.

---

## Status

Actively being built. Current progress:

| Module | Status |
|---|---|
| `ttp_base.py` - TTP base class | done |
| `iam_recon.py` - IAM reconnaissance (T1087.004) | done |
| `s3_enum.py` - S3 enumeration (T1530) | in progress |
| `privilege_escalation.py` - PassRole/AssumeRole abuse (T1484.001) | coming |
| Detection engine | coming |
| Response automation layer | coming |

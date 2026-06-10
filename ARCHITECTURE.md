# CloudSweeper Architecture

This document explains how CloudSweeper is structured and why I made the decisions I did. It's meant to be useful both as a reference and as something I can walk through in an interview.

---

## Overview

CloudSweeper has three layers that feed into each other:

```
Attack Simulation Engine
        |
        v
   AWS CloudTrail
        |
        v
  Detection Engine
        |
        v
 Response Automation
```

The simulation makes real AWS API calls. Those calls generate real CloudTrail logs. The detection engine reads those logs and fires alerts. The response layer acts on those alerts and writes a report.

---

## Layer 1: Attack Simulation Engine

**Location:** `cloudsweeper/attack/`

All attack modules inherit from `TTP` in `ttp_base.py`. The base class enforces three things on every module: a `ttp_id`, a `mitre_id`, and a `mitre_tactic`. You literally can't instantiate a TTP without a MITRE technique ID attached to it.

Each module implements `execute()`, which makes the actual AWS API calls and returns a `TTPresult`: a structured object containing the findings, the API calls made, and the status.

| Module | Technique | What it does |
|---|---|---|
| `iam_recon.py` | T1087.004 | Lists users, roles, groups, and the target user's permissions |
| `s3_enum.py` | T1530 | Finds buckets, checks access controls, lists objects |
| `privilege_escalation.py` | T1484.001 | Checks for assumable roles and attempts AssumeRole |

`runner.py` runs all three in sequence with a shared `run_id` so everything from the same simulation can be traced together in logs and reports.

---

## Layer 2: Detection Engine

**Location:** `cloudsweeper/detection/`

The detection engine has four components that work in sequence:

**`log_ingestor.py`** fetches CloudTrail log files from S3, decompresses them (CloudTrail writes gzipped JSON), and returns a flat list of event dicts. There's also a `load_from_file()` method for testing offline with the sample data in `sample_data/cloudtrail_sample.json`.

**`rule_engine.py`** runs every detection rule against the event list and collects the results. Rules are just functions: to add a new one, write a function that takes a list of events and returns a list of alert dicts, then add it to the `RULES` list in `rule_engine.py`.

**Detection rules** live in `cloudsweeper/detection/rules/`. Each file covers one TTP:

| Rule file | Technique | What triggers it |
|---|---|---|
| `recon_rules.py` | T1087.004 | Spike of IAM read calls from one identity above the threshold |
| `data_access_rules.py` | T1530 | Spike of S3 list calls from one identity above the threshold |
| `privesc_rules.py` | T1484.001 | Multiple AssumeRole calls, or any AssumeRole from an IAM user |

**`alert_generator.py`** takes the raw rule output, adds timestamps, and sorts by severity. **`mitre_mapper.py`** enriches each alert with the full technique name, tactic, and a link to the ATT&CK page.

---

## Layer 3: Response Automation

**Location:** `cloudsweeper/response/`

**`response_dispatcher.py`** is the entry point. It routes HIGH and CRITICAL alerts to the credential revoker, then calls the report generator regardless of what else ran.

**`credential_revoker.py`** disables all active IAM access keys for the flagged identity. It runs in dry-run mode by default so nothing gets touched during demos: set `DRY_RUN=false` in `.env` to enable live remediation.

**`report_generator.py`** writes two files to `reports/`: a JSON report for machine readability and a Markdown report for humans. Both include the full alert list, MITRE details, and a record of any response actions taken.

---

## Utilities

**`cloudsweeper/utils/aws_client.py`**: single boto3 session with a client cache. Every module gets clients from here so credential handling is consistent across the whole framework.

**`cloudsweeper/utils/logger.py`**: structured JSON logging in production, colour-coded human-readable output in debug mode.

**`cloudsweeper/config.py`**: all environment config in one place, loaded from `.env`. The whole thing is a frozen dataclass so nothing can accidentally change config mid-run.

---

## End-to-end flow

```
python3 scripts/run_full_pipeline.py
```

1. Confirms AWS identity via `sts:GetCallerIdentity`
2. Runs all three TTPs in sequence, generating real CloudTrail events
3. Fetches those events from S3 (CloudTrail logs arrive within ~15 minutes)
4. Runs all detection rules against the events
5. Generates and enriches alerts with MITRE ATT&CK details
6. Dispatches response actions and writes the incident report

---

## Design decisions

**Why a base class for TTPs?** It means the runner and detection engine treat all TTPs the same way. Adding a new technique is just a new file: nothing else in the framework needs to change.

**Why rule functions instead of rule classes?** Keeps the rules simple and readable. Each rule is a function that takes events and returns alerts. That's it.

**Why dry-run by default?** This runs against a real AWS account. I'd rather log what the response layer would do than accidentally revoke my own credentials during a demo.

**Why both JSON and Markdown reports?** JSON for anything that wants to parse the output programmatically. Markdown because it renders nicely on GitHub and is readable by anyone without tooling.

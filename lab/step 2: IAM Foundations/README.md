# Objective

The root account and a single Admin account are not enough for secure cloud operations. To follow the principle of least privilege, we must:

* Organize users into groups for easier management.

* Attach permissions to groups, not individuals.

* Enforce MFA and strong credential hygiene for all IAM users.

* Prepare a scalable structure for future users (e.g., Developers, Auditors).

* This ensures access control is manageable and secure, even as the environment grows.

# Actions Taken
* ## Create IAM Groups

 - Admins → Full administrator rights.

- Developers → Permissions for compute/storage (e.g., EC2, S3).

- Auditors → Read-only access to logs, CloudTrail, and security data.

```bash
aws iam create-group --group-name Admins
aws iam create-group --group-name Developers
aws iam create-group --group-name Auditors
```

* ## Attach AWS Policies to Groups
  I am attaching AWS Privileges to the Groups to enforce least privilege.

- Admins will get full rights:
```bash
aws iam attach-group-policy --group-name Admins --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

- Developers will only have access to ?:
```bash
aws iam attach-group-policy --group-name Developers --policy-arn arn:aws:iam::aws:policy/AmazonEC2FullAccess
aws iam attach-group-policy --group-name Developers --policy-arn arn:aws:iam::aws:policy/AmazonS3FullAccess
```

- Auditors will only be able to security audit (read-only):
```bash
aws iam attach-group-policy --group-name Auditors --policy-arn arn:aws:iam::aws:policy/SecurityAudit
```

* ## Create a Demo Account
  I am creating a demo Developer account to validate that the group-based permissions are working properly.

  - Create demo user:
```bash
aws iam create-user --user-name DemoDev
aws iam add-user-to-group --user-name DemoDev --group-name Developers
```

 - Create a login profile:
```bash
aws iam create-login-profile --user-name DemoDev --password "********" --password-reset-required
```

# Findings / Results

- IAM groups (Admins, Developers, Auditors) were successfully created.

- Attached AWS managed policies aligned with least privilege.

- DemoDev user (in Developers group) could access EC2 and S3 as intended.

- Attempts by DemoDev to access IAM and Billing were denied (as expected).

- MFA was enforced and successfully tested on DemoDev’s login.

# Security Rationale

* Least Privilege: Users gain only the permissions required for their role, reducing the attack surface.

* Separation of Duties: Admins manage the environment, Developers work with resources, Auditors review logs — minimizing overlap that could lead to abuse.

* Scalability: Groups allow permissions to be managed centrally, avoiding insecure ad-hoc user policies.

* Defense in Depth: MFA adds a second authentication factor, protecting accounts even if passwords are compromised.

# Objective

In Step 2, we enforced the principle of least privilege to limit the scope of damage a compromised account can cause. However, it does not eliminate the risk entirely. If an attacker gains access to IAM user credentials, they may still perform unauthorized actions within those granted permissions.

To harden the environment further, we will be introducing credential hygiene and multi-factor authentication (MFA) as mandatory safeguards. Specifically, it aims to:

- Require MFA for all IAM users, ensuring account access cannot rely on a single factor (password).

- Enforce strong password policies to prevent the use of weak or reused credentials.

- Reduce reliance on long-term access keys, which are a common source of leaks and compromise.

By layering these controls, we significantly raise the cost of credential-based attacks such as phishing, brute force, or credential stuffing, while aligning the environment with AWS security best practices.

# Actions Taken
## 1. Set a strong password policy
This enforces baseline hygiene across all IAM users.

```bash
aws iam update-account-password-policy --minimum-password-length 12 --require-symbols --require-numbers --require-uppercase-characters --require-lowercase-characters --allow-users-to-change-password --max-password-age 90 --password-reuse-prevention 5
```
With this, users' passwords are required to:
- Have a minimum length of 12 characters
- Require symbols
- Require both lowercase and uppercase letters
- Require numbers
- Have a maximum age of 90 days before being changed

As well as ensuring that a user can not reuse any of their last 5 passwords.

## 2. Enforce MFA for all IAM Users
Enable MFA per user:

```bash
aws iam create-virtual-mfa-device --virtual-mfa-device-name DemoDevMFA --outfile C:\Users\toluw\Downloads\DemoDevMFA.png --bootstrap-method QRCodePNG
```
This generates a QR Code PNG file that can be scanned with an Authenticator App. Now, we enable the MFA:

```bash
aws iam enable-mfa-device --user-name DemoDev --serial-number "arn:aws:iam::123454321675:mfa/DemoDevMFA" --authentication-code1 123456 --authentication-code2 789012
```

# Findings / Result

All IAM users are required to follow strong password practices.

MFA is enforced on each IAM user, not just root.

Any account without MFA stands out in audits and can be flagged.

# Security Rationale

MFA blocks 99% of credential-stuffing and brute-force attempts.

Rotation & complexity reduce risk of weak or reused passwords.

Enforcing MFA across users demonstrates “defense in depth”.

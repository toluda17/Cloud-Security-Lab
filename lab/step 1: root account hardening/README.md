## Objective

The root account is the single most powerful identity in a cloud environment. If compromised, it gives attackers unrestricted access to all resources and billing. My objective is to secure the root account, minimize its use, and set guardrails to prevent abuse.

## Actions Taken
* Logged into the root account using the signup email.

* Set a long, unique password stored in a password manager (Google Password Manager).

* Enabled MFA (Multi-Factor Authentication) on the root account using an authenticator app (Authenticator).

* Configured billing alerts (to receive email if charges exceed a specified amount).

* Verified account contacts (security, billing, operations) were up to date.

* Created an IAM Admin user with AdministratorAccess and MFA.

* Logged out of root and switched to the IAM Admin user for future operations.

## Security Rationale

* Unique password → prevents brute force or credential stuffing.

* MFA → ensures a stolen password alone cannot compromise the account.

* Billing alerts → detect abnormal charges quickly, often the first sign of compromise.

* IAM Admin user → reduces dependency on root and enforces best practice: "root is for emergencies only."

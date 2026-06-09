# Security Policy

Nine-Security VERIS 9STriage is published as source-available code for transparency review. This repository is intended to let customers, auditors, and security practitioners inspect the scanner's endpoint evidence collection behavior.

## Reporting Security Issues

If you find a security issue in the 9STriage scanner source, please report it by email:

consult@nine-security.com

Please include:

- a concise description of the issue
- affected file or component
- reproduction steps when possible
- expected impact
- whether the issue could affect endpoint privacy, evidence integrity, or scanner execution safety

Do not include real customer evidence packages, access tokens, private keys, passwords, or production host data in your report. If evidence is needed, use synthetic or redacted examples.

## In Scope

Security reports for this transparency repository may include:

- scanner evidence collection behavior that exceeds the documented scope
- accidental collection of file contents, secrets, credentials, browser data, screenshots, keystrokes, clipboard data, or other excluded data
- evidence package integrity or tampering concerns
- scanner execution safety issues
- build or packaging issues that could introduce unintended collection behavior
- source-code defects that affect privacy boundaries

## Out of Scope

The following are outside the scope of this public repository:

- proprietary VERIS Central scoring logic
- proprietary VERIS Central correlation, root-cause, and reporting logic
- production infrastructure, deployment scripts, or service configuration
- Central API probing or service abuse
- denial-of-service testing against Nine-Security services
- social engineering
- reports based only on the presence of a public verification key

## Transparency Boundary

9STriage is an endpoint evidence collector. It does not make final malicious or benign decisions and does not include VERIS Central analysis logic.

This repository does not include:

- Central upload tokens
- dedicated launcher submission tokens
- signing private keys
- production API keys
- customer evidence packages

## Coordinated Disclosure

Nine-Security asks reporters to avoid public disclosure until we have had a reasonable opportunity to validate and address the issue. We will review reports in good faith and may request additional technical details when needed.

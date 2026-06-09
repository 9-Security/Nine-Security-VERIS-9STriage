# Privacy Notes

9STriage is an endpoint evidence collector. It is built to collect bounded metadata for security triage, not personal content.

## Potentially Sensitive Metadata

Even without collecting file contents or browser history, evidence packages may include sensitive metadata such as:

- usernames
- hostnames
- file paths
- process command lines
- remote IP addresses and ports
- service names
- scheduled task commands
- registry persistence values
- executable hashes

Review your legal, privacy, and incident-response authorization requirements before running the scanner or uploading evidence.

## Central Analysis

The proprietary VERIS Central service is not included in this repository. Central performs interpretation, scoring, correlation, root-cause analysis, and report generation after evidence is submitted.

## Tokens And Signing Keys

This repository does not include:

- Central upload tokens
- dedicated launcher submission tokens
- Central private signing keys
- production deployment secrets
- Central API keys

The scanner contains public-key verification logic for signed VERIS tokens. A public key is not a submission token and is not a signing private key.

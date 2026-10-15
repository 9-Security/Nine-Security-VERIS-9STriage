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

### File-Hash Reputation Checks

During analysis, Central may check the SHA-256 hashes of executables in the evidence (for example, running programs, persistence targets, and executables in temporary folders) against the Nine-Security malware analysis platform and third-party threat-intelligence services (such as MalwareBazaar, abuse.ch URLhaus and ThreatFox, VirusTotal, and AlienVault OTX) to identify known malware.

- Only hashes are sent. File contents, file names, paths, hostnames, usernames, and contact details are not.
- A hash is a one-way fingerprint of a file's contents and cannot be used to reconstruct the file.
- Those services may retain the hashes they are queried with under their own policies.

See also the Nine-Security Privacy Policy: https://nine-security.com/privacy.html

## Tokens And Signing Keys

This repository does not include:

- Central upload tokens
- dedicated launcher submission tokens
- Central private signing keys
- production deployment secrets
- Central API keys

The scanner contains public-key verification logic for signed VERIS tokens. A public key is not a submission token and is not a signing private key.

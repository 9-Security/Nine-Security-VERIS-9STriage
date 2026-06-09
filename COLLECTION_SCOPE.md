# 9STriage Collection Scope

This document summarizes the endpoint metadata that 9STriage may collect. The scanner is designed to collect evidence for later Central-side analysis. It does not produce final malicious or benign verdicts.

## Process Metadata

9STriage may collect:

- process name
- PID
- parent PID
- parent and grandparent process context when available
- process command line
- image path
- normalized image path
- image SHA-256 when the executable is readable and within bounded size limits
- file created and modified timestamps
- file size
- process start time
- owner
- session ID
- executable architecture
- token elevation state
- publisher/company metadata when available from file version information

## Network Metadata

9STriage may collect:

- TCP connection metadata
- TCP listener metadata
- UDP endpoint metadata
- local and remote address
- local and remote port
- connection state
- owning PID
- process context for the owning PID when available

## Memory Metadata

9STriage may collect memory-region metadata such as:

- executable private memory region indicators
- RWX region indicators
- mapped RWX region indicators
- high-entropy region indicators
- suspicious executable region hints
- memory anomaly counts per process
- region base address
- region size
- memory protection flags
- region type
- entropy sample value when computed

The scanner records memory metadata and bounded samples needed to compute entropy. It does not upload arbitrary process memory dumps.

## Persistence Metadata

9STriage may collect persistence-related metadata such as:

- registry Run key values
- service configuration metadata
- scheduled task inventory and task action metadata
- driver and minifilter inventory metadata
- executable path, command line, publisher, and hash for persistence targets when available

## Artefact And Integrity Metadata

9STriage may collect selected forensic artefact metadata and integrity indicators, including bounded event log indicators, prefetch or recent execution metadata, hosts file indicators, and basic system binary integrity metadata.

## Collection Gap Metadata

9STriage may record collector status and gap metadata such as:

- collector success or failure
- access denied conditions
- partial data conditions
- observation window duration
- short-lived process or network activity suspicion
- skipped collector reason

## What 9STriage Does Not Collect

9STriage is not designed to collect:

- browser history
- browser cookies
- saved passwords
- API keys or secrets by searching user files
- document contents
- email contents
- chat or message contents
- screenshots
- keystrokes
- clipboard contents
- webcam or microphone data
- arbitrary recursive directory listings
- arbitrary file uploads
- full process memory dumps
- proprietary VERIS Central scoring or report data

## Important Note

Evidence metadata can still be sensitive. Command lines, usernames, paths, remote addresses, and persistence commands may reveal operational details. Only run the scanner on systems where you are authorized to collect endpoint triage metadata.

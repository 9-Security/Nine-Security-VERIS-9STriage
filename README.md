# Nine-Security VERIS 9STriage

Nine-Security VERIS 9STriage is published as source-available code for transparency review. It is not licensed as open source software.

This repository lets customers, auditors, and security practitioners inspect what the 9STriage scanner collects and what it does not collect. The proprietary VERIS Central analysis service, scoring logic, correlation engine, root-cause engine, and reporting workflow are not included.

## What This Repository Contains

- `scanner-engine/`: the 9STriage endpoint evidence collector.
- `COLLECTION_SCOPE.md`: what the scanner collects and does not collect.
- `PRIVACY.md`: privacy and sensitive metadata notes.
- `BUILD.md`: build and local execution notes.
- `LICENSE`: source-available, non-commercial transparency review terms.

## Scanner Role

9STriage is an evidence collector. It gathers bounded endpoint metadata and packages it as evidence for VERIS Central.

## Try VERIS

You can try the VERIS service here:

https://nine-security.com/veris.html

The public service uses VERIS Central to analyze submitted 9STriage evidence packages. Central remains proprietary and is not included in this repository.

9STriage does not:

- make final malicious or benign decisions
- include Central scoring logic
- include Central correlation or root-cause analysis
- include Central report generation
- include Central API or deployment code
- include submission tokens or signing private keys

## License

Commercial use is not permitted without written permission from Nine-Security Inc.

See [LICENSE](LICENSE).

## Transparency Goal

The purpose of publishing this source is to make the scanner's collection behavior auditable. The source is intended to answer:

- what endpoint metadata can be collected
- what privacy boundaries are enforced
- what the scanner does not collect
- where Central-side proprietary analysis begins

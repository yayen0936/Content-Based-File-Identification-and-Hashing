A Python-based intake/triage tool that analyzes **file content** (magic bytes + header structures), not filenames or extensions. It is designed for **malware-analysis** workflows where correct identification of artifacts (e.g., executables mislabeled as .txt) is required.

## Requirements Met
This tool explicitly implements the following:

- **Walk a directory of mixed files** (recursive)
- **Generate cryptographic hashes** for each file (SHA-256 by default; MD5 optional)
- **Identify true file type using magic bytes/headers** (not extensions)
- **Sort files into folders by true type** (e.g., `/executables`, `/scripts`, `/textdocs`, `/other`, plus additional buckets)
- **Produce a summary report** (CSV and/or TXT) mapping:
  - `Original Filename → True file type → Hash → Notes`
- **Does not execute files** and does not attempt to judge maliciousness.

## What the Tool Will NOT Do (by design)
- It will **not execute** or open files in an unsafe way.
- It will **not decide** malicious vs. benign.
- It will **not auto-escalate** using reputation scores or external intelligence.

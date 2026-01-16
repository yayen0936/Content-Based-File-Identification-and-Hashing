# File Content Triage Tool

## What this Python script does
This Python script helps you **organize a folder of unknown files**.

It **looks inside each file** to figure out what it really is (instead of trusting the filename like `.exe` or `.txt`), then it:

- **Calculates a unique fingerprint (SHA-256 hash)** for each file
- **Sorts files into folders** such as `executables`, `documents`, `images`, `scripts`, etc.
- **Creates a CSV report** (`triage_summary.csv`) listing each file’s:
  - name
  - detected type
  - hash
  - notes (e.g., if the filename looks suspicious)

## What it does NOT do
- It **does not run or open** the files.
- It **does not decide** if a file is safe or malicious.
- It **does not use the internet** or reputation checks.

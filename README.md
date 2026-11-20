# The Revocation GAP — Evidence Archive

This archive reorganizes the three source uploads without modifying the content of the included original evidence files.

Original source archives:
- RevocationLab.zip
- Evidence-Chrome.zip
- Evidence-Edge.zip

Additional previously available material:
- RevocationGap_Batch_Analysis_v11.zip (derived analyses, not primary evidence)

## Structure
- 01-Windows-CryptoAPI: R01–R28 and their recorded variants
- 02-HTTP-HAProxy: available R30-G evidence; **R29 and R30-A–F original files were not identified in the three uploads**
- 03-Controlled-Replication: R31 experiments, including repeated-run folders
- 04-Browser-Experiments: Chrome and Edge original NetLogs and captures
- 05-PKI-Material: standalone public certificates and other PKI supporting files
- 06-Analysis: pre-existing derived analyses and uncategorized supporting files
- 07-Tools-and-Scripts: actual RevocationLab C# source, plus a clearly labeled NEW integrity-checking helper

## Provenance
Evidence-Manifest.csv lists each included file, its SHA-256 hash, its original source ZIP, and its original path. SHA256SUMS.txt is a standard checksum list. The manifest itself is excluded from SHA256SUMS to avoid circular hashing.

Generated files (README.md, Evidence-Manifest.csv, SHA256SUMS.txt, and the integrity helper) were NOT part of the original experimental measurements.

## Important limitations
- Original R29 data and most R30-A–F raw files were not found in the three uploaded ZIP files. Do not represent them as included.
- The evidence manifest identifies artifacts, not independently verified experimental outcomes.
- Review any included configuration or diagnostic text for credentials, personal information, or infrastructure details before public distribution.
- Temporary compiled build outputs (bin/ and obj/) have been omitted; actual C# source and project files are retained.
- No replacement experimental scripts or fabricated measurement files were generated.

## Verify
After extraction, run `python 07-Tools-and-Scripts/Post-Research-Utilities/verify_sha256.py`.

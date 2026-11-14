#!/usr/bin/env python3
"""Post-research utility: verify files against SHA256SUMS.txt. Not used during original experiments."""
import hashlib
from pathlib import Path
root=Path(__file__).resolve().parents[2]
manifest=root/'SHA256SUMS.txt'
failed=0; total=0
for line in manifest.read_text(encoding='utf-8').splitlines():
    if not line.strip(): continue
    expected, relative=line.split('  ',1)
    file=root/relative
    actual=hashlib.sha256(file.read_bytes()).hexdigest() if file.is_file() else 'MISSING'
    total+=1
    if actual.lower()!=expected.lower():print('FAIL:',relative);failed+=1
print(f'Checked {total} files; {failed} failures')
raise SystemExit(1 if failed else 0)

#!/usr/bin/env bash
set -euo pipefail

FILE="${1:-src/afl-fuzz-bandit.c}"

header="$(python3 - <<'PY' "$FILE"
import sys,re
header=[]
collect=False
with open(sys.argv[1],'r',encoding='utf-8') as f:
    for line in f:
        if 'fprintf(b->log_fp' in line and not collect:
            collect=True
        if collect:
            for m in re.finditer(r'\"([^"]*)\"', line):
                header.append(m.group(1))
        if collect and ');' in line:
            break
if not header:
    sys.exit("header not found")
print(''.join(header))
PY
)"

row_fmt="$(python3 - <<'PY' "$FILE"
import sys,re
row=[]
collect=False
with open(sys.argv[1],'r',encoding='utf-8') as f:
    for line in f:
        if 'fprintf(b->log_fp' in line:
            collect=True
        if collect:
            for m in re.finditer(r'\"([^"]*)\"', line):
                row.append(m.group(1))
        if collect and ');' in line:
            break
if not row:
    sys.exit("row format not found")
print(''.join(row))
PY
)"

hc=${header//[^,]/}
rc=${row_fmt//[^,]/}
hc=$(( ${#hc} + 1 ))
rc=$(( ${#rc} + 1 ))

echo "Header columns : $hc"
echo "Row columns    : $rc"

if [ "$hc" -ne "$rc" ]; then
  echo "Mismatch!" >&2
  exit 1
fi

echo "OK"

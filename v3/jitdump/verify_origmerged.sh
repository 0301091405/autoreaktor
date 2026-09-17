#!/bin/bash
cd ~/Desktop/decodehub-week1/tools/autoreaktor/v3/multi-target/real-targets/t4y
echo "=== t4y75-orig-merged (ORIJINAL + 41 govde + AT-kill) ==="
timeout 12 ./t4y75-orig-merged.exe 2>e2.txt
RC=$?
echo "rc=$RC"
if [ $RC -eq 124 ]; then echo "YASIYOR (12s+)"; else grep -oE 'Exception: [A-Za-z. ]+' e2.txt | head -1; fi
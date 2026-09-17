#!/bin/bash
cd ~/Desktop/decodehub-week1/tools/autoreaktor/v3/multi-target/real-targets/t4y
echo "=== nb2fresh (siradan uretilmis nb2) ==="
timeout 12 ./t4y75-nb2fresh.exe 2>e1.txt
RC=$?
echo "rc=$RC"
if [ $RC -eq 124 ]; then echo "YASIYOR (12s+)"; else grep -oE 'Exception: [A-Za-z. ]+' e1.txt | head -1; fi
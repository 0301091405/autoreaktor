#!/bin/bash
cd ~/Desktop/decodehub-week1/tools/autoreaktor/v3/multi-target/real-targets/t4y
echo "=== restored2 ==="
timeout 10 ./t4y75-restored2.exe 2>err1.txt
RC1=$?
echo "restored2 rc=$RC1"
grep -oE 'Exception: [A-Za-z.]+' err1.txt | head -1
echo "=== nb2 ==="
timeout 10 ./t4y75-nb2.exe 2>err2.txt
RC2=$?
echo "nb2 rc=$RC2"
grep -oE 'Exception: [A-Za-z.]+' err2.txt | head -1
echo "=== orijinal ==="
timeout 10 "./NET Reactor Unpack Me.exe" 2>err3.txt
RC3=$?
echo "orijinal rc=$RC3"
grep -oE 'Exception: [A-Za-z.]+' err3.txt | head -1
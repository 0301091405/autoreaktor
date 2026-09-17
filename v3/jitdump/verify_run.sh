#!/bin/bash
cd ~/Desktop/decodehub-week1/tools/autoreaktor/v3/multi-target/real-targets/t4y
echo "=== restored2 (41 govde yazili PE) ==="
"./t4y75-restored2.exe" &
T4PID=$!
sleep 10
if kill -0 $T4PID 2>/dev/null; then
  echo "[SONUC] restored2 YASIYOR"
  taskkill //IM t4y75-restored2.exe //F 2>/dev/null
else
  wait $T4PID
  echo "[SONUC] restored2 OLDU"
fi
sleep 1
echo "=== nb2 (karsilastirma) ==="
"./t4y75-nb2.exe" &
T4PID2=$!
sleep 10
if kill -0 $T4PID2 2>/dev/null; then
  echo "[SONUC] nb2 YASIYOR"
  taskkill //IM t4y75-nb2.exe //F 2>/dev/null
else
  wait $T4PID2
  echo "[SONUC] nb2 OLDU"
fi
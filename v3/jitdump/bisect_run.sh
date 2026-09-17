#!/bin/bash
# bisection: NB_MAXWRITE 0..41 arasi govde yaz, InvalidProgram
# hangi govdeden geliyor izole et. Orijinal taban + AT-kill.
cd ~/Desktop/decodehub-week1/tools/autoreaktor/v3/jitdump
TGT="../multi-target/real-targets/t4y"
for N in 0 1 2 5 10 20 41; do
  export NB_ATKILL=1 NB_NOSIL=1 NB_MAXWRITE=$N
  ./nbilmerge.exe "$TGT/NET Reactor Unpack Me.exe" "$TGT/jitdump" "$TGT/bisect.exe" >/dev/null 2>&1
  timeout 10 "$TGT/bisect.exe" 2>/dev/null
  RC=$?
  if [ $RC -eq 124 ]; then R="YASIYOR"; else R="OLDU rc=$RC"; fi
  echo "MAXWRITE=$N -> $R"
done
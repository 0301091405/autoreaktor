"""auto_stubmap.py — NecroBit auto token-bind driver (v3 route).

Builds NB_STUBMAPTOK automatically from a token-named JIT dump dir
(clrjit_hook v4 route: filenames carry the REAL MethodDef token) and
runs nbilmerge with it. No manual m_X=token pairs, no IL-pattern
guessing — token-precise, zero false binds.

Usage:
  python auto_stubmap.py <target.exe> <dumpdir> <out.exe>

Proof (t-max, 2026-09-18): 182 dump bins -> 36 token-exact binds
(sample-max metadata) + 222 decoy stubs null-wiped -> nbfixctor2
v54 chain -> FULL child-tree parity (2 EDIT + register BUTTON),
stable T+15/30/60s single pid. This is the REAL-body route — the
running ctor is the merge-bound original body, not a hand-built one.
"""
import glob
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
MERGE = os.path.join(HERE, 'nbilmerge.exe')


def build_pairs(dumpdir):
    pairs = []
    for b in sorted(glob.glob(os.path.join(dumpdir, 'm_06*.bin'))):
        tok = os.path.basename(b)[2:-4]          # m_06000006.bin -> 06000006
        pairs.append('%s=%s' % (os.path.basename(b), tok))
    return pairs


def main():
    if len(sys.argv) != 4:
        print(__doc__)
        return 1
    target, dumpdir, out = sys.argv[1], sys.argv[2], sys.argv[3]
    pairs = build_pairs(dumpdir)
    if not pairs:
        print('[!] no token-named bins in %s (clrjit_hook v4 route writes m_06*)' % dumpdir)
        return 2
    env = dict(os.environ)
    env['NB_STUBMAPTOK'] = ';'.join(pairs)
    print('[*] %d token pairs from %s' % (len(pairs), dumpdir))
    r = subprocess.run([MERGE, target, dumpdir, out],
                       capture_output=True, text=True, env=env,
                       cwd=os.path.dirname(os.path.abspath(target)))
    sys.stdout.write(r.stdout)
    return r.returncode


if __name__ == '__main__':
    sys.exit(main())
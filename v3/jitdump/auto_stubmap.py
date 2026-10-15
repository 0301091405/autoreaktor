"""auto_stubmap.py — NecroBit auto token-bind driver (v3 route).

Builds NB_STUBMAPTOK automatically from a token-named JIT dump dir
(clrjit_hook v4 route: filenames carry the REAL MethodDef token) and
runs nbilmerge with it. No manual m_X=token pairs, no IL-pattern
guessing — token-precise, zero false binds.

With NB_SCOPE_DIRS dumps (nbjitdump sets it), the dump dir holds one
scope*/ subdirectory per CLR module that JIT'd in the process. Only one
of them is the target; the others are the host companion / framework
bodies whose rids would collide. The driver trial-merges every scope
dir and keeps the output with the most restored bodies — no guessing
by name or order, the merge result itself picks the dir.

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
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))


def _find_merge():
    """nbilmerge.exe: repo-root copy, dotnet build output, then HERE."""
    cands = [
        os.path.join(HERE, 'nbilmerge.exe'),
        os.path.join(HERE, 'bin', 'Release', 'nbilmerge.exe'),
        os.path.join(HERE, 'bin', 'Release', 'net48', 'nbilmerge.exe'),
    ]
    for c in cands:
        if os.path.exists(c):
            return c
    return cands[0]


MERGE = _find_merge()


def build_pairs(dumpdir):
    pairs = []
    for b in sorted(glob.glob(os.path.join(dumpdir, 'm_06*.bin'))):
        tok = os.path.basename(b)[2:-4]          # m_06000006.bin -> 06000006
        pairs.append('%s=%s' % (os.path.basename(b), tok))
    return pairs


def _trial_merge(target, dumpdir, out_path):
    """One nbilmerge run on a candidate dump dir. Returns restored count."""
    env = dict(os.environ)
    env['NB_STUBMAPTOK'] = ';'.join(build_pairs(dumpdir))
    r = subprocess.run([MERGE, target, dumpdir, out_path],
                       capture_output=True, text=True, env=env,
                       cwd=os.path.dirname(os.path.abspath(target)))
    sys.stdout.write(r.stdout)
    m = re.search(r'method actually written:\s*(\d+)', r.stdout or '')
    return (int(m.group(1)) if m else 0), r.returncode


def main():
    if len(sys.argv) != 4:
        print(__doc__)
        return 1
    target, dumpdir, out = (os.path.abspath(p) for p in (sys.argv[1], sys.argv[2], sys.argv[3]))

    scope_dirs = sorted(glob.glob(os.path.join(dumpdir, 'scope*')))
    scope_dirs = [d for d in scope_dirs
                  if os.path.isdir(d) and glob.glob(os.path.join(d, 'm_*.bin'))]
    if not scope_dirs:
        scope_dirs = [dumpdir]   # legacy flat dump

    # clause tables written by the forcedump companion land at the dump root;
    # each trial dir needs the ones matching its own bodies
    for eh in glob.glob(os.path.join(dumpdir, 'm_*.eh')):
        for d in scope_dirs:
            dst = os.path.join(d, os.path.basename(eh))
            if not os.path.exists(dst):
                shutil.copyfile(eh, dst)

    if len(scope_dirs) == 1:
        restored, rc = _trial_merge(target, scope_dirs[0], out)
        return 0 if (os.path.exists(out) and restored > 0) else (rc or 1)

    # one scope per CLR module: merge each, keep the strongest result.
    # The winner is decided by the write count, ties broken by how many
    # token-precise candidates the dir carries (target-scope signature).
    print('[*] %d scope dirs — trial-merging each' % len(scope_dirs))
    tmpdir = tempfile.mkdtemp(prefix='ar_scopes_')
    best = (-1, -1, None, None)
    try:
        for d in scope_dirs:
            trial_out = os.path.join(tmpdir, os.path.basename(d) + '.out')
            pairs = build_pairs(d)
            print('--- %s (%d bins, %d token pairs)' % (os.path.basename(d),
                                                        len(glob.glob(os.path.join(d, 'm_*.bin'))),
                                                        len(pairs)))
            restored, rc = _trial_merge(target, d, trial_out)
            ok = os.path.exists(trial_out)
            print('    restored=%d rc=%d written=%s' % (restored, rc, ok))
            if ok and (restored, len(pairs)) > best[:2]:
                best = (restored, len(pairs), d, trial_out)
        if best[2] is None:
            print('[!] no scope dir produced a merge output')
            return 1
        print('[*] winner: %s (%d restored)' % (os.path.basename(best[2]), best[0]))
        shutil.copyfile(best[3], out)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())

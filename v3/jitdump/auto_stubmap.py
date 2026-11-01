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
import base64
import glob
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))


def _materialise(pe_path, out):
    """Copy a merged PE to `out`, surviving an AV quarantine of the source.

    nbilmerge writes `<pe>.b64` (inert base64 text) BEFORE the PE itself.
    Defender's real-time protection deletes the PE the moment the writer
    closes it (Trojan:Win32/Wacatac.C!ml on the merged assembly), and a
    delete-pending file cannot even be opened — that is what broke the
    trial-merge with `OSError [Errno 22]` on nbilmerge's own output. The
    base64 sibling is never touched, so it is the reliable carrier.
    """
    b64 = pe_path + ".b64"
    if os.path.exists(b64):
        try:
            with open(b64, "rb") as f:
                data = base64.b64decode(f.read())
            with open(out, "wb") as f:
                f.write(data)
            return True
        except Exception as ex:
            print("[!] b64 carrier unreadable (%s): %s" % (b64, ex))
    else:
        print("[!] no b64 carrier for %s" % pe_path)
    if os.path.exists(pe_path):
        try:
            shutil.copyfile(pe_path, out)
            return True
        except Exception as ex:
            print("[!] direct copy failed (%s): %s" % (pe_path, ex))
    return False


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


def _trial_merge(target, dumpdir, out_path, b64_path=None, keep_out=False):
    """One nbilmerge run on a candidate dump dir. Returns (restored, rc, wrote).

    The merge product is NOT relied upon here: real-time AV quarantines it on
    close (Trojan:Win32/Wacatac.C!ml), and %TEMP% gets swept as well, so the
    trial is judged by nbilmerge's own log line instead of by the file. The
    winner is re-merged into the caller's directory afterwards, where its
    base64 carrier survives.
    """
    env = dict(os.environ)
    env['NB_STUBMAPTOK'] = ';'.join(build_pairs(dumpdir))
    # Pass a caller-supplied ldstr map through to nbilmerge (it reads
    # NB_LDSTRMAP itself). Without this the consumer below is unreachable
    # whenever the merge is driven through auto_stubmap, which is the normal
    # path. Nothing is generated here: producing the map needs a decrypter.
    if 'NB_LDSTRMAP' in os.environ:
        env['NB_LDSTRMAP'] = os.environ['NB_LDSTRMAP']
    if b64_path:
        env['NB_B64_OUT'] = b64_path
    if keep_out:
        env['NB_KEEP_OUT'] = '1'
    r = subprocess.run([MERGE, target, dumpdir, out_path],
                       capture_output=True, text=True, env=env,
                       cwd=os.path.dirname(os.path.abspath(target)))
    sys.stdout.write(r.stdout)
    m = re.search(r'method actually written:\s*(\d+)', r.stdout or '')
    wrote = '[ok] written' in (r.stdout or '')
    return (int(m.group(1)) if m else 0), r.returncode, wrote


def main():
    if len(sys.argv) != 4:
        print(__doc__)
        return 1
    target, dumpdir, out = (os.path.abspath(p) for p in (sys.argv[1], sys.argv[2], sys.argv[3]))

    scope_dirs = sorted(glob.glob(os.path.join(dumpdir, 'scope*')))
    scope_dirs = [d for d in scope_dirs
                  if os.path.isdir(d) and glob.glob(os.path.join(d, 'm_*.bin'))]
    # the forcedump companion writes REAL-token bodies at the dump root —
    # those bind best, so the root goes first in the trial order
    if glob.glob(os.path.join(dumpdir, 'm_*.bin')):
        scope_dirs = [dumpdir] + scope_dirs
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
        restored, rc, wrote = _trial_merge(target, scope_dirs[0], out,
                                           b64_path=out + '.b64')
        if not wrote:
            return rc or 1
        _materialise(out, out)
        return 0 if restored > 0 else (rc or 1)

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
            restored, rc, wrote = _trial_merge(target, d, trial_out,
                                               b64_path=trial_out + '.b64',
                                               keep_out=True)
            print('    restored=%d rc=%d written=%s' % (restored, rc, wrote))
            if wrote and (restored, len(pairs)) > best[:2]:
                best = (restored, len(pairs), d, trial_out)
        if best[2] is None:
            print('[!] no scope dir produced a merge output')
            return 1
        print('[*] winner: %s (%d restored)' % (os.path.basename(best[2]), best[0]))
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    # final pass: straight into the caller's directory, base64 carrier first
    restored, rc, wrote = _trial_merge(target, best[2], out, b64_path=out + '.b64')
    if not wrote:
        return rc or 1
    _materialise(out, out)
    return 0


if __name__ == '__main__':
    sys.exit(main())

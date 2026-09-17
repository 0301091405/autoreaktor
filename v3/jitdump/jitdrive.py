"""jitdrive.py — Force-JIT coverage driver for NecroBit targets.

Problem (R6/dotqw proof): the JIT dump only catches methods that
actually compile during the dump window. A GUI target that idles after
startup leaves most of its MethodDefs outside the dump. The null-wipe
then neutralizes stubs whose real bodies were never captured ->
native AV at runtime.

Route: launch the target under the nbjitdump hook, then drive the GUI
programmatically: enumerate top-level + child windows of the process,
send clicks to every button, set text in every edit, check every
checkbox — each interaction forces event handlers to JIT, growing the
dump. Re-run nbjitdump's marker/bins afterwards.

Usage:
  python jitdrive.py <target.exe> [--wait 45]

Output: dump dir jitdump_drive/ + interaction log.
"""
import argparse
import ctypes
import os
import subprocess
import time
from ctypes import wintypes

user32 = ctypes.windll.user32
CMPFUNC = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)

WM_GETTEXT = 0x000D
WM_GETTEXTLENGTH = 0x000E
BM_CLICK = 0x00F5
WM_SETTEXT = 0x000C
WM_LBUTTONDOWN = 0x0201
WM_LBUTTONUP = 0x0202

HERE = os.path.dirname(os.path.abspath(__file__))
NBJIT = os.path.join(HERE, 'nbjitdump.py')


def find_pids(image_name):
    r = subprocess.run(['tasklist', '/FO', 'CSV'], capture_output=True, text=True).stdout
    pids = []
    for line in r.splitlines():
        if image_name.lower() in line.lower():
            parts = line.split('","')
            if len(parts) > 1:
                try:
                    pids.append(int(parts[1].strip('"')))
                except ValueError:
                    pass
    return pids


def get_text(h):
    n = user32.SendMessageW(h, WM_GETTEXTLENGTH, 0, 0)
    buf = ctypes.create_unicode_buffer(n + 2)
    user32.SendMessageW(h, WM_GETTEXT, n + 2, buf)
    return buf.value


def get_class(h):
    buf = ctypes.create_unicode_buffer(256)
    user32.GetClassNameW(h, buf, 256)
    return buf.value


def windows_of(pids):
    wins = []
    def cb(h, l):
        pid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(h, ctypes.byref(pid))
        if pid.value in pids and user32.IsWindowVisible(h):
            wins.append(h)
        return True
    user32.EnumWindows(CMPFUNC(cb), 0)
    return wins


def children_of(h):
    out = []
    def cb(hc, l):
        out.append(hc)
        return True
    user32.EnumChildWindows(h, CMPFUNC(cb), 0)
    return out


def drive(h, log):
    for hc in children_of(h):
        cls = get_class(hc)
        txt = get_text(hc)
        if 'BUTTON' in cls.upper():
            # radio/checkbox get BM_CLICK; push buttons too
            user32.SendMessageW(hc, BM_CLICK, 0, 0)
            log.append('click btn %r' % txt)
        elif 'EDIT' in cls.upper():
            user32.SendMessageW(hc, WM_SETTEXT, 0, 'autoreaktor')
            log.append('set edit %r' % txt)
        elif 'COMBO' in cls.upper() or 'LIST' in cls.upper():
            user32.SendMessageW(hc, WM_LBUTTONDOWN, 0, 0)
            user32.SendMessageW(hc, WM_LBUTTONUP, 0, 0)
            log.append('tap %s %r' % (cls, txt))
        time.sleep(0.05)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('target')
    ap.add_argument('--wait', type=int, default=45)
    ap.add_argument('--out', default='jitdump_drive')
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)

    # launch under the hook
    p = subprocess.Popen(['python', NBJIT, a.target, '--out', a.out,
                          '--wait', str(a.wait), '--force-run'],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         text=True)
    # wait for GUI to come up
    time.sleep(10)
    base = os.path.basename(a.target)
    pids = find_pids(base)
    log = []
    rounds = 0
    deadline = time.time() + (a.wait - 15)
    while time.time() < deadline and pids:
        wins = windows_of(pids)
        for h in wins:
            drive(h, log)
            rounds += 1
            time.sleep(2)
            # after first drive the app may have changed state
            pids = find_pids(base)
            if not pids:
                break
        time.sleep(2)
        pids = find_pids(base)
    try:
        o, _ = p.communicate(timeout=a.wait + 30)
        print(o[-400:])
    except subprocess.TimeoutExpired:
        p.kill()
    with open(os.path.join(a.out, 'drive.log'), 'w', encoding='utf-8') as f:
        f.write('\n'.join(log))
    bins = [b for b in os.listdir(a.out) if b.endswith('.bin')]
    print('interactions: %d | bins: %d' % (len(log), len(bins)))


if __name__ == '__main__':
    main()
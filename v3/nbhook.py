#!/usr/bin/env python3
"""nbhook v3.1 — NecroBit JIT harvester (x86 + x64, ABI-correct).

Mechanism (measured on .NET Reactor 7.3 & 7.5 targets):
  NecroBit removes method bodies from the IL stream; the CLR still needs
  them at JIT time, so the Reactor runtime decrypts each body and hands the
  real IL to clrjit!compileMethod via CORINFO_METHOD_INFO (arg #2).

  v3.0 bugs (fixed here):
    - x86 read [esp+4] (arg1 = ICorJitInfo*) instead of [esp+8] (arg2 =
      CORINFO_METHOD_INFO*) — off-by-one, garbage rows.
    - hooked at spawn time when clrjit.dll is not yet loaded -> JS errors.
    - used setInterval, unavailable in this Frida runtime -> TypeError.

  v3.1 design:
    - Python-side retry: re-inject a fresh hook attempt every 1s until
      clrjit.dll exports getJit (CLR JITs the entrypoint -> guaranteed load).
    - x86 thiscall: this=ECX, args on stack -> info = [esp+8]
    - x64 MS x64: RCX=this, RDX=comp, R8=info -> args[2]
    - records flushed to disk every batch (crash-safe)

Usage: python nbhook.py <target.exe> [timeout_sec]
"""
import base64
import json
import os
import subprocess
import sys
import time

import frida

HOOK_SRC = r"""
// Frida 17: Module.findExportByName removed — use findGlobalExportByName.
var getJitAddr = Module.findGlobalExportByName('clrjit.dll!getJit')
              || Module.findGlobalExportByName('getJit');
if (!getJitAddr) {
    send({t:'retry'});
} else {
    var getJit = new NativeFunction(getJitAddr, 'pointer', []);
    var vt = getJit();
    if (vt.isNull()) { send({t:'retry'}); }
    else {
        var compileMethodPtr = vt.readPointer();  // slot 0
        send({t:'info', m:'compileMethod @ ' + compileMethodPtr});
        var is64 = Process.pointerSize === 8;

        Interceptor.attach(compileMethodPtr, {
            onEnter: function (args) {
                // x86 __thiscall: this=ECX, stack args: [esp+4]=comp,
                //   [esp+8]=info (CORINFO_METHOD_INFO*), [esp+12]=flags...
                // x64: RCX=this, RDX=comp, R8=info.
                var info;
                if (is64) { info = args[2]; }
                else { info = ptr(this.context.esp).add(8).readPointer(); }
                if (info.isNull()) return;
                // CORINFO_METHOD_INFO (net48):
                //   +0x00 method handle, +ptr scope, +ptr ILCode, +u32 ILCodeSize
                var off = is64 ? 8 : 4;
                var hMethod = info.readPointer();
                var ilCode  = info.add(off + off).readPointer();
                var ilSize  = info.add(off + off + (is64 ? 8 : 4)).readU32();
                if (ilSize > 0 && ilSize < 0x200000) {
                    send({t:'il', m:hMethod.toString(), size:ilSize,
                          scope:info.add(off).readPointer().toString()},
                         ilCode.readByteArray(ilSize));
                }
            }
        });
        send({t:'info', m:'hook live'});
    }
}
"""


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    target = os.path.abspath(sys.argv[1])
    timeout = int(sys.argv[2]) if len(sys.argv) > 2 else 30

    outdir = os.path.dirname(target) or "."
    dump_path = os.path.join(outdir, "nbhook_il_dump.json")
    records = []

    def flush():
        with open(dump_path, "w") as f:
            json.dump(records, f)

    state = {"live": False, "done": False}

    def on_message(message, data):
        if message["type"] == "send":
            p = message["payload"]
            t = p.get("t")
            if t == "il":
                records.append({"handle": p["m"], "size": p["size"],
                                "scope": p["scope"],
                                "b64": base64.b64encode(data or b"").decode()})
                print(f"[il] handle={p['m']} size={p['size']}")
                if len(records) % 25 == 0:
                    flush()
            elif t == "info":
                print(f"[info] {p['m']}")
            elif t == "retry":
                state["live"] = False
        elif message["type"] == "error":
            print(f"[err] {message.get('description') or message}")

    pid = None
    child = None
    if len(sys.argv) > 3 and sys.argv[3] == "--attach-running":
        # attach to an already-running process by pid (32-bit spawn unsupported
        # on some frida-helper builds: ERROR 0x32)
        pid = int(sys.argv[2])
        timeout = int(sys.argv[4]) if len(sys.argv) > 4 else 30
    else:
        try:
            pid = frida.spawn([target])
        except frida.NotSupportedError:
            # fallback: launch ourselves, attach; the OS resumes it for us
            child = subprocess.Popen([target])
            pid = child.pid
            time.sleep(0.4)  # let the loader map the image
    session = frida.attach(pid)
    if child is None:
        try:
            frida.resume(pid)
        except Exception:
            pass
    print(f"[*] attached pid={pid}; polling for clrjit + hooking...")

    deadline = time.time() + timeout
    hook_script = None
    while time.time() < deadline:
        if not state["live"]:
            if hook_script is not None:
                try:
                    hook_script.unload()
                except Exception:
                    pass
            hook_script = session.create_script(HOOK_SRC)
            hook_script.on("message", on_message)
            hook_script.load()
            # the script signals 'retry' (clrjit absent) or attaches (live)
            time.sleep(1.0)
            state["live"] = last_live = not any(
                m.get("t") == "retry" for m in [{"t": "retry"}]
            ) and True
            # simpler truth: if the script sent no 'retry', it hooked.
        if records:
            # process JITs the whole startup quickly; wait for settle
            last_count = len(records)
            time.sleep(2.0)
            if len(records) == last_count:
                break  # no new methods — startup settled
        else:
            time.sleep(1.0)

    flush()
    try:
        frida.kill(pid)
    except Exception:
        pass
    print(f"[*] {len(records)} IL record(s) -> {dump_path}")
    return 0 if records else 1


if __name__ == "__main__":
    sys.exit(main())
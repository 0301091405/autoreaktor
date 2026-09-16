# NecroBit 7.3 — Internal Mechanism (REVERSED)

Target: Tuts4You ".NET Reactor v7.3" unpackme (WindowsFormsApplication37.exe)
Method: pure Reflection harvest (nbwalk) + Krypton.Runner dynamic-dump cross-match

## The mechanism (all claims measured on-target)

1. NecroBit replaces each protected MethodDef body with a stub that invokes a
   **static Delegate field** (Field token 0x04xxxxxx) — one delegate per method.
2. `AuthenticatorState.policyCreatorDic : Dictionary<int,int>` maps
   **201 field-tokens -> 0x0Axxxxxx (MethodSpec) / 0x4Axxxxxx (custom) tokens**.
   Dumped to policyCreatorDic.txt via nbwalk.
3. The delegate targets are DynamicMethods the Reactor runtime emits at
   module-ctor time. Krypton.Runner's DynamicMethod capture harvests them:
   **204 entries, full IL**, each 1-7 instructions (basic-block fragmentation  - 
   NecroBit chains tiny DynamicMethods rather than emitting one body).
4. Cross-match: **201/201 policyCreatorDic keys == dump SourceField tokens**
   (3 extras are BCL lambdas: ValueTaskAwaiter, ManualResetValueTaskSource).
   This is the complete NecroBit inventory for the target - nothing missing.
5. Bodies do NOT surface via:
   - Hashtable dump (DumpHashtableBodies sees 0 rows even after 766
     PrepareMethod calls - the body cache is not a static IDictionary)
   - getJit vtable swap (vtable[0] stays 0x72f104bc = clrjit+0x704bc for
     20+ s; Reactor 7.3 does not hook the ICorJitCompiler vtable)
   - Frida inline hook on compileMethod (races the module-ctor; inline
     trampoline caused <Module>.cctor AccessViolation)

## What v3 builds from this

nbdump (nbwalk v3): loads target via Reflection, runs module+class ctors,
PrepareMethod-forces all methods, dumps:
  - policyCreatorDic (field-token -> MethodSpec-token map)
  - creatorPolicyItems / filterPolicyItems blobs (DI string tables, runtime-decrypted)
  - delegate chain: every static delegate's DynamicMethod IL (via
    DynamicMethodBodyReader, same path Krypton.Runner uses)

nbrebuild (planned): dnlib patcher
  - resolve each dic value token -> MethodDef (MethodSpec.Parent)
  - inline the delegate-chain fragments into the parent method body
  - write rebuilt assembly; verify by IL diff + GUI invoke

## Negative results worth keeping

- PrepareMethod x766: succeeds, does NOT populate any harvestable Hashtable.
- getJit caller = clr.dll+0xe6fe8 (single call site), vtable unchanged after.
- creatorPolicyItems 1940 bytes = 9 UTF-16 blobs: DI exception strings
  ("button1", "register", "textBox1", "textBox2", "AmbiguousConstructorException",
  ...) - evidence Reactor runtime-decrypts string tables into static fields,
  harvestable via plain Reflection (no JIT hook needed for THOSE).

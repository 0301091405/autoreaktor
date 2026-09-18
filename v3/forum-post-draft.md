[AutoReaktor v3] NecroBit method recovery — reflection harvest + a runnable rebuild (working notes)

i've been picking at the .NET Reactor v7.3 unpackme from here (whoknows, june 2025) for a while. everyone knows the usual chain stops somewhere — de4dot calls it unknown obfuscator, Slayer does its thing but the wiki already says "except code virtualization", and necrobit bodies are just... gone. you get stubs that call into delegate fields and that's where the road ends.

so here's what i found messing with it. this is not a finished tool, more like a writeup of a mechanism + two small tools that do work on this target. take it as research notes.

the mechanism (7.3 build):
- every necrobit'd method body becomes a stub invoking a static delegate field, one field per method
- there's a Dictionary<int,int> (policyCreatorDic) in the runtime that maps the field token to a methodspec token. you can just read it with reflection after forcing the ctors. no jit hook, no debugger, no native anything
- the delegates point at DynamicMethods the reactor runtime bakes at module-ctor time. they're tiny, 1-7 instructions each. necrobit doesn't emit one body per method - it chains a bunch of these little fragments (basic-block style)
- harvest those with the same DynamicMethod body reader krypton's runner uses and you get the full inventory. on this target: 201/201 fields matched, 204 fragments total (3 extras are BCL lambdas, not necrobit)

things that did NOT work, for the record: PrepareMethod on everything (766 calls, populates nothing), getJit vtable hook (vtable never changes on 7.3, clrjit stays vanilla), frida inline hook on compileMethod (races the module cctor, AVs in <Module>). the reflection path just... works. honestly feels like the intended debug path was left in.

the rebuild part is where it got interesting. naive dnlib write produces a binary that launches the VM stub loader and dies inside it with the anti-tamper exception. three separate bugs, all found by running the thing rather than reading it:

1. metadata token renumbering. the VM resource blob stores original tokens and resolves them at runtime through Module.ResolveMethod/ResolveField. dnlib renumbers rows on write by default, so every constant in the blob silently points somewhere else. PreserveAll on write, problem gone
2. overload resolution by arity. Array.SetValue(object, int) vs (object, int[]) - same param count. the rebuild picked the array one and crashed with ArgumentNullException at runtime. you need the full signature from the harvested fragment
3. even my own logging injector hit #1 - rebuild without PreserveAll and the anti-tamper fires again. diagnostic builds don't get an exemption from the VM's token discipline

end state on this target: 1438 call sites substituted across 187 methods, 0 necrobit pairs left in the output, and the rebuilt binary opens the same GUI and behaves identically to the original (register button, empty-field error box, all of it). i verified by actually clicking the button on both.

code + full research notes: https://github.com/0301091405/autoreaktor (v3 folder)

honest limits: this is one target (7.3, x86, net48). the harvest/rebuild approach is structural - no hardcoded opcode tables or per-build offsets, everything comes from what the runtime itself exposes — but i'm not claiming 6.x/7.0/7.5 coverage until it's run on them. code virtualization is still a separate problem (slayer+krypton handles those on this target), necrobit+antitamper is what's solved here.

questions welcome, especially if someone has samples from other reactor versions to try it against
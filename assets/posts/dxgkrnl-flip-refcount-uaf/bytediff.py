"""Raw byte diff of two same-size PE images, grouped into runs and attributed
to the section each run falls in.

For an in-place security patch (no size change) this localises the change far
faster than a function-inventory diff.
"""
import pefile
import sys


def sections(pe):
    out = []
    for s in pe.sections:
        name = s.Name.rstrip(b'\x00').decode(errors='replace')
        out.append((name, s.PointerToRawData, s.PointerToRawData + s.SizeOfRawData,
                    s.VirtualAddress, pe.OPTIONAL_HEADER.ImageBase))
    return out


def which(secs, off):
    for name, lo, hi, va, base in secs:
        if lo <= off < hi:
            return name, base + va + (off - lo)
    return '?', None


def main(fa, fb):
    a = open(fa, 'rb').read()
    b = open(fb, 'rb').read()
    print('sizes: %d vs %d' % (len(a), len(b)))
    pe = pefile.PE(fa, fast_load=True)
    secs = sections(pe)

    n = min(len(a), len(b))
    runs, start = [], None
    for i in range(n):
        if a[i] != b[i]:
            if start is None:
                start = i
        else:
            if start is not None:
                if i - start > 0:
                    runs.append((start, i))
                start = None
    if start is not None:
        runs.append((start, n))

    # merge runs separated by small gaps so one patched basic block reads as one run
    merged = []
    for r in runs:
        if merged and r[0] - merged[-1][1] <= 16:
            merged[-1] = (merged[-1][0], r[1])
        else:
            merged.append(list(r))
            merged[-1] = tuple(merged[-1])
    merged = [tuple(m) for m in merged]

    print('differing runs: %d (raw), %d (merged)' % (len(runs), len(merged)))
    bysec = {}
    for lo, hi in merged:
        name, va = which(secs, lo)
        bysec.setdefault(name, []).append((lo, hi, va))

    for name in sorted(bysec):
        lst = bysec[name]
        total = sum(h - l for l, h, _ in lst)
        print('\n=== %s : %d runs, %d bytes ===' % (name, len(lst), total))
        for lo, hi, va in lst[:60]:
            vs = ('VA 0x%X' % va) if va else ''
            print('  file 0x%06X..0x%06X  (%3d bytes)  %s' % (lo, hi, hi - lo, vs))
        if len(lst) > 60:
            print('  ... %d more' % (len(lst) - 60))


if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])

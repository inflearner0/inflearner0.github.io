"""Diff two idasql function-inventory exports.

Input lines are  name~size~instruction_count  (see the idasql query in the
driver script).  Reports functions that were added, removed, or whose size /
instruction count changed between the two builds.
"""
import sys


def load(path):
    out = {}
    with open(path, encoding='utf-8', errors='replace') as fh:
        for line in fh:
            line = line.strip()
            if not line or line == 'row':
                continue
            parts = line.rsplit('~', 2)
            if len(parts) != 3:
                continue
            name, size, icount = parts
            try:
                out[name] = (int(size), int(icount))
            except ValueError:
                continue
    return out


def main(before_path, after_path, label):
    before, after = load(before_path), load(after_path)
    added = sorted(set(after) - set(before))
    removed = sorted(set(before) - set(after))
    changed = []
    for name in sorted(set(before) & set(after)):
        bs, bi = before[name]
        as_, ai = after[name]
        if (bs, bi) != (as_, ai):
            changed.append((name, bs, as_, bi, ai))

    print('=== %s ===' % label)
    print('functions: before=%d after=%d  |  added=%d removed=%d changed=%d'
          % (len(before), len(after), len(added), len(removed), len(changed)))

    if changed:
        print('\n--- changed (size / instruction count) ---')
        for name, bs, as_, bi, ai in sorted(changed, key=lambda r: -abs(r[2] - r[1])):
            print('  %-62s %6d -> %-6d (%+5d)   insns %5d -> %-5d (%+d)'
                  % (name[:62], bs, as_, as_ - bs, bi, ai, ai - bi))
    if added:
        print('\n--- added (%d) ---' % len(added))
        for n in added:
            print('  +', n[:100])
    if removed:
        print('\n--- removed (%d) ---' % len(removed))
        for n in removed:
            print('  -', n[:100])

    # emit bare names so the caller can intersect branches
    with open(label.replace('/', '_').replace(' ', '') + '.changed', 'w') as fh:
        for name, *_ in changed:
            fh.write(name + '\n')
        for n in added:
            fh.write(n + '\n')


if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2], sys.argv[3])

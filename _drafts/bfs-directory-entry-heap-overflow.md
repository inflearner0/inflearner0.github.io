---
title: "CVE-2026-62722 — Microsoft Brokering File System Elevation of Privilege Vulnerability: 512 Bytes and No Check"
date: 2026-08-17 18:00:00 +0200
categories: [Vulnerability Research, Windows Kernel]
tags: [windows, bfs, patch-diffing, winbindex, ida, heap-overflow, pool-corruption, use-after-free, reverse-engineering]
---

The advisory for this one couldn't decide what it was about.

`CVE-2026-62722` was published on 11 August 2026 as a heap-based buffer overflow
in the Windows Brokering File System. Six days later Microsoft revised it —
*"Corrected the CVE description and title"* — and the record still carries both
titles side by side:

```
"Windows Bind Filter Driver Elevation of Privilege Vulnerability"
"Windows Brokering File System Elevation of Privilege Vulnerability"
```

Those are two different drivers: `bindflt.sys` and `bfs.sys`. The advisory does
not tell you which one changed.

Winbindex does, in about thirty seconds, and the rest of the patch turns out to
be one of the cleanest diffs I have looked at: 264 functions, eight of them
changed, and a single missing bounds check duplicated across four call sites.

## Table of contents

1. [Which driver?](#which-driver)
2. [The diff](#the-diff)
3. [The overflow](#the-overflow)
4. [Counting the fix sites](#counting-the-fix-sites)
5. [A false lead worth showing](#a-false-lead-worth-showing)
6. [The other five functions](#the-other-five-functions)
7. [Feature flags, again](#feature-flags-again)
8. [Why there is no PoC this time](#why-there-is-no-poc-this-time)
9. [What this is worth](#what-this-is-worth)
10. [Artifacts](#artifacts)
11. [What was worth learning](#what-was-worth-learning)

## Which driver?

Winbindex indexes every shipped build of a Windows binary by SHA-256. If a
driver did not change in an update, the hash before and after is identical. That
makes "which of these two drivers did the August patch touch" a lookup rather
than a research question:

| Driver | Branch | Before | After | |
|---|---|---|---|---|
| `bindflt.sys` | 24H2/25H2 | `3d35d17b40031485` | `3d35d17b40031485` | **unchanged** |
| `bindflt.sys` | 26H1 | `b9c525516a16d2ff` | `b9c525516a16d2ff` | **unchanged** |
| `bfs.sys` | 24H2/25H2 | `b144c382c9e6ca40` | `0f3a7196b1b909f4` | changed |
| `bfs.sys` | 26H1 | `38ff950a0fd38a21` | `ebffdd1b7cfa6bc1` | changed |

`bindflt.sys` is byte-for-byte identical across the August update on both
branches. It was never touched. The corrected title is the accurate one: this is
**`bfs.sys`**, the Brokering File System — the kernel component that brokers file
access for packaged and AppContainer applications.

Worth keeping in the toolbox: when an advisory is ambiguous about the component,
hash equality across the patch is a definitive answer, and it costs one download.

## The diff

`bfs.sys` is small — about 165 KB and 264 functions, against the 5 MB and 8,400
functions of `dxgkrnl.sys` in the Graphics Kernel writeup. Analysis takes seconds
rather than minutes.

Both serviced branches, intersected:

```
24H2/25H2  26100.8972 -> 26100.9168 : 8 changed, 8 added, 1 removed
26H1       28000.2605 -> 28000.2704 : 8 changed, 8 added, 1 removed
```

The same eight functions in both:

```
BfsPreloadPolicyEntriesForDeleteList   799 -> 1097  (+298)
BfsRenameEntry                        1610 -> 1770  (+160)
BfsCloseStorage                        213 ->  317  (+104)
BfsInsertDirectoryEntry               1250 -> 1333   (+83)
BfsInsertDirectoryEntry_OLD           1237 -> 1318   (+81)
BfsDereferenceTableEntry               295 ->  366   (+71)
BfsInsertPolicyEntryLocked            1837 -> 1889   (+52)
BfsInsertPolicyEntry                  2060 -> 2108   (+48)

removed: BfsCloseRootDirectory   (inlined into BfsCloseStorage)
```

Every single one grew. Nothing shrank, nothing was restructured for size. That
is the signature of added validation rather than refactoring, and with only eight
candidates there is nowhere for the bug to hide.

## The overflow

`BfsRenameEntry`, before the patch:

```c
Entry = BfsFindEntry(v10, v61);
if ( Entry )
{
  memset((void *)(Entry + 20), 0, 0x200u);              // 512-byte destination
  memmove((void *)(v20 + 20), Src[1], LOWORD(Src[0]));  // no bound check
  Directory = BfsGetEntryBlock(v10, v20, StartingIndex, v58);
  ...
}
```

`Src` is a `UNICODE_STRING`:

```
+0x00  Length         USHORT      -> LOWORD(Src[0])
+0x02  MaximumLength  USHORT
+0x08  Buffer         PWSTR       -> Src[1]
```

So the copy length is the caller-supplied name length, and the destination is a
**fixed 512-byte field** inside the heap-allocated directory entry — which is
precisely what the `memset` on the line above is clearing. Nothing checks that
one fits inside the other.

`Length` is a `USHORT`. A rename with a name longer than 512 bytes writes past
the end of the field into adjacent pool memory, and the overflow can run up to
roughly 64 KB.

That is the CWE-122, and it is about as textbook as the class gets: a fixed-size
inline buffer, a caller-controlled length, and a `memmove` between them.

The patched version:

```c
if ( (unsigned int)Feature_3252922680__private_IsEnabledDeviceUsageNoInline()
     && LOWORD(Src[0]) > 0x1FEu )
{
  ExReleasePushLockExclusiveEx(v10, 0);
  KeLeaveCriticalRegion();
  BfsDereferenceTableEntry((PVOID)(v17 - 8));
  Directory = -1073741562;               // 0xC0000106 STATUS_NAME_TOO_LONG
}
else
{
  memset((void *)(Entry + 20), 0, 0x200u);
  memmove((void *)(Entry + 20), Src[1], LOWORD(Src[0]));
  ...
}
```

`0x1FE` is 510 — the 512-byte field minus two bytes for the UTF-16 NUL
terminator. The bound is exactly right, which is a small sign that somebody
looked at the structure rather than picking a round number.

## Counting the fix sites

Reading one function proves a fix exists. Counting the fix across the whole
binary proves you have found *the* fix.

So: search every instruction in both builds for a comparison against `1FEh`.

```
26100.8972_BEFORE : 0 occurrences
26100.9168_AFTER  : 4 occurrences

    BfsInsertDirectoryEntry       mov  eax, 1FEh
    BfsInsertDirectoryEntry_OLD   mov  eax, 1FEh
    BfsRenameEntry                mov  eax, 1FEh
    BfsRenameEntry                mov  eax, 1FEh
```

Zero before. Four after. In exactly the three functions that grew by +83, +81
and +160 bytes — the three largest unexplained deltas in the diff, now
explained.

The same missing length check on the same 512-byte name field, in four places:
both directory-insert paths (including the legacy `_OLD` variant, which somebody
remembered to fix) and two sites inside rename. This is one bug, duplicated
wherever a name gets copied into a directory entry.

## A false lead worth showing

Before finding the real thing I spent a while convinced the bug was in
`BfsInsertPolicyEntryLocked`, which allocates and copies SIDs:

```c
Pool2 = ExAllocatePool2(256, 4LL * *((unsigned __int8 *)SourceSid + 1) + 8, ...);
v10   = ExAllocatePool2(256, 4LL * a6[1] + 8, ...);
...
RtlCopySid(4 * *((unsigned __int8 *)SourceSid + 1) + 8, Pool2, SourceSid);
RtlCopySid(4 * *((unsigned __int8 *)Sid + 1) + 8, v10, Sid);
```

The allocation for `v10` uses `a6[1]` while the copy uses `*((BYTE *)Sid + 1)`.
A SID is `8 + 4 * SubAuthorityCount` bytes with `SubAuthorityCount` at offset 1,
so if `a6` were a `_QWORD *`, `a6[1]` would be reading eight bytes from offset 8
— a completely different field — and the allocation would not match the copy.
That is exactly the shape of a heap overflow.

It isn't one. The function signature says:

```c
__int64 __fastcall BfsInsertPolicyEntryLocked(..., unsigned __int8 *a6, ...)
```

`a6` is a **byte** pointer, so `a6[1]` *is* `SubAuthorityCount`. The two
expressions are the same value written two different ways, and both lines are
identical before and after the patch.

I am including this because array indexing in decompiler output is only
meaningful together with the pointer's declared type, and it is an easy way to
talk yourself into a vulnerability that isn't there. Checking the signature took
ten seconds and saved a wrong writeup.

## The other five functions

The remaining changes are not length checks at all — they are object-lifetime
hardening, bundled into the same update.

**`BfsDereferenceTableEntry`** — re-check the refcount under the lock:

```c
for ( i = _InterlockedExchangeAdd(Buffer + 38, 0xFFFFFFFF); i == 1; ... )
{
  ExAcquirePushLockExclusiveEx(v5, 0);
+ if ( Feature_3150426426...() && *((_DWORD *)v1 + 38) )
+ {
+   ExReleasePushLockExclusiveEx(...);
+   KeLeaveCriticalRegion();
+   return;                                   // someone re-referenced it: do NOT free
+ }
  ... unlink and free
```

A resurrection race. The count is atomically driven to zero, but between that
decrement and acquiring the lock another thread can find the entry still in the
table and take a reference. Without the re-check the object is freed while
someone holds it.

**`BfsCloseStorage`** — do not keep walking a table you just freed:

```c
   if ( RtlIsGenericTableEmptyAvl(...) )
     BfsDereferenceTableEntry(p_DeleteCount);        // may free the entry
-  else
-    v4 = (RTL_AVL_TABLE *)(p_DeleteCount + 40);     // continue from that entry
+  { ... reset the enumeration root back to (P + 10) ... }
```

The old loop could continue enumerating from a pointer *into* the entry it had
just released.

**`BfsPreloadPolicyEntriesForDeleteList`** — switches from weak to **strong**
hash-table enumeration (`RtlInitStrongEnumerationHashTable`,
`RtlStronglyEnumerateEntryHashTable`), which pins entries so they cannot be
removed mid-walk. That is the canonical fix for "entry freed while enumerating"
and it accounts for the largest delta in the diff, +298 bytes.

**`BfsInsertPolicyEntry` / `Locked`** — state-machine tightening around the
pending-insert states.

So the August `bfs.sys` update is really two themes in one: the CWE-122 name
overflow that the CVE describes, and a cluster of lifetime fixes that it doesn't
mention. Whether those are a second CVE, an internal audit, or defence in depth,
the advisory doesn't say.

## Feature flags, again

Every one of these fixes is gated behind a WIL velocity flag, with the original
code kept in the `else` branch:

| Flag | Guards |
|---|---|
| `Feature_3252922680` | the `0x1FE` length bound — **the CWE-122 fix** |
| `Feature_3150426426` | refcount re-check under the lock |
| `Feature_1154987323` | enumeration reset in `BfsCloseStorage` |
| `Feature_331850041` | strong hash-table enumeration |

That is now three consecutive Microsoft patches in this series — NTFS, then
`dxgkrnl`, now `bfs` — where the security fix is runtime-gated rather than
unconditional, and the vulnerable path is still compiled in and reachable.

I have not resolved what the default state is for any of them. Which means, for
the third time: "patched" and "protected" are not automatically the same claim,
and I am not in a position to tell you which one your machine is.

## Why there is no PoC this time

Short version: the lab guest does not contain the vulnerable function.

The CVE affects Windows 11 24H2, 25H2, 26H1 and Server 2025. Notably **not**
22H2 or 23H2. My lab guest is 22H2, build 22621.6060, and pulling its `bfs.sys`
apart shows why that matters:

- **`BfsRenameEntry` does not exist in that build at all.** The primary
  vulnerable function is simply absent.
- `BfsInsertDirectoryEntry` exists and has a similar unchecked shape, but
  against a different field size:

  ```c
  memset((void *)(v15 + v14 + 12), 0, 0x210u);       // 0x210, not 0x200
  memmove(v16 + 5, a5[1], *(unsigned __int16 *)a5);  // still unbounded
  ```

- Zero occurrences of the `1FEh` bound, as expected for an unpatched build.

So the guest is structurally similar but is not the affected code. Running an
exploit attempt against it would produce a result — crash or no crash — that
says nothing whatsoever about this CVE. That is worse than no result, because it
looks like evidence.

Doing this properly needs a 24H2-or-later target and a harness that drives the
Brokering File System's rename path, which is the broker used for file
redirection by packaged applications. That is a different afternoon.

## What this is worth

- **Type: heap-based buffer overflow (CWE-122)**, and here the CWE and the code
  actually agree — unlike the NTFS `$EA` case, where a CWE-122 label sat on top
  of an out-of-bounds *read*.
- **A write primitive.** Attacker-controlled data, attacker-controlled length,
  into a pool allocation. That is the ingredient the NTFS read bug lacked, and
  it is why this rates a genuine path to SYSTEM rather than an information leak.
- **Low privilege, no user interaction** (`AV:L/AC:L/PR:L/UI:N`). No crafted
  volume, no race to win. Just a long name.
- **`E:U`** — no known exploit code, not publicly disclosed, not in CISA KEV.

And the honest limit: **everything here is static.** I did not execute anything,
did not corrupt a pool block, did not build a PoC. The evidence is the
before/after code, the four-versus-zero count of the bound check, and the fact
that both serviced branches received the identical change. I think that is a
solid identification. It is not a demonstration, and I am not going to blur the
two.

## Artifacts

| File | What it is |
|---|---|
| [`BFS_findings.txt`](/assets/posts/bfs-directory-entry-heap-overflow/BFS_findings.txt) | Full analysis: the hash comparison that resolved the driver ambiguity, the complete diff, the before/after overflow code, the fix-site count, the SID false lead, and an explicit statement of what was not done. |

## What was worth learning

**Hash equality resolves component ambiguity.** When the advisory names two
possible drivers, the one whose SHA-256 is unchanged across the update is not
the one. That took one index lookup and settled a question the vendor's own
record was confused about.

**Small binaries are a gift.** 264 functions and eight changes meant the bug had
nowhere to hide. Some of the best patch-diffing targets are the unglamorous
little drivers, not the million-line ones.

**Count the fix, don't just read it.** Finding the `0x1FE` check in
`BfsRenameEntry` was suggestive. Finding that it appears zero times before and
four times after, in precisely the three functions with unexplained size growth,
is proof. A one-line query turned a hypothesis into a closed case.

**Check the pointer type before believing the index.** `a6[1]` means completely
different things depending on whether `a6` is a `BYTE *` or a `_QWORD *`, and
one of those readings is a heap overflow that does not exist. Decompiler output
is a hypothesis, not a source file.

**Know when your lab cannot answer the question.** The guest was missing the
vulnerable function entirely. Testing anyway would have produced an outcome that
looked like evidence and wasn't.

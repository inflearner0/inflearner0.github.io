---
title: "CVE-2026-61346 — Windows Graphics Kernel Elevation of Privilege Vulnerability: A Missing `lock` Prefix"
date: 2026-08-17 17:00:00 +0200
categories: [Vulnerability Research, Windows Kernel]
tags: [windows, dxgkrnl, patch-diffing, winbindex, ida, kernel-debugging, kdnet, use-after-free, race-condition, refcount, reverse-engineering]
---

Some vulnerabilities take a week to find. This one is a single missing
instruction prefix, and once you are looking at the right three instructions it
is impossible to miss.

`CVE-2026-61346` is a use-after-free in the Windows Graphics Kernel, patched on
11 August 2026. Microsoft's advisory is four lines long and the interesting part
is buried in an FAQ entry: *"successful exploitation of this vulnerability
requires an attacker to win a race condition."*

That sentence plus **CWE-416** tells you the shape of the bug before you open a
disassembler. Something in `dxgkrnl.sys` has an object whose lifetime is managed
without proper synchronisation. This post is about finding exactly which object,
and then proving the race is real by reading the instructions out of a live
kernel.

The whole fix turns out to be one word: `lock`.

## Table of contents

1. [Reading the advisory](#reading-the-advisory)
2. [Getting the binaries](#getting-the-binaries)
3. [When byte-diffing fails](#when-byte-diffing-fails)
4. [The function inventory diff](#the-function-inventory-diff)
5. [The answer, in the added-functions list](#the-answer-in-the-added-functions-list)
6. [The vulnerable Release](#the-vulnerable-release)
7. [Three instructions, two race windows](#three-instructions-two-race-windows)
8. [The increment side was worse](#the-increment-side-was-worse)
9. [The fix](#the-fix)
10. [Reachability](#reachability)
11. [Proving it on a live kernel](#proving-it-on-a-live-kernel)
12. [Trying to win the race, and failing](#trying-to-win-the-race-and-failing)
13. [What this is worth](#what-this-is-worth)
14. [Artifacts](#artifacts)
15. [What was worth learning](#what-was-worth-learning)

## Reading the advisory

```
Use after free in Windows Graphics Kernel allows an authorized attacker
to elevate privileges locally.

CVSS 3.1: 7.0  AV:L/AC:L... no — AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H
CWE-416: Use After Free
Exploit maturity: E:U (unproven)
```

Three fields matter here.

**`AC:H`** — high attack complexity. Microsoft spells out why in the FAQ: you
have to win a race. That is a strong hint that the fix will be synchronisation,
not bounds checking.

**`PR:L`** — low privileges required. Any authenticated user. Combined with
"could gain SYSTEM privileges" from the FAQ, this is a straight local privilege
escalation.

**`E:U`** — no known exploit code. No PoC to read, nothing on GitHub, not in
CISA KEV. Nothing to work from except the patch.

"Windows Graphics Kernel" in Microsoft's advisory vocabulary means
**`dxgkrnl.sys`**, the DirectX graphics kernel subsystem. It is about 5 MB and
exposes a very large syscall surface to unprivileged user mode, which is why it
is such a popular LPE target.

Fixed builds, from the CVE record:

| Branch | Fixed in |
|---|---|
| Windows 11 24H2 / 25H2 | `.9168` |
| Windows 11 26H1 | `28000.2704` |
| Windows 11 23H2 | `22631.7517` |
| Windows 10 21H2 / 22H2 | `19044.7663` / `19045.7663` |
| Server 2025 | `26100.33296` |

`.9168` shipped on 11 August — August Patch Tuesday.

## Getting the binaries

Same approach as
[the NTFS writeup](/posts/ntfs-ea-oob-read-patch-diff/): winbindex indexes every
`dxgkrnl.sys` that has ever shipped, keyed by SHA-256, and each entry carries the
PE `TimeDateStamp` and `SizeOfImage` that form the Microsoft symbol-server key.

512 entries for `dxgkrnl.sys`. Filtered to the branches I care about, the pairs
fall out immediately:

| Branch | Before | After |
|---|---|---|
| 24H2 / 25H2 | `26200.8973` (28 Jul) | **`26200.9168` (11 Aug)** |
| 26H1 | `28000.2608` (28 Jul) | **`28000.2704` (11 Aug)** |

Two independently-serviced branches, both updated on Patch Tuesday. As before I
downloaded both pairs plus their PDBs, so I could intersect the changed-function
sets and throw away anything that only appears in one branch.

All four SHA-256 hashes matched the winbindex index keys exactly.

## When byte-diffing fails

Here is a detour worth including because it cost me ten minutes and taught me
something.

The before and after files are **exactly the same size** — 5,207,584 bytes for
the 24H2 pair, byte-for-byte identical in length. That is unusual and very
tempting: if the image layout did not move, a raw byte diff should point straight
at the patched bytes.

So I wrote one. It walks both files, collects runs of differing bytes, merges
runs separated by small gaps, and attributes each run to its PE section.

```
sizes: 5207584 vs 5207584
differing runs: 435506 (raw), 6915 (merged)

=== .text   : 938 runs,  531385 bytes ===
=== .rdata  : 128 runs,  757295 bytes ===
=== PAGE    : 5640 runs, 2302042 bytes ===
=== .pdata  : 1 runs,    104691 bytes ===
```

2.3 MB of `PAGE` and half a megabyte of `.text` differ. This is a **full
recompile**: different codegen, different register allocation, different inlining
decisions throughout. The identical file size was a coincidence of a
layout-stable build, not evidence of a small change.

The lesson: **file size tells you nothing about patch size.** A monthly
cumulative rebuild touches almost every byte. Byte diffing only works when you
are comparing a hotpatch or a genuinely surgical binary update; for a normal
Patch Tuesday build you need a semantic diff.

## The function inventory diff

So: load all four binaries into IDA with their PDBs applied, let auto-analysis
finish, and export the function list from each — name, size, instruction count.
With symbols the names are stable across builds, so functions can be matched by
name and compared.

`dxgkrnl.sys` has around 8,400 functions. The result was astonishingly clean:

```
24H2: before=8424 after=8435  |  added=14 removed=3 changed=24
26H1: before=8475 after=8487  |  added=16 removed=4 changed=26
```

**24 changed functions out of 8,424.** After intersecting both branches and
dropping the `Feature_*` staging stubs, 27 names survive — and they are all in
one subsystem:

```
?AddRef@CFlipPropertySetBase@@QEAAKXZ          <- NEW
?AddRef@CFlipResource@@QEAAKXZ                 <- NEW
?Release@CFlipPropertySetBase@@QEAAKXZ
?Release@CFlipResource@@QEAAKXZ
?SetBoundBuffer@CContentResourceState@@...
?SetBoundPropertySet@CContentResourceState@@...
?SetFlipPropertySet@CFlipPresentUpdate@@...
??1CContentResourceState@@UEAA@XZ
?Remove@CContentResourceState@@UEAAXXZ
?Create@CContentResource@@...
?Create@CPoolBufferResource@@...
?ConsumerAcquirePresent@CFlipManager@@...
NtFlipObjectQueryNextMessageToProducer
...
```

Every one of them is in the **flip object / presentation** path — the plumbing
behind desktop composition and swapchain presents.

## The answer, in the added-functions list

Before decompiling anything, look at the size deltas:

```
?Release@CFlipPropertySetBase@@QEAAKXZ    42 -> 82   (+40)   insns 14 -> 28  (+14)
?Release@CFlipResource@@QEAAKXZ           42 -> 82   (+40)   insns 14 -> 28  (+14)
```

Both `Release` methods exactly doubled. And in the *added* list:

```
+ ?AddRef@CFlipPropertySetBase@@QEAAKXZ
+ ?AddRef@CFlipResource@@QEAAKXZ
```

Two classes that had a `Release` but **no `AddRef` at all**, now suddenly have
one, while their `Release` doubles in size.

That is a reference-counting fix, and CWE-416 plus "win a race condition" says
what kind. At this point the bug is essentially identified; the rest is
confirming the details.

## The vulnerable Release

```c
__int64 __fastcall CFlipResource::Release(CFlipResource *this)
{
  bool v1;
  unsigned int v2;

  v1 = (*((_DWORD *)this + 6))-- == 1;      // decrement, test against 1
  v2 = *((_DWORD *)this + 6);               // re-read
  if ( v1 )
    (**(void (__fastcall ***)(CFlipResource *, __int64))this)(this, 1);  // destructor
  return v2;
}
```

The refcount lives at `this+0x18` (`_DWORD` index 6). `CFlipPropertySetBase` is
identical with the field at `this+0x08`.

Decompiled C hides the important part, though. Here is the same function
disassembled out of a **live kernel** over KDNET:

```
dxgkrnl!CFlipResource::Release:
  fffff807`26a22298 4053            push    rbx
  fffff807`26a2229a 4883ec20        sub     rsp,20h
  fffff807`26a2229e 834118ff        add     dword ptr [rcx+18h],0FFFFFFFFh
  fffff807`26a222a2 8b5918          mov     ebx,dword ptr [rcx+18h]
  fffff807`26a222a5 7511            jne     dxgkrnl!CFlipResource::Release+0x20

dxgkrnl!CFlipResource::Release+0xf:
  fffff807`26a222a7 488b11          mov     rdx,qword ptr [rcx]
  fffff807`26a222aa 488b02          mov     rax,qword ptr [rdx]
  fffff807`26a222ad ba01000000      mov     edx,1
  fffff807`26a222b2 e8e98f4000      call    fffff807`26e2b2a0      ; destructor
```

## Three instructions, two race windows

```
add   dword ptr [rcx+18h], 0FFFFFFFFh    (A)
mov   ebx, dword ptr [rcx+18h]           (B)
jne   +0x20
```

**(A) has no `lock` prefix.** `add [mem], imm` is one instruction, but on x86 it
is internally a read-modify-write, and without `lock` it is *not* atomic across
cores. Two CPUs can both read the old value, both compute the decrement, and both
write the same result.

**(B) is a second, independent read** of the same field. Even if (A) were atomic,
the value returned to the caller and the value used for the zero test come from
two different moments in time.

Three instructions, two ways to lose.

The benign losing case:

```
refcount = 2,  T1 and T2 both call Release()

  T1 reads 2
  T2 reads 2
  T1 writes 1
  T2 writes 1        -> one decrement lost, count never reaches 0, object leaks
```

The dangerous one:

```
refcount = 1,  T1 and T2 both call Release()

  T1: add -> 0, ZF=1
  T2: add -> 0, ZF=1     (both observe the transition to zero)
  T1 calls the destructor
  T2 calls the destructor   -> double free -> use-after-free
```

The second interleaving frees an object twice. Everything downstream — the
freed pool block being reallocated by an attacker-controlled spray, the virtual
call through `(**(...)this)` at `+0xf` reading a hijacked vtable pointer — is the
standard UAF-to-SYSTEM playbook from there.

Note the destructor is reached through a *virtual call*: `mov rdx,[rcx]` loads
the vtable, `mov rax,[rdx]` loads the first entry. An attacker who controls the
reallocated memory controls that pointer. That is why this is `C:H/I:H/A:H` and
not merely a crash.

## The increment side was worse

The missing `AddRef` methods are the other half of the story. Before the patch,
increments were not merely unsynchronised — they were *inlined at every call
site*:

```c
// CContentResourceState::SetBoundPropertySet   BEFORE
v4 = (CFlipPropertySetBase *)*((_QWORD *)this + 5);
if ( v4 != a2 )
{
  if ( v4 )
    CFlipPropertySetBase::Release(v4);
  *((_QWORD *)this + 5) = a2;
  if ( a2 )
    ++*((_DWORD *)a2 + 2);        // <-- inline, non-atomic increment
  *((_BYTE *)this + 64) |= 1u;
}
```

```c
// CContentResourceState::SetBoundPropertySet   AFTER
  if ( a2 )
    CFlipPropertySetBase::AddRef(a2);   // <-- proper atomic method
```

That single-line change is the `+5` byte delta seen on `SetBoundPropertySet`,
`SetBoundBuffer` and `SetFlipPropertySet` in the diff — an inline `inc dword ptr`
replaced by a `call`. Three call sites, five bytes each, and they were the tell
that a whole ownership model was being rewritten.

## The fix

```
call    Feature_562023738__private_IsEnabledDeviceUsageNoInline
test    eax, eax
jz      short legacy_path

or      ebx, 0FFFFFFFFh
lock xadd [rdi+18h], ebx        ; atomic, returns the OLD value
dec     ebx                     ; new value derived, not re-read
jmp     short common_tail

legacy_path:
mov     ebx, [rdi+18h]          ; original non-atomic sequence, retained
dec     ebx
mov     [rdi+18h], ebx

common_tail:
test    ebx, ebx
jnz     short ret
test    rdi, rdi                ; added NULL check
jz      short ret
...
call    _guard_dispatch_icall   ; destructor
```

`lock xadd` closes both windows in one instruction. The decrement is atomic, and
the value tested for zero is the one the atomic operation returned rather than a
fresh read. Exactly one thread can observe the transition to zero, so exactly one
destructor call happens. `AddRef` gets the mirror-image `_InterlockedIncrement`.

And once again — as with the NTFS EA fix — **the fix is gated behind a feature
flag**, `Feature_562023738`. The `else` branch still contains the original
non-atomic sequence, compiled in and reachable. Whether a patched machine is
actually protected depends on runtime feature state, which is a separate question
from whether the update is installed.

Two of these in two months is a pattern worth noticing.

## Reachability

The flip objects are driven by 21 syscalls that `dxgkrnl` exposes to
unprivileged user mode:

```
NtFlipObjectCreate                  NtFlipObjectSetContent
NtFlipObjectOpen                    NtFlipObjectAddContent
NtFlipObjectAddPoolBuffer           NtFlipObjectRemoveContent
NtFlipObjectRemovePoolBuffer        NtFlipObjectConsumerAcquirePresent
NtFlipObjectConsumerPostMessage     NtFlipObjectQueryNextMessageToProducer
NtFlipObjectDisconnectEndpoint      NtFlipObjectPresentCancel
...
```

`SetContent`, `AddContent` and `RemoveContent` are the ones that reach
`CContentResourceState::SetBoundPropertySet` and `::SetBoundBuffer` — precisely
the call sites whose inline increments were converted to `AddRef`. Two threads
hammering those paths against the same flip object is the primitive, and
`AC:H` is Microsoft's own assessment of how tight the window is.

## Proving it on a live kernel

The lab guest is Windows 11 22H2, build 22621.6060 — a build that, like last
time, is **not in the CVE's affected list**. And, like last time, that turns out
to be a servicing-scope artefact rather than a statement about the code.

Pulling `dxgkrnl.sys` out of the running guest, downloading its PDB and loading
it in IDA:

```c
__int64 __fastcall CFlipResource::Release(CFlipResource *this)
{
  v1 = (*((_DWORD *)this + 6))-- == 1;
  v2 = *((_DWORD *)this + 6);
  if ( v1 )
    (**(...)this)(this, 1);
  return v2;
}
```

Identical. And searching that build for the reference-counting methods:

```
?UnlockAndRelease@CFlipManagerToken@@QEAAXXZ
?Release@CFlipPropertySetBase@@QEAAKXZ
?Release@CFlipResource@@QEAAKXZ
```

No `AddRef` anywhere. The guest carries the same unprotected ownership model, so
the KDNET disassembly above is the vulnerable code as it actually executes.

For the debugger setup itself — KDNET configuration, the PowerShell Direct
interaction, and the trap where the reported encryption key did not match the
one the guest was using — see the
[NTFS writeup](/posts/ntfs-ea-oob-read-patch-diff/#building-the-lab). Same lab,
same gotchas.

## Trying to win the race, and failing

Everything above is static analysis plus a disassembly listing. That proves the
bug is real; it does not prove the race is winnable. So I tried to win it.

I did not. Here is exactly how far I got, because a documented failure is more
useful than a vague claim.

**The syscalls are reachable.** All 21 `NtFlipObject*` entry points are exported
by `win32u.dll`, so no syscall-stub work is needed — a plain `DllImport` reaches
them:

```
NtFlipObjectCreate -> 0x00000000   handle=0x2D0
```

An ordinary user-mode process can create a flip object. Good start.

**The instrumentation works.** Three breakpoints over KDNET — the two `Release`
methods plus `DxgkCompositionObject::Create` as a control, since that is what
`NtFlipObjectCreate` calls internally:

```
Breakpoint 2 hit
dxgkrnl!DxgkCompositionObject::Create:
fffff807`269b416c 4c8bdc          mov     r11,rsp
```

The control fired. Breakpoints are live and the syscall path executes.

**The race attempt.** Eight threads hammering `AddContent` / `SetContent` /
`RemoveContent` against one shared flip object for thirty seconds:

```
spinning 8 threads for 30s ...
iterations: 22542232
survived (no bugcheck)

CFlipResource::Release        -> NEVER FIRED
CFlipPropertySetBase::Release -> NEVER FIRED
```

22.5 million iterations. Zero hits on either `Release`. The refcount code never
executed once, so **no race was ever contested**. The absence of a crash here
means nothing at all — I never got to the starting line.

**Why.** Per-call status codes exposed the problem immediately:

```
Create        0x00000000
AddContent    0xC0000005    STATUS_ACCESS_VIOLATION
SetContent    0xC0000005    STATUS_ACCESS_VIOLATION
RemoveContent 0xC0000005    STATUS_ACCESS_VIOLATION
```

`ACCESS_VIOLATION` means the kernel was probing my arguments as **user-mode
pointers**. My signatures were guesses, and they were wrong. The real one:

```c
NtFlipObjectAddContent(void *handle,
                       unsigned __int64 *contentId,   // pointer, probed
                       unsigned int count,
                       void *items)                   // FlipPropertyItem[]
{
  ...
  v8 = *a2;
  FlipPropertySet = CreateFlipPropertySetWorker<CFlipPropertySet>(a3, a4);
  if ( FlipPropertySet >= 0 )
    FlipPropertySet = FlipManagerObject::ResolveHandle(a1, 2u, v10, &v12);
  if ( FlipPropertySet >= 0 )
    FlipPropertySet = FlipManagerObject::AddContent(v12, v8, 0);
}
```

Note `CreateFlipPropertySetWorker<CFlipPropertySet>` — that allocates precisely
the object whose refcount is vulnerable. The path is right; I just cannot get
through the door.

Retrying with correct pointer semantics:

```
AddContent cnt=0 buf=64   -> 0xC0000022   STATUS_ACCESS_DENIED
AddContent cnt=1 buf=256  -> 0xC000000D   STATUS_INVALID_PARAMETER
AddContent cnt=4 buf=1024 -> 0xC000000D   STATUS_INVALID_PARAMETER
```

The `ACCESS_VIOLATION` is gone, so the pointer handling is now correct. Two
blockers remain:

- **`count = 0` → ACCESS_DENIED**, failing inside
  `FlipManagerObject::ResolveHandle`. The handle from `NtFlipObjectCreate` does
  not carry the rights this call wants — the object almost certainly has to be
  opened in a specific producer/consumer endpoint role first. `NtFlipObjectOpen`
  also rejects my guessed signature.
- **`count >= 1` → INVALID_PARAMETER.** The `FlipPropertyItem` layout is wrong.
  It is recoverable from
  `CFlipPropertySet(unsigned int, FlipPropertyItem *, void *, unsigned int)`,
  but I did not reverse it.

**And an environmental doubt worth stating.** Neither `Release` breakpoint fired
during ordinary system operation either, with `dwm.exe` running. This guest's
display adapter is *Microsoft Hyper-V Video* — a synthetic device with no
WDDM flip-model support — and there is no interactive session. The flip path may
simply be cold on this hardware no matter how correct my calls become. A GPU-PV
enabled VM or physical hardware would settle that.

So: the attempt was real, instrumented, and unsuccessful. Winning this race
needs the endpoint role model and the property-item layout reversed properly,
and probably hardware that actually uses the flip present path. That is a
different project, and `AC:H` is starting to look like an understatement.

## What this is worth

Being precise, because this is where writeups usually overclaim:

- **Type: use-after-free (CWE-416)** via a lost update on a non-atomic reference
  count. Winning the race frees an object twice.
- **Impact ceiling: SYSTEM.** Unlike an out-of-bounds *read*, this one really
  does have a path to code execution — the destructor is invoked through a
  virtual call, so controlling the reallocated pool block controls `rip`.
- **Reachable from low privilege** through the `NtFlipObject*` syscalls. No admin,
  no crafted hardware, no user interaction.
- **Hard to win.** `AC:H` is honest. The window is three instructions wide, and
  you need two threads to land inside it on the same object while the count is
  at exactly 1.

**What I did not do: win the race.** I tried — the whole attempt is documented
[above](#trying-to-win-the-race-and-failing) — and 22.5 million iterations later
the vulnerable function had not executed a single time. This post proves the
vulnerable instruction sequence exists in a live kernel, that it is genuinely
non-atomic, that the patched build replaces it with a locked instruction, and
that the increment path was unprotected too. It does not include a working
exploit, and I am not going to pretend that instruction-level root-cause
evidence is the same thing as one.

The gap between "this is a real race" and "I can win this race reliably enough to
groom the pool and hijack a vtable" is most of the work in a real LPE chain, and
it is exactly the part `AC:H` is describing.

## Artifacts

| File | What it is |
|---|---|
| [`RACE_evidence.txt`](/assets/posts/dxgkrnl-flip-refcount-uaf/RACE_evidence.txt) | The live-kernel disassembly, the patched sequence, both losing interleavings, and an explicit statement of what is and is not proven. |
| [`bytediff.py`](/assets/posts/dxgkrnl-flip-refcount-uaf/bytediff.py) | The raw byte-diff tool from the failed detour — grouped runs attributed to PE sections. Useful when a patch really is surgical. |
| [`diffdb.py`](/assets/posts/dxgkrnl-flip-refcount-uaf/diffdb.py) | Function-inventory diff: added, removed and changed functions by name with size and instruction-count deltas. |
| [`RACE_ATTEMPT.txt`](/assets/posts/dxgkrnl-flip-refcount-uaf/RACE_ATTEMPT.txt) | Full log of the failed race attempt — every status code, the corrected signature, and the two remaining blockers. |
| [`fliprace.cs`](/assets/posts/dxgkrnl-flip-refcount-uaf/fliprace.cs) | The multi-threaded harness. It reaches `NtFlipObjectCreate` successfully and gets no further; published as a starting point, not a working exploit. |

## What was worth learning

**Read the FAQ, not just the CVSS string.** "Requires an attacker to win a race
condition" narrowed the search to synchronisation before a single byte was
disassembled. The vector alone would not have told me that.

**Same file size does not mean small patch.** 5,207,584 bytes before and after,
and 2.3 MB of the file differs. Monthly builds are full recompiles. Byte-level
diffing is the wrong tool unless you already know the update is surgical.

**The added-functions list is the highest-signal part of a diff.** Two new
`AddRef` methods appearing beside two doubled `Release` methods identified the
bug class before any decompilation. Functions that *appear* often say more than
functions that merely change.

**Read the disassembly, not just the pseudocode.** Hex-Rays renders the bug as
`(*((_DWORD *)this + 6))--`, which looks entirely ordinary. The vulnerability is
the absence of a four-letter prefix that the decompiler does not show you.

**A missing `lock` is a security bug.** It reads as a performance detail. On a
refcount that governs object lifetime, on a multiprocessor system, reachable from
unprivileged syscalls, it is a use-after-free with a path to SYSTEM.

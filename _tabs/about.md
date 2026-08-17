---
# the default layout is 'page'
icon: fas fa-info-circle
order: 4
---

I'm **inflearner**. I do Windows kernel vulnerability research, and this is where
I write up what I find.

Most of it starts the same way: a four-line MSRC advisory, a CWE number, and a
binary that changed by a few hundred bytes. The advisory is never the
interesting part. The interesting part is the specific instruction that moved,
and whether the story you build around it survives contact with a live kernel.

## What you'll find here

### Patch diffing

Pulling pre- and post-patch binaries out of
[Winbindex](https://winbindex.m417z.com/), diffing them, and working down to the
individual change the CVE is about — including the awkward case where one patch
fixes several bugs and nobody tells you which change belongs to which CVE.

- [CVE-2026-50313 — an `$EA` out-of-bounds read in NTFS]({% post_url 2026-08-17-ntfs-ea-oob-read-patch-diff %})
- [CVE-2026-61346 — a missing `lock` prefix in `dxgkrnl.sys`]({% post_url 2026-08-17-dxgkrnl-flip-refcount-uaf %})

### Exploitation

Taking a primitive from "this reads out of bounds" to something concrete on a
target with SMEP, KASLR, DEP and CFG all enabled — and being explicit about
which steps the target handed me and which ones had to be earned.

- [The Vulnerable Password Manager]({% post_url 2026-08-17-vulnerable-password-manager %})
  — four information leaks and a ring 0 ROP chain against a deliberately
  vulnerable driver.

### Lab and tooling notes

The infrastructure the above runs on: kernel debugging setups that actually
stay attached, hypervisor work, and the various ways a virtual machine can lie
to you about being alive. Less of this is written up so far; more is coming.

## How I work

A few rules I hold myself to, because they're the difference between a writeup
and a guess:

- **Read the instructions, not the summary.** If a claim can be settled in a
  disassembler or a kernel debugger, it gets settled there rather than argued
  from documentation.
- **Prove it on a live system.** Static analysis tells you what *should*
  happen; a breakpoint tells you what *does*. These posts end with output from
  a real kernel, not a screenshot of pseudocode.
- **Say when I'm wrong, and say what I forced.** If the bug I found turns out
  not to be the CVE I started from, that goes in the post. If part of a crash
  was set up by hand rather than reached organically, that goes in the post
  too.

## Tools

IDA Pro and the Hex-Rays decompiler, WinDbg and `kd` over KDNET and KDCOM,
Winbindex for binary archaeology, Hyper-V for targets, and a steady supply of
throwaway harnesses.

## Ground rules

Everything published here targets vulnerabilities that are **already patched**,
on machines I own. The writeups explain mechanisms. They are not drop-in
exploits, and I leave out the parts that would only be useful for pointing at
somebody else's machine.

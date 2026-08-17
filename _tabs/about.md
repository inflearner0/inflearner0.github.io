---
# the default layout is 'page'
icon: fas fa-info-circle
order: 4
---

I'm **inflearner**, a security researcher. Most of what I publish here is
Windows kernel vulnerability research, but the thing underneath it is a broader
interest in how computers actually work — compilers, machine learning systems,
and systems programming generally.

The security writing usually starts the same way: a four-line MSRC advisory, a
CWE number, and a binary that changed by a few hundred bytes. The advisory is
never the interesting part. The interesting part is the specific instruction
that moved, and whether the story you build around it survives contact with a
live kernel.

## What you'll find here

**Patch diffing.** Pulling pre- and post-patch binaries out of
[Winbindex](https://winbindex.m417z.com/), diffing them, and working down to the
individual change a CVE is about — including the awkward case where one patch
fixes several bugs and nobody tells you which change belongs to which CVE. So
far that has covered an `$EA` out-of-bounds read in NTFS (CVE-2026-50313) and a
missing `lock` prefix in `dxgkrnl.sys` (CVE-2026-61346).

**Exploitation.** Taking a primitive from "this reads out of bounds" to
something concrete on a target with SMEP, KASLR, DEP and CFG all enabled, and
being explicit about which steps the target handed me and which ones had to be
earned.

**Systems and tooling.** The infrastructure the above runs on: kernel debugging
setups that stay attached, hypervisor work, and the various ways a virtual
machine can lie to you about being alive.

**Computer science more broadly.** Compiler theory — IRs, optimisation passes,
and the gap between what you wrote and what the backend decided you meant — and
machine learning and AI systems, mostly from the same angle: what the runtime
is really doing, not what the abstraction promises. Less of this is written up
so far. More is coming.

## How I work

Different subjects, same habits, and they're the difference between a writeup
and a guess:

- **Read the artefact, not the summary.** If a claim can be settled in a
  disassembler, a kernel debugger, or a compiler's own output, it gets settled
  there rather than argued from documentation.
- **Prove it on a live system.** Static analysis tells you what *should*
  happen; a breakpoint tells you what *does*. These posts end with output from
  a real machine, not a screenshot of pseudocode.
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

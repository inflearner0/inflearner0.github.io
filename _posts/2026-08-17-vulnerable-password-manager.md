---
title: "The Vulnerable Password Manager: Four Leaks, One Format String, and a Ring 0 ROP Chain"
date: 2026-08-17 05:30:00 +0200
categories: [Exploitation, Windows Kernel]
tags: [windows, kernel, exploitation, rop, x86-64, kaslr, stack-cookie, ida, reverse-engineering]
---

Somebody wrote a password manager and put it in the kernel.

That sentence is the whole vulnerability class, but the driver in front of me is
more interesting than that joke deserves. It is about 8 KB, it exposes three
IOCTLs on `\\.\pwvault`, it keeps its entries in a doubly linked list
in the non-paged pool, and it hashes every password with SHA-512 before storing
it. Somebody was *trying*.

This was a deliberately vulnerable target in a lab, and the point of writing it
up is the mechanism rather than the answer key, so the names, paths and control
codes here are neutralised. I will call it **pwvault**. Everything structural —
offsets, field layout, gadget shapes, the arithmetic — is exactly as it was.

The stack overflow in it is a one-line mistake. Getting from that one-line
mistake to `nt authority\system` on a Windows 10 1809 box with SMEP, KASLR, DEP
and CFG all on took four separate information leaks, one of which the driver
hands you as a *feature*, and a return path that cannot return.

This is how it went together.

## Table of contents

1. [The attack surface](#the-attack-surface)
2. [What an entry looks like](#what-an-entry-looks-like)
3. [The bug](#the-bug-one-wrong-constant)
4. [Leak 1: the cookie, gift-wrapped](#leak-1-the-cookie-gift-wrapped)
5. [Why the cookie is not the canary](#why-the-cookie-is-not-the-canary)
6. [Leak 2: the error log](#leak-2-the-error-log-is-a-kernel-stack-leak)
7. [Leak 3: KASLR](#leak-3-kaslr-for-free)
8. [Laying out 128 bytes](#laying-out-128-bytes)
9. [Leak 4: where to put the chain](#leak-4-where-to-put-the-chain)
10. [The chain](#the-chain)
11. [The return that cannot return](#the-return-that-cannot-return)
12. [The sacrificial thread](#the-sacrificial-thread)
13. [Things that went wrong](#things-that-went-wrong)
14. [What was worth learning](#what-was-worth-learning)

## The attack surface

The driver creates one device and one symbolic link, and its
`IRP_MJ_DEVICE_CONTROL` handler is a four-way switch on the control code. All
three real IOCTLs are `METHOD_BUFFERED`, so the input and output buffers are
kernel copies at `Irp->AssociatedIrp.SystemBuffer` and the lengths come out of
the `IO_STACK_LOCATION`.

| Code | Name | Input length | Output length |
|---|---|---|---|
| `0x223000` | ADD | must be exactly `0x180` | 8 |
| `0x223004` | GET | must be exactly `8` | must be `>= 0x200` |
| `0x223008` | DEL | must be exactly `8` | 8 |
| anything else | — | — | — |

The length checks are strict equalities, which is a good sign: whoever wrote
this knew that "at least" is where kernel drivers die, and closed it. ADD takes
a 0x180-byte record and returns the new entry's ID. GET takes an ID and renders
that entry back to you as a human-readable line of text. DEL unlinks and frees.

The fourth branch — the one for a control code the driver does not recognise —
is where the story starts, and I will come back to it.

## What an entry looks like

ADD copies its 0x180-byte input into a freshly allocated 0x1D8-byte pool entry.
The mapping is not one-to-one, and the shape of it is the whole exploit:

```
entry+0x000   8      pool/list bookkeeping (id)
entry+0x008   0x100  <- input[0x000 .. 0x100]   title @ +0x08, username @ +0x88
entry+0x108   0x40   encrypted_hash            (computed, not copied)
entry+0x148   0x80   <- input[0x100 .. 0x180]   the password field
entry+0x1C8   0x10   LIST_ENTRY { Flink, Blink }
```

Two things to notice, because both of them matter later.

**256 bytes of the entry are a raw copy of my input.** `title` and `username`
are not strings being `strcpy`'d — the driver takes the whole 0x100 block
verbatim. Embedded NUL bytes survive. That is a 256-byte fully-controlled buffer
in the non-paged pool, and I will eventually put a ROP chain in it.

**The `LIST_ENTRY` is directly above the password field, with nothing between
them.** The password field is 128 bytes at `entry+0x148`; `Flink` starts at
`entry+0x1C8`. A password that is exactly 128 non-NUL bytes has no terminator,
and anything that prints it with `%s` will keep going straight into two pool
pointers.

The `encrypted_hash` field is the only part ADD computes rather than copies, and
it is the cleverest thing in the driver, in the sense that it is the thing that
loses:

```c
SHA512(password, 128, hash);            /* 64 bytes */
for (i = 0; i < 64; i++)
    entry->encrypted_hash[i] = hash[i] ^ key[i % 8];
```

The 8-byte `key` is the driver's own `__security_cookie`.

Sit with that for a second. It is a completely plausible piece of amateur
cryptography — "encrypt the hash with a secret the attacker cannot read" — and
the secret they reached for was the one global that was already there and
already random.

## The bug: one wrong constant

GET renders the entry into a stack buffer and copies it to the output:

```c
NTSTATUS GetEntry(...)
{
    char Dest[400];                        /* rsp+0xD0 */
    ...
    vsnprintf(Dest, 512, kFormat,          /* <-- 512 */
              entry->id, entry->title, entry->username,
              entry->password, "SHA512", hex);
    memcpy(SystemBuffer, Dest, 0x200);
}
```

400-byte array, 512-byte count. `vsnprintf` will happily write 511 bytes plus a
terminator, so there are **112 bytes of overflow** past the end of `Dest`, and
every one of them comes from fields I control.

That is `sizeof` applied to the wrong thing, or a `#define` that drifted from the
array it was named after. It is the single most common way a bounded copy stops
being bounded.

Walking the frame in IDA puts the interesting targets at:

| offset in `Dest` | absolute | contents |
|---|---|---|
| `400` | `rsp+0x260` | stack cookie |
| `472` | `rsp+0x298` | return address |

72 bytes — nine qwords — between the cookie and the return address, which is the
saved non-volatiles and home space. So I need 472 bytes of correctly-positioned
text with the right eight bytes landing on offset 400, and I get to control what
sits at offset 472.

Which means I need the cookie.

## Leak 1: the cookie, gift-wrapped

`encrypted_hash = SHA512(password) XOR repeat8(__security_cookie)`.

XOR with a repeating 8-byte key is not encryption, it is a shift cipher with a
period. It leaks the key to anyone who knows one plaintext block. And I choose
the plaintext: ADD with an all-zero password field, GET the entry back, and the
first eight bytes of `encrypted_hash` are

```
SHA512(0x00 * 128)[0:8]  XOR  __security_cookie
```

`SHA512` of a known input is a known constant. One XOR and the driver's
`__security_cookie` is on my screen. No brute force, no partial overwrite, no
byte-at-a-time oracle — a single ADD and a single GET.

I love this as a piece of design. It is a second, entirely separate bug whose
only effect is to hand out the mitigation, dressed up as a security feature —
which is exactly what home-grown crypto in a real product does. The strongest
mitigation on the stack was defeated by the one routine written specifically to
protect something.

## Why the cookie is not the canary

Knowing `__security_cookie` is not enough, and this is the part that catches
people who have only done this on Linux.

MSVC's `/GS` on x86-64 does not put the global cookie on the stack. It puts:

```nasm
mov  rax, cs:__security_cookie
xor  rax, rsp                    ; <-- per-frame
mov  [rsp+0x260], rax
```

and checks it on the way out with `__security_check_cookie` after re-XORing.
The value on the stack is `__security_cookie ^ rsp`, where `rsp` is this
invocation's frame pointer. That XOR is what stops a leak of the global from
being reusable, and it means the canary changes with the stack depth of the
call, the thread, and where in the kernel stack the thread happens to be sitting.

So I have half the equation. I need `rsp` at the moment GET runs.

## Leak 2: the error log is a kernel stack leak

Back to that fourth branch of the dispatch switch. Send a control code the
driver does not know and it appends a diagnostic line to `C:\pwvault.log`:

```
Error: unknown IOCTL code 0x00223010 in DeviceIoCtlHandler [FFFFF8047A1B32E0]
```

That `%p` is not a constant, not a pointer to a global, and not the IRP. It is
`&stack[1]` in the dispatch routine's own frame — a raw kernel stack address —
printed into a log file that is created with a security descriptor permissive
enough for a medium-integrity user to read.

The dispatch routine calls GET, so GET's frame sits a fixed distance below the
one that got logged. Measure it once in a debugger and it is a constant for the
build:

```
GET_rsp = logged_pointer - 0x2F0
canary  = __security_cookie XOR GET_rsp
```

The one detail that will bite you: **kernel stacks are per-thread.** The leaked
`rsp` is only meaningful for the thread that provoked the log write. If you leak
on the main thread and trigger the overflow on a worker, the canary is wrong and
you get a `0xF7 DRIVER_OVERRAN_STACK_BUFFER` instead of a shell. Every thread
that is going to trigger has to open its own handle and do its own leak, in that
order, with nothing in between that changes its stack depth.

The log is append-only, so read the *last* bracketed pointer, not the first.

## Leak 3: KASLR, for free

The chain needs `ntoskrnl.exe`'s randomised base. On Windows 10 1809 a
medium-integrity process can still call `psapi!EnumDeviceDrivers` and get back
the load address of every kernel module, with `GetDeviceDriverBaseNameW` to name
them.

```python
psapi.EnumDeviceDrivers(arr, sizeof(arr), byref(cb))
for base in arr[:cb.value // 8]:
    psapi.GetDeviceDriverBaseNameW(c_void_p(base), name, 260)
    if name.value.lower().startswith("ntoskrnl"):
        nt = base
```

This is not a bug in the driver; it is a Windows design decision that predates
the threat model it now sits in, and it has been narrowed in later builds
(`EnumDeviceDrivers` returns pointers that are zeroed for low-integrity callers,
and various sandboxes block it entirely). On 1809 at medium IL it is a two-line
KASLR defeat and it is the reason kernel LPE writeups from that era all look
this easy in their first act.

Four leaks, then, and each one comes from a different place:

| # | What | Where from |
|---|---|---|
| 1 | `__security_cookie` | the driver's XOR "encryption" |
| 2 | GET's kernel `rsp` | the driver's error log |
| 3 | `ntoskrnl` base | `psapi!EnumDeviceDrivers` |
| 4 | pool address of my chain | the entry list's own `LIST_ENTRY` (below) |

## Laying out 128 bytes

Now the arithmetic. I need to place bytes at exactly `Dest[400]` and
`Dest[472]`, and the only thing writing into `Dest` is a format string rendering
my fields in a fixed order:

```
... title = '<title>', username = '<user>', password = '<password>', hash_algorithm = ...
```

The literal text between the fields is constant — 201 bytes of it before the
password begins. The variable parts are the decimal ID, the title, and the
username. So the offset at which the password starts is

```
201 + len(str(id)) + len(title) + len(username)
```

and I get to choose the last two. Pinning the password to `Dest[382]`:

```python
idl   = len(str(entry_id))
USER  = 60
TITLE = 181 - idl - USER      # 120 for a single-digit id
```

Shrink the title by one, grow the username by one, and the password lands in the
same place. The ID is not under my control — the driver assigns it — so the
payload is built, submitted, and rebuilt if the returned ID has a different digit
count than I guessed. (Cheaper than it sounds: ADD returns the ID, and I just
resubmit.)

With the password field starting at `Dest[382]`, the 128-byte field covers
`Dest[382..510]` — just inside the 512-byte write — and the two targets fall at:

```
canary        -> password[18]   (Dest[400])
return address -> password[90]  (Dest[472])
pivot value    -> password[98]  (Dest[480])
```

And now the constraint that shapes everything downstream: **`%s` stops at the
first NUL byte.** Every byte from `password[0]` through `password[105]` must be
non-zero, or the render truncates and the overflow never reaches the return
address. The canary, the gadget address and the pivot target all have to be
NUL-free. Nothing forces them to be. This is the single most annoying property
of a format-string-driven stack overflow, and it turns into a real reliability
problem later.

The return address gets a `pop rsp; ret` gadget, and `password[98]` gets the
address to pivot to. Which raises the question of where to pivot *to*.

## Leak 4: where to put the chain

The chain is about 208 bytes. It cannot go in the overflow itself — I only have
112 bytes past the buffer and most of that is spoken for. It needs to be
somewhere with a known address.

SMAP is off on this target, so a user-mode buffer would in fact work: kernel code
can read user data, and a ROP chain is data, not code — SMEP only stops
*executing* user pages. But the driver hands me something better for free.

Every ADD gives me a pool allocation with 256 contiguous fully-controlled bytes
in it. So: ADD one entry whose `title`+`username` region *is* the ROP chain.
Then I need its address.

That is what the `LIST_ENTRY` sitting flush against the password field is for.
Add a second "leaker" entry immediately after the chain entry, with its password
field filled with 128 bytes of `'P'` — no terminator. GET it, and the `%s` for
password walks off the end of the field and prints `Flink` and `Blink` raw:

```python
j = 0
while pw[j:j+1] == b'P':          # skip the padding I sent
    j += 1
blink = struct.unpack_from("<Q", pw[j:], 8)[0]   # Flink at +0, Blink at +8
pivot = (blink - 0x1C8) + 8
```

`Blink` points at the *previous* entry's `LIST_ENTRY`, which is at `+0x1C8` in
that entry, so the entry base is `Blink - 0x1C8` and my chain starts eight bytes
in. One adjacent-field disclosure, and I know exactly where in the non-paged pool
my chain lives.

This route also survives SMAP being turned on, which the user-mode-buffer version
would not.

## The chain

The goal is the oldest trick in Windows kernel exploitation and still the most
reliable: copy the System process's token over my own process's token.

```
nt!PsInitialSystemProcess  ->  EPROCESS of PID 4
EPROCESS + 0x358           ->  Token          (1809; it is 0x4B8 on 22621)
```

The gadgets, hunted with capstone over the exact `ntoskrnl.exe` from the target:

```nasm
pop rax ; ret
pop rcx ; ret
mov rax, [rax] ; ret
add rax, rcx ; ret
push rax ; pop rbx ; ret
mov [rax], rbx ; ... ; add rsp, 0x30 ; ret
swapgs ; iretq
```

and the chain reads:

```
pop rax            <- &nt!PsInitialSystemProcess
mov rax, [rax]                       ; rax = System EPROCESS
pop rcx            <- 0x358
add rax, rcx                         ; rax = &System->Token
mov rax, [rax]                       ; rax = System token
push rax ; pop rbx                   ; rbx = System token
<nt!PsGetCurrentProcess>             ; rax = current EPROCESS
pop rcx            <- 0x358
add rax, rcx                         ; rax = &current->Token
mov [rax], rbx                       ; *** SYSTEM ***
  <7 qwords of padding>              ; the gadget's add rsp,0x30 trailer
swapgs ; iretq
  <5 qwords: RIP, CS, RFLAGS, RSP, SS>
```

Two notes on that.

`PsGetCurrentProcess` is used as a gadget, not called as a function — it is
`mov rax, gs:[188h] ; mov rax, [rax+0B8h] ; ret`, which is exactly the two
dereferences I want and ends in a `ret`. An exported function whose body happens
to be a useful gadget is free and does not need a hunt.

The write copies the token pointer *including its low three bits*, which are
`EX_FAST_REF`'s inline reference count. That is technically wrong — it
over-counts System's token by whatever was in my process's low bits — and it is
what essentially every published token-stealer does, because a leaked reference
on the System token is not a problem anyone will ever observe. Clearing the low
bits is one more `and` and I did not bother.

The seven padding qwords are the price of the write gadget having an `add rsp,
0x30` between the store and its `ret`. Gadget trailers are the part of ROP that
nobody puts in the diagram and everybody debugs.

## The return that cannot return

The classic finale is to fix the stack up and let the driver return normally, so
the process keeps running with its new token and nobody notices. I tried that
first. It does not work here, and the reason is worth writing down.

By the time the overflow has reached the return address at `Dest[472]`, it has
also overwritten everything between the cookie and there — and the format
string's own trailing output continues past it. The dispatch routine's saved
`IRP` pointer lives in that region. Even if I return to the right place with the
right `rsp`, the caller then dereferences a pointer I have turned into ASCII.
There is no arrangement of the payload that both reaches the return address and
leaves the caller's locals intact; the two regions overlap.

So the chain does not return to the kernel. It leaves it:

```
swapgs ; iretq   with a frame of { RIP=stub, CS=0x33, RFLAGS=0x202, RSP=user, SS=0x2b }
```

`stub` is a two-byte user-mode page containing `EB FE` — `jmp $`. The thread
transitions to CPL 3 and spins there forever.

**Does this survive KPTI?** The target has KVA shadow on, and my first instinct
was that a bare `swapgs; iretq` would fault instantly: the kernel's real exit path
goes through the `KVASCODE` trampoline that swaps CR3, and I am skipping it.

It works, and the reason is that KVA shadow is asymmetric. The *user* CR3 is the
cut-down one — it maps only a trampoline's worth of kernel. The *kernel* CR3
maps everything, user space included, protected by SMEP and SMAP rather than by
being absent. So an `iretq` to a user RIP while still on the kernel CR3 lands
somewhere that is genuinely mapped and executable at CPL 3, and the CPU is
perfectly happy.

What is *not* happy is everything afterwards. That thread is now running user
code on the kernel page tables with the kernel's GS bookkeeping half-restored. It
must never make a syscall, take a page fault into anything unmapped, or get
scheduled through a path that assumes the CR3 matches the mode. Which is exactly
why the stub is an infinite loop and not a `ret`.

## The sacrificial thread

That constraint would be fatal if the token were a per-thread property. It is
not. `Token` is a field of `EPROCESS`, so the moment that one store lands,
**every thread in the process is SYSTEM**, including the ones that were never
anywhere near the kernel stack I just corrupted.

So the exploit spends a thread:

```python
def worker():
    wh      = openh()                 # its own handle
    logaddr = leak_logaddr(wh)        # its own kernel stack
    canary  = cookie ^ (logaddr - 0x2F0)
    ...
    get(wh, overflow_id)              # never returns; parks in jmp $

threading.Thread(target=worker).start()
time.sleep(5)

print(subprocess.check_output("whoami"))     # main thread, normal CR3
print(open(SYSTEM_ONLY_FILE, "rb").read())
```

The worker thread burns a core in `jmp $` until the process exits. The main
thread has a normal stack, a normal CR3, an intact GS base — and a SYSTEM token.
It does the file reads.

There is something pleasing about an exploit whose final step is a completely
ordinary `open()` call on a completely ordinary thread. All the violence happened
next door.

```
whoami: nt authority\system
```

## Things that went wrong

The writeup above is the version that works. Four things cost real time.

**One boot in eight is unexploitable, and it is KASLR's fault in an unusual
way.** `ntoskrnl` lands at a randomly chosen high address, and roughly one slot
in eight puts it at `0xfffff800_xxxxxxxx`. Little-endian, that address is

```
xx xx xx 4x 00 f8 ff ff
             ^^ byte 4
```

A NUL byte in the middle of every single kernel address. And my write primitive
is a `%s`. On those boots the gadget address truncates the render and the payload
never reaches the return address — not "less reliable", *impossible*, for every
kernel address at once. There is no clever encoding around it either, because the
constraint applies to the pivot and the canary too. The fix is to reboot and get
a different slot, which meant wrapping the whole thing in a harness that boots,
tries, and reboots on failure. The canary has the same problem
independently: `cookie ^ rsp` contains a zero byte about 3% of the time, and that
one is fixed by simply re-leaking on a fresh thread at a different stack depth.

**I developed the entire thing against a local VM I could break.** The real
target was reachable only through a fragile remote shell with a session limit
behind it, and every bugcheck cost minutes and a reconnect — the worst possible
environment for a technique that fails by crashing the machine. So I installed
the same driver on a local Windows 11 VM with a kernel debugger attached, built
the exploit there until it printed `nt authority\system`, and only then ported it.
Porting is a matter of three build-specific numbers — `EPROCESS.Token`, the two
export RVAs, and the gadget RVAs — which is a strong argument for keeping them in
a table:

```python
TARGETS = {
  'win10_17763': dict(PsISP=..., PsGetCurProc=..., TOK=0x358, pop_rax=..., ...),
  'win11_22621': dict(PsISP=..., PsGetCurProc=..., TOK=0x4B8, pop_rax=..., ...),
}
```

**My PE export parser was wrong and cost me a bugcheck.** On the Win11 kernel it
returned an RVA for `PsGetCurrentProcess` that disassembled to garbage; the chain
called into the middle of an unrelated function and the machine died with a
`0x1AA`. I stopped hand-rolling it and resolved exports — and `EPROCESS.Token`'s
offset — through `dbghelp` against the Microsoft symbol server instead:
`SymFromNameW` for the exports, `SymGetTypeInfo` with `TI_GET_OFFSET` for the
struct member. Both builds' PDBs are a download away and neither number is worth
guessing.

**The remote box runs Python 2.7.** The 3.8 install on it is broken, so the final
script had to be valid under both. The bug that caught me was in the cookie
routine: my parser was calling `.decode()` on the hash before handing it over, and
`bytearray(unicode)` in Python 2 raises `TypeError: unicode argument without an
encoding`. It failed only on the remote, only in the one function that mattered,
and only after a two-minute VM boot. `binascii.unhexlify` accepts `str` and
`unicode` alike, so the fix was to unhexlify first and never let a text type into
the arithmetic.

## What was worth learning

The overflow is `512` where `400` belonged. Every mitigation on that machine
worked exactly as designed, and none of them mattered, because each one was
defeated by a *different* piece of information the system gave away for free:

- The stack cookie fell to the driver's own encryption, which XORed a known
  plaintext with the secret.
- The per-frame randomisation of that cookie fell to a debug log that printed a
  raw kernel stack pointer into a world-readable file.
- KASLR fell to a documented API that a medium-integrity process is still allowed
  to call.
- The unknown location of my payload fell to a linked list whose `LIST_ENTRY` sat
  one byte past a field printed with `%s`.

None of those four is a memory-safety bug. Three of them are *features*. The
memory-safety bug was necessary but nowhere near sufficient, and if any one of
the four leaks had been closed, the other three would have been useless.

That is the actual lesson and it generalises past this toy: on a modern target
the exploit is mostly an information-gathering problem with a corruption bug at
the end of it. The person who wrote this driver understood buffer lengths well
enough to write three strict equality checks on `InputBufferLength`. They still
lost, twice over, to a diagnostic log and to a `for` loop that XORed with a
global.

The password manager, incidentally, works fine. It stores your passwords, it
hashes them properly, and it will give them back to you on request. It just also
gives back the kernel.

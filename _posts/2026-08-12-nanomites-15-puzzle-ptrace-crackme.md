---
title: "Fifteen Nanomites: Solving a ptrace Crackme Without Ever Solving Its Puzzle"
date: 2026-08-12 18:00:00 +0200
categories: [Reverse Engineering, Crackme]
tags: [reverse-engineering, linux, x86-64, ptrace, nanomites, xtea, elf, crackme]
---

An 8,944-byte statically linked ELF. Stripped, no libc, two program headers, and
exactly **718 bytes of executable code**. Everything else is ciphertext.

Under that ciphertext are fifteen forked processes that hold each other's code
hostage, a 15-puzzle that decides who is allowed to talk to whom, and a payload
that only exists once the conversation has happened in precisely the right
order.

This is a writeup of how I took it apart — and why the interesting part is that
**I never solved the puzzle**. I solved the algebra behind it instead.

## Table of contents

1. [First contact](#first-contact)
2. [The loader](#the-loader-fifteen-forks-and-a-rolling-key)
3. [The input is a 15-puzzle](#the-input-is-a-15-puzzle)
4. [Nanomites](#nanomites-tiles-that-patch-their-neighbours)
5. [Not solving the puzzle](#not-solving-the-puzzle)
6. [Recovering the opcode](#recovering-an-opcode-i-did-not-know)
7. [0xC0FFEE](#0xc0ffee)
8. [The flag](#the-flag)
9. [Proving it](#proving-it-end-to-end)
10. [A real race condition](#a-real-race-condition-in-the-challenge)

## First contact

```
$ readelf -hlS ch54.bin
Entry point address:               0x4000b0
LOAD 0x400000  filesz 0x37e  R E
LOAD 0x600380  filesz 0x1e10  memsz 0x20a8  RW
[ 1] .text  0x4000b0  size 0x2ce
[ 2] .data  0x600380  size 0x1e10
[ 3] .bss   0x602190  size 0x298
```

No sections worth the name, no imports, no strings. `.text` is 0x2ce bytes and
`.data` is 7.7 KB of high-entropy noise. The entire program is in that noise;
`.text` is just the machine that unpacks it.

The entry point is refreshingly blunt:

```nasm
4000b0:  mov  esi, 0x6021d0     ; buffer
4000b5:  inc  dh                ; rdx = 0x100
4000b7:  syscall                ; rax=0 at process entry -> read(0, buf, 256)
4000b9:  call 0x40018b          ; setup
```

At process entry Linux zeroes the general-purpose registers, so `rax`, `rdi` are
already 0 and `inc dh` is a two-byte way of writing `mov edx, 256`. That is the
whole flavour of this binary: nothing is spelled out if it can be implied.

## The loader: fifteen forks and a rolling key

`0x40018b` is where it gets good.

```nasm
mmap(NULL, 0x2000, RWX, 0x21, -1, 0)   ; r12 = base
; fill the first 0x200 bytes with 0xFF..FF
mov  ecx, 0x40
dec  QWORD PTR [rax] / add rax,8 / loop
```

Note the mmap flags: `0x21` is `MAP_SHARED|MAP_ANONYMOUS`. **Not** `MAP_PRIVATE`.
I misread this on the first pass and it invalidates everything downstream — the
region survives `fork()` as genuinely shared memory. Every child writes into the
same 8 KB the parent is reading.

The region is carved into sixteen 0x200-byte slots. Slot 0 is scratch,
initialised to all-`0xFF`. Slots 1–15 each get 0x200 bytes of `.data` decrypted
into them, and then:

```nasm
4001f9:  mov  eax, 0x39
         syscall                    ; fork()
         test eax, eax
         jne  parent
         sub  rdi, 0x200            ; child: rdi = its own slot
         call rdi                   ; ...and runs it
parent:  mov  [r15*4+0x602190], eax ; remember the pid
         mov  edi, 0x4206           ; PTRACE_SEIZE
         syscall
```

So: fifteen child processes, one per puzzle tile, each executing code that lives
in memory shared with everybody else, each seized by the parent as a ptrace
tracee. The parent is a debugger and a scheduler; the children are coroutines.

### The cipher

The decryption at `0x40023d` is XTEA-shaped but not XTEA:

```nasm
mov  cl, 0x20
mov  r8d, 0xc6ef3720          ; sum = delta*32  -> decrypt direction
mov  r9d, r13d                ; key pointer
.loop:
  ; v0 -= ((v1<<4)+k2) ^ (v1+sum) ^ ((v1>>5)+k3)
  ; v1 -= ((v0<<4)+k0) ^ (v0+sum) ^ ((v0>>5)+k1)
  sub  r8d, 0x9e3779b9
  dec  cl
  jne  .loop
```

Real XTEA selects the round key with `(sum>>11)&3`. This one hardcodes the
indices and reorders the terms, so you cannot reuse a library implementation —
you have to transcribe the loop.

The genuinely nice touch is the key schedule. `r9d` is a *32-bit address*, and
the key is read straight out of the loaded image:

```nasm
67 41 03 41 08    add eax, DWORD PTR [r9d+0x8]
```

`r13d` starts at `0x400000` — the ELF header — and advances by one byte per
8-byte block, then rewinds 8 at each slot boundary. Every block is encrypted
under a 16-byte window sliding over the program's own header and code. Patch a
single byte of `.text` and every slot after it decrypts to garbage. It is a
self-integrity check that costs zero instructions to enforce.

A short Python transcription drops out fifteen 512-byte plaintexts, and they are
all the same shape:

```nasm
0x000:  cd 03                    int3
0x002:  81 6f 24 29 c3 f3 2e     sub DWORD PTR [rdi+0x24], 0x2ef3c329
        ... 34 of these ...
0x0f0:  90 90 90 90              nop
0x0f4:  cd 03                    int3
0x0f6:  48 83 f8 01              cmp rax, 1
0x0fa:  0f 85 02 ff ff ff        jne 0x002
0x100:  <256 bytes of noise>
```

The first half is a *sub table*: 34 hardcoded subtractions at fixed offsets from
`rdi`. The second half is 256 bytes that do not disassemble to anything.

The loop tells you the protocol. The child stops at `int3`. Whoever resumes it
chooses `rdi` and `rax`. If `rax != 1` it applies its 34 subtractions to whatever
`rdi` points at and stops again. If `rax == 1` it falls through into the noise at
`0x100` and executes it.

So the noise is code that has not been assembled yet, and the sub table is the
assembler.

## The input is a 15-puzzle

Back in `_start`, the 256 bytes read from stdin are parsed one hex digit at a
time against a 16-byte array at `0x602180`:

```nasm
4000c6:  mov  al, [r15+0x6021d0]   ; input[i]
         cmp  al, 0xa
         je   done                  ; newline ends the sequence
         ; '0'-'9' -> 0..9, 'a'-'f' -> 10..15, anything else -> exit
         sub  rax, r13              ; r13 = blank position
         cmp  al, 0xfc              ; -4  ok
         cmp  al, 0x04              ; +4  ok
         ; -1 allowed only if blank column != 0
         ; +1 allowed only if blank column != 3
```

That is exactly the legal-move test for a 4×4 sliding puzzle. Each hex digit
names the **position of a tile adjacent to the blank**, and slides it in:

```nasm
400117:  mov  dl, [rax+0x602180]    ; tile at p
         mov  [r13+0x602180], dl    ; move it into the blank cell
         mov  BYTE PTR [rax+0x602180], 0
         call 0x400299              ; <-- notify
         pop  r13                   ; blank is now at p
```

The board at `0x602180` in the file is `00 01 02 03 ... 0f`. The puzzle **starts
solved**. The input is not a solution — it is a scramble, and what matters is not
where the tiles end up but the sequence of neighbour relationships you create on
the way.

## Nanomites: tiles that patch their neighbours

`0x400299` walks the four neighbours of the destination cell and, for each
non-blank one, calls this:

```nasm
4002db:  mov  al, [rax+0x602180]     ; N = tile sitting at that neighbour
         test al, al
         je   .ret                   ; blank, skip
         mov  r14d, [rax*4+0x602190] ; pid of tile N's process
         call GETREGS
         mov  al, [r13+0x602180]     ; M = the tile that just moved
         shl  eax, 9
         add  ax, 0x180
         add  rax, r12
         mov  [0x6023c0], rax        ; regs.rdi = slot(M) + 0x180
         call SETREGS_CONT_WAIT
```

`0x6023c0` is offset 0x70 into the `user_regs_struct` at `0x602350`, which is
`rdi`. So:

> When tile **M** slides next to tile **N**, the parent wakes up **N**'s process
> and points it at **M**'s buffer. N applies its 34 subtractions to M's second
> half, then stops again.

The tiles are nanomites. Each one carries a piece of every other tile's code, and
the only way to assemble tile M's payload is to march M past exactly the right
neighbours exactly the right number of times.

Because the offsets are `[rdi+disp8]` with `rdi = slot + 0x180`, the writes land
in `[0x100, 0x200)` — the noise. And because subtraction commutes, **order does
not matter**. Only the multiset of encounters does.

Once the newline is reached, the parent checks its work and fires:

```nasm
40013e:  cmp  DWORD PTR [r12 + r15*0x200 + 0x100], 0x90909090
         jne  fail
         ; regs.rax += 1 ; regs.rdi = r12 ; CONT
         ...
40017f:  call r12                   ; execute slot 0
```

Each tile is resumed once more with `rax = 1`, so it falls into its now-assembled
second half with `rdi` pointing at slot 0. Fifteen payloads write into slot 0.
Then the parent calls it.

## Not solving the puzzle

The obvious path is: work out the move sequence, feed it in, watch it work. I
tried. It is not tractable by hand, and as it turns out it is not necessary.

Model it. Let `V_N[k]` be the constant tile N subtracts at offset `k`, and
`c[N][M]` the number of times N ever notifies M. Then for every tile M and every
offset k:

$$\text{final}_M[k] = \text{init}_M[k] - \sum_N c[N][M] \cdot V_N[k] \pmod{2^{32}}$$

Fourteen unknowns per tile, 64 equations per tile — but the right-hand side is
unknown, because I do not know the final code. Except at one offset. The parent
checks `[slot+0x100] == 0x90909090`, and that one dword is free:

$$\sum_N c[N][M]\cdot V_N[0x100] = \text{init}_M[0x100] - \texttt{0x90909090}$$

Only six or seven tiles have a subtraction at offset `0x100` at all, so this is a
single 32-bit equation in ~7 non-negative unknowns. Meet-in-the-middle with a
bound of 16 per coefficient searches `16^7 ≈ 2.7×10^8` combinations against a
32-bit target — you expect **0.06** spurious hits. Every tile returned exactly
one solution:

```
1  [4,5,9,11,13,14]     {4:5, 5:3, 9:2, 11:0, 13:2, 14:2}
2  [1,4,5,9,11,13,14]   {1:6, 4:1, 5:3, 9:3, 11:2, 13:0, 14:4}
...
```

Ninety-eight of the 210 coefficients, from one constant.

## Recovering an opcode I did not know

The other seven columns need another equation, which means I need to know
something else about the final code. So guess the *shape*: a 4-nop marker
followed by a table of identical instructions.

I do not have to guess *which* instruction. The bytes at `0x104` and `0x105` are
the opcode and ModRM of the first instruction, and if the fifteen payloads share
a shape then those two bytes are **the same for all fifteen tiles**. That is a
solvable constraint: for each tile, enumerate the remaining unknowns with a small
bound, collect the achievable values of `final[0x104] & 0xFFFF`, and intersect
across all fifteen.

```
B=6   common low16 candidates: 0
B=8   common low16 candidates: 1  ->  0xaf81
B=10  common low16 candidates: 1  ->  0xaf81
```

`81 AF` is `sub DWORD PTR [rdi + disp32], imm32` — ten bytes. The payload is
`nop nop nop nop`, then a table of 32-bit-displacement subtractions, because the
final target is slot 0 and `disp8` would not reach.

From there it propagates. Every tenth byte is a known `0x81`, every tenth-plus-one
a known `0xAF`, and the remaining coefficients fall out one offset at a time.
Propagation stayed consistent through `0x1DF` and then failed — which is not a
contradiction, it is the end of the table. Twenty-two instructions, `0x104` to
`0x1DF`, then a 32-byte tail.

Unique solution, all fifteen tiles, 210 coefficients:

```
        1   2   3   4   5   6   7   8   9  10  11  12  13  14  15   tot
N=1     0   6   4   3   5   2   3   3   1   3   2   3   2   2   2    41
N=2     2   0   6   2   5   5   6   4   2   2   1   1   1   2   4    43
N=3     4   4   0   6   1   6   1   3   0   0   5   2   0   0   5    37
N=4     5   1   4   0   4   3   2   5   0   2   1   7   2   1   4    41
N=5     3   3   2   2   0   2   4   4   1   3   2   2   4   4   4    40
N=6     4   5   4   4   4   0   3   3   0   1   2   4   2   1   1    38
N=7     5   2   3   2   4   2   0   3   1   2   3   1   0   4   1    33
N=8     5   4   2   2   2   0   3   0   4   4   1   2   1   3   3    36
N=9     2   3   0   1   2   1   1   5   0   6   2   1   2   5   2    33
N=10    3   3   1   1   3   1   4   4   3   0   4   4   3   1   4    39
N=11    0   2   3   2   7   2   2   0   3   3   0   3   3   6   4    40
N=12    4   2   4   2   2   4   0   3   3   1   0   0   4   2   4    35
N=13    2   0   4   5   1   0   0   1   3   4   4   4   0   2   5    35
N=14    2   4   0   0   2   1   1   4   3   2   2   1   3   0   3    28
N=15    4   4   4   2   3   3   1   0   1   3   6   3   5   2   0    41
tot    45  43  41  34  45  32  31  42  25  36  35  38  32  35  46   560
```

560 neighbour encounters. A move to a corner produces one, to an edge two, to a
centre three — so the intended input is somewhere around 200–255 moves, which is
exactly the 256-byte read buffer. Nice design.

Subtract, and the noise becomes this:

```nasm
0x100:  90 90 90 90
0x104:  81 af dc 00 00 00  2b f3 fc 05   sub DWORD PTR [rdi+0xdc], 0x5fcf32b
        ... 22 of them ...
0x1e0:  90 90
0x1e2:  cd 03                            int3
0x1e4:  41 8a 44 24 0f                   mov al, [r12+0xf]
0x1e9:  41 32 44 24 03                   xor al, [r12+3]
0x1ee:  3c 11                            cmp al, 0x11
0x1f0:  75 05                            jne .out
0x1f2:  41 fe 44 24 20                   inc BYTE PTR [r12+0x20]
0x1f7:  31 ff / b8 3c.. / 0f 05          exit(0)
```

## 0xC0FFEE

Fifteen tiles × 22 subtractions = 330 writes into slot 0, which starts as 512
bytes of `0xFF`. Apply them all and disassemble:

```nasm
   0:  xor  eax, eax
   2:  mov  ecx, eax
   4:  mov  cl, 0x80
   6:  mov  rdx, r12
   9:  add  eax, DWORD PTR [rdx]      ; sum 128 dwords...
   b:  add  rdx, 4
   f:  dec  cl
  11:  jne  0x9
  13:  cmp  eax, 0xc0ffee             ; ...of itself
  18:  je   0x1b
  1a:  ret
```

The payload's first act is to checksum itself, and my reconstruction sums to
exactly `0xC0FFEE`. Two hundred and ten coefficients recovered by algebra, and
the program's own integrity check agrees. That is a 1-in-2³² coincidence or it is
right.

```
$ python3 -c 'import struct; b=open("slot0.bin","rb").read();
> print(hex(sum(struct.unpack("<128I",b)) & 0xffffffff))'
0xc0ffee
```

And there are strings:

```
'\nGood job on arriving here.\nYou managed to avoid letting the voracious
nanomites devour the vital parts of the program.\nYou may now enter your flag
for verification: '
'Congratulations! Enter RootMe{flag} to validate the challenge.\n'
'This is not the correct flag.\n'
```

## The flag

The payload prints the prompt, reads 16 bytes into slot 0, zeroes a counter at
`[r12+0x20]`, then `PTRACE_CONT`s all fifteen tiles. Each tile resumes at `0x1E4`
— just past the `int3` — checks one relation on the flag bytes, bumps the counter
if it holds, and exits. Three more checks run inline. Then:

```nasm
  d3:  cmp  BYTE PTR [r12+0x20], 0x12   ; 18 checks
  d9:  jne  .bad
```

Fifteen tiles plus three inline checks. Every constraint is one byte wide:

| source | constraint |
|---|---|
| tile 1 | `f[15] ^ f[3] == 0x11` |
| tile 2 | `f[10] ^ f[5] == 0x07` |
| tile 3 | `f[12] ^ f[4] == 0x3e` |
| tile 4 | `f[4] ^ f[6] == 0x0e` |
| tile 5 | `f[9] ^ f[2] == 0x00` |
| tile 6 | `f[0] ^ f[12] == 0x1d` |
| tile 7 | `f[7] ^ f[11] == 0x1b` |
| tile 8 | `f[2] ^ f[7] == 0x06` |
| tile 9 | `f[6] ^ f[13] == 0x53` |
| tile 10 | `f[11] ^ f[8] == 0x42` |
| tile 11 | `f[5] ^ f[14] == 0x5a` |
| tile 12 | `f[13] ^ f[10] == 0x03` |
| tile 13 | `f[8] ^ f[0] == 0x7f` |
| tile 14 | `f[14] ^ f[9] == 0x00` |
| tile 15 | `f[1] ^ f[15] == 0x61` |
| inline | `f[15] == 0x21` |
| inline | `f[3] ^ f[1] == 0x70` |
| inline | `sum(f) & 0xFFFF == 0x4ef` |

`f[15] = 0x21` pins `f[3] = 0x30` and `f[1] = 0x40`. The remaining thirteen
bytes form a single XOR cycle — `f0 → f12 → f4 → f6 → f13 → f10 → f5 → f14 → f9
→ f2 → f7 → f11 → f8 → f0` — whose constants XOR to zero, so it is consistent
with exactly one free parameter. The checksum fixes it:

```python
xs = [(0,0x00),(12,0x1d),(4,0x23),(6,0x2d),(13,0x7e),(10,0x7d),(5,0x7a),
      (14,0x20),(9,0x20),(2,0x20),(7,0x26),(11,0x3d),(8,0x7f)]
for x in range(256):
    f = [None]*16
    f[15], f[3], f[1] = 0x21, 0x30, 0x40
    for i, k in xs: f[i] = x ^ k
    if sum(f) & 0xffff == 0x4ef:
        print(x, bytes(f))
```

```
78 b'N@n0m4ch1n3sS0n!'
```

**Nanomachines, son.** Of course.

```
RootMe{N@n0m4ch1n3sS0n!}
```

## Proving it end to end

Deriving a flag from reconstructed code is not the same as running it. But I
still did not have a move sequence, so I made one unnecessary.

Since the loader decrypts `.data` into the slots and I now know exactly what each
slot must contain, I re-encrypted the *solved* state back into the binary. The
key schedule reads `.text`, which I did not touch, so it still works. Each slot's
first half became a two-instruction stub:

```nasm
cd 03            int3
e9 f9 00 00 00   jmp 0x100
```

so a tile resumed with `rax = 1` and `rdi = r12` goes straight to its assembled
payload — no puzzle required. Feed the parser a bare newline and it skips
straight to the check, which passes, because `0x90909090` is already there.

```
### input: N@n0m4ch1n3sS0n!

Good job on arriving here.
You managed to avoid letting the voracious nanomites devour the vital parts of
the program.
You may now enter your flag for verification: N@n0m4ch1n3sS0n!
Congratulations! Enter RootMe{flag} to validate the challenge.

### input: AAAAAAAAAAAAAAAA

...
You may now enter your flag for verification: AAAAAAAAAAAAAAAA
This is not the correct flag.
```

Two notes for anyone reproducing this. The flag is read from a terminal in
canonical mode, so you must send a trailing newline or the read never returns —
I lost twenty minutes to a program that looked like it had hung when it was
simply waiting. And `strace -f` is useless here: strace becomes the tracer, the
program's own `PTRACE_SEIZE` fails, and you get a screenful of `ECHILD` that
tells you nothing about the binary. Trace the parent only.

## A real race condition in the challenge

That `strace -f` run did surface something genuine. Look at the fork path again:

```nasm
syscall                  ; fork
test eax, eax
jne  parent
sub  rdi, 0x200
call rdi                 ; child immediately executes int3
parent:
mov  edi, 0x4206         ; PTRACE_SEIZE  <-- happens *after*
syscall
```

The child hits `int3` as fast as it can be scheduled. The parent seizes it
afterwards. If the child wins, `SIGTRAP` has no tracer, the default action
applies, and the child dies before it ever exists as a nanomite:

```
ptrace(PTRACE_SEIZE, 323462, NULL, 0) = 0
--- SIGCHLD {si_code=CLD_TRAPPED, si_pid=323462, si_status=SIGTRAP} ---
ptrace(PTRACE_SEIZE, 323463, NULL, 0) = 0
--- SIGCHLD {si_code=CLD_KILLED,  si_pid=323463, si_status=SIGTRAP} ---
ptrace(PTRACE_SEIZE, 323466, NULL, 0) = -1 EPERM
--- SIGCHLD {si_code=CLD_KILLED,  si_pid=323466, si_status=SIGTRAP} ---
```

`CLD_KILLED`. Fourteen of the fifteen tiles died. Under normal load the parent
wins every time and you never see it, but the correctness of this binary rests on
scheduler timing rather than on anything it does. `PTRACE_TRACEME` in the child
before the `int3` would have closed it for the cost of one syscall.

## What was worth learning

The thing I keep coming back to is that the nanomite scheme defends against
static analysis beautifully and against *algebra* not at all. Splitting the
payload across fifteen processes and gating reassembly behind a combinatorial
puzzle means no disassembler will ever show you the code, and single-stepping
gets you one tile at a time in an order you do not control.

But the mechanism is a sum. Subtraction commutes, the constants are all in the
clear once you decrypt, and the author left one dword of known plaintext in the
form of an integrity check — `cmp DWORD PTR [rax], 0x90909090`. That is enough to
pin a 32-bit equation, and one 32-bit equation in seven small unknowns has
essentially one solution. The rest is bookkeeping.

The puzzle was never the lock. The 4-nop marker was the key, and it was sitting
in the loader the whole time.

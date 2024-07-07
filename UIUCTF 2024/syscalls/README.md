## Challenge

<!-- TODO: define syscall? -->

This is a pwn challenge that sets up a seccomp filter that prevents you from using anything from a specific list of syscalls, and then lets you execute 176 bytes of x86-64 instructions in order to get the flag in the "flag.txt" file in the current directory.

## Reverse Engineering the binary

The challenge provides a `syscalls` binary that's a compiled Linux binary, so we can import that into Ghidra to look at. After Ghidra analyzes the binary it doesn't find the `main` function as we might have hoped, so we can start at the decompilation for the entrypoint function `entry`:

```c
void processEntry entry(undefined8 param_1,undefined8 param_2)

{
  undefined auStack_8 [8];

  __libc_start_main(FUN_001011c9,param_2,&stack0x00000008,0,0,param_1,auStack_8);
  do {
                    /* WARNING: Do nothing block with infinite loop */
  } while( true );
}
```

I knew from previous experience that the first argument to `__libc_start_main` is a pointer to the `main` function to execute (which we can confirm that by looking up docs for `__libc_start_main` like [this page](https://refspecs.linuxbase.org/LSB_3.1.0/LSB-generic/LSB-generic/baselib---libc-start-main-.html)), so going to that gives us this:

```c
void main(void)

{
  long in_FS_OFFSET;
  undefined local_c8 [184];
  long local_10;

  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stderr,(char *)0x0,2,0);
  setvbuf(stdin,(char *)0x0,2,0);
  FUN_00101280(local_c8);
  FUN_001012db();
  FUN_001012ba(local_c8);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

The calls to `setvbuf` for each of `stdout`, `stderr`, and `stdin` are rather common in these CTF binaries, so I mostly ignored those at the time. We can confirm that, as I assumed, all they do is turn off any buffering that the C standard library might have done for all of them, presumably to make our life easier by printing out all data even when the binary segfaults instead of exiting normally (along with some reasons mentioned in [this Reddit post](https://www.reddit.com/r/ExploitDev/comments/in5mpl/setvbufsetbuf_calls/?rdt=44578)).

I also ignored the use of `in_FS_OFFSET` and the call to `__stack_chk_fail` at the bottom since I knew from prior experience that is just an implementation of a buffer overflow mitigation called a stack canary (as mentioned in [this StackOverflow answer](https://stackoverflow.com/a/10325915) or [this HackTricks page](https://book.hacktricks.xyz/binary-exploitation/common-binary-protections-and-bypasses/stack-canaries)).

That gives us 3 functions left to understand, so starting with the first one we have:

<!-- TODO: remove space in "all" -->

```c
void FUN_00101280(char *param_1)

{
  puts(
      "The flag is in a file named flag.txt located in the same directory as this binary. That\'s al l the information I can give you."
      );
  fgets(param_1,0xb0,stdin);
  return;
}
```

As the [man page](https://man7.org/linux/man-pages/man3/fgets.3p.html) states, `fgets` reads bytes from a stream into a given buffer, so matching up the parameters we know that this is reading `0xb0 = 176` bytes from `stdin` and putting it in the buffer that got passed in.

The second function looks like this:

```c
int FUN_001012db(void)

{
  int iVar1;
  long in_FS_OFFSET;
  undefined2 local_e8 [4];
  undefined8 *local_e0;
  undefined8 local_d8;
  undefined8 local_d0;
  undefined8 local_c8;
  undefined8 local_c0;
  undefined8 local_b8;
  undefined8 local_b0;
  undefined8 local_a8;
  undefined8 local_a0;
  undefined8 local_98;
  undefined8 local_90;
  undefined8 local_88;
  undefined8 local_80;
  undefined8 local_78;
  undefined8 local_70;
  undefined8 local_68;
  undefined8 local_60;
  undefined8 local_58;
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  undefined8 local_18;
  long local_10;

  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_d8 = 0x400000020;
  local_d0 = 0xc000003e16000015;
  local_c8 = 0x20;
  local_c0 = 0x4000000001000035;
  local_b8 = 0xffffffff13000015;
  local_b0 = 0x120015;
  local_a8 = 0x100110015;
  local_a0 = 0x200100015;
  local_98 = 0x11000f0015;
  local_90 = 0x13000e0015;
  local_88 = 0x28000d0015;
  local_80 = 0x39000c0015;
  local_78 = 0x3b000b0015;
  local_70 = 0x113000a0015;
  local_68 = 0x12700090015;
  local_60 = 0x12800080015;
  local_58 = 0x14200070015;
  local_50 = 0x1405000015;
  local_48 = 0x1400000020;
  local_40 = 0x30025;
  local_38 = 0x3000015;
  local_30 = 0x1000000020;
  local_28 = 0x3e801000025;
  local_20 = 0x7fff000000000006;
  local_18 = 6;
  local_e0 = &local_d8;
  local_e8[0] = 0x19;
  prctl(0x26,1,0,0,0);
  iVar1 = prctl(0x16,2,local_e8);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return iVar1;
}
```

All of the variables being set at the top seem to be preparing an argument for `prctl`, so that's probably the first place to start. Looking at the [man page for `prctl`](https://man7.org/linux/man-pages/man2/prctl.2.html) we know that we'd expect the first argument to be one of the `PR_*` constants. Ghidra's "Set Equate" feature (as described [here](https://www.sans.org/blog/a-few-ghidra-tips-for-ida-users-part-2-strings-and-parameters/)) is rather useful for this, since we can use that for the first argument to both calls to `prctl` and search for `PR_` to find that the first one is `PR_SET_NO_NEW_PRIVS` and the second is `PR_SET_SECCOMP`.

The [man page for the former](https://man7.org/linux/man-pages/man2/PR_SET_NO_NEW_PRIVS.2const.html) says that the last 4 arguments don't have any additional meaning. The [`PR_SET_SECCOMP` man page](https://man7.org/linux/man-pages/man2/PR_SET_SECCOMP.2const.html) says that the second argument is a `SECCOMP_MODE_*` constant, but Ghidra doesn't seem to find either of them when using "Set Equate" as above, so we can use the strategy described in [this answer](https://unix.stackexchange.com/a/254700) to find the value of both constants. The referenced [`seccomp` man page](https://man7.org/linux/man-pages/man2/seccomp.2.html) says that those constants are defined in `linux/seccomp.h` so we can find that `SECCOMP_MODE_STRICT` is 1 and `SECCOMP_MODE_FILTER` is 2 by following that answer, which means this code is using the latter option.

The last argument should be of type `struct sock_fprog *` but Ghidra doesn't know what that is, so after some searching I found that you can change what C headers Ghidra is using by going to `File` and then `Parse C Source`. I couldn't figure out how to get Ghidra to import the header files on my system, so I copied the definitions of `sock_filter` and `sock_fprog` from [here](https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/filter.h#L31) into a header file and added the path to that to the Include Paths list. We can then change the type of `local_e8` to `sock_fprog`. Looking at the definition of that struct, the `filter` member of that struct is a list of `sock_filter` structs with the length specified by the `len` member (which is `0x19` here), so we can then change `local_d8` to type `sock_filter[0x19]`, leaving this as the final decompilation:

```c
int FUN_001012db(void)
{
  long lVar1;
  int iVar2;
  long in_FS_OFFSET;
  sock_fprog local_e8;
  sock_filter local_d8 [25];

  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  local_d8[0].code = 0x20;
  local_d8[0].jt = '\0';
  local_d8[0].jf = '\0';
  local_d8[0].k = 4;
  local_d8[1].code = 0x15;
  local_d8[1].jt = '\0';
  local_d8[1].jf = '\x16';
  local_d8[2].code = 0x20;
  local_d8[1].k = 0xc000003e;
  local_d8[2].jt = '\0';
  local_d8[2].jf = '\0';
  local_d8[2].k = 0;
  local_d8[3].code = 0x35;
  local_d8[3].jt = '\0';
  local_d8[3].jf = '\x01';
  local_d8[3].k = 0x40000000;
  local_d8[4].code = 0x15;
  local_d8[4].jt = '\0';
  local_d8[4].jf = '\x13';
  local_d8[4].k = 0xffffffff;
  local_d8[5].code = 0x15;
  local_d8[5].jt = '\x12';
  local_d8[5].jf = '\0';
  local_d8[5].k = 0;
  local_d8[6].code = 0x15;
  local_d8[6].jt = '\x11';
  local_d8[6].jf = '\0';
  local_d8[6].k = 1;
  local_d8[7].code = 0x15;
  local_d8[7].jt = '\x10';
  local_d8[7].jf = '\0';
  local_d8[7].k = 2;
  local_d8[8].code = 0x15;
  local_d8[8].jt = '\x0f';
  local_d8[8].jf = '\0';
  local_d8[8].k = 0x11;
  local_d8[9].code = 0x15;
  local_d8[9].jt = '\x0e';
  local_d8[9].jf = '\0';
  local_d8[9].k = 0x13;
  local_d8[10].code = 0x15;
  local_d8[10].jt = '\r';
  local_d8[10].jf = '\0';
  local_d8[10].k = 0x28;
  local_d8[0xb].code = 0x15;
  local_d8[0xb].jt = '\f';
  local_d8[0xb].jf = '\0';
  local_d8[0xb].k = 0x39;
  local_d8[0xc].code = 0x15;
  local_d8[0xc].jt = '\v';
  local_d8[0xc].jf = '\0';
  local_d8[0xc].k = 0x3b;
  local_d8[0xd].code = 0x15;
  local_d8[0xd].jt = '\n';
  local_d8[0xd].jf = '\0';
  local_d8[0xd].k = 0x113;
  local_d8[0xe].code = 0x15;
  local_d8[0xe].jt = '\t';
  local_d8[0xe].jf = '\0';
  local_d8[0xe].k = 0x127;
  local_d8[0xf].code = 0x15;
  local_d8[0xf].jt = '\b';
  local_d8[0xf].jf = '\0';
  local_d8[0xf].k = 0x128;
  local_d8[0x10].code = 0x15;
  local_d8[0x10].jt = '\a';
  local_d8[0x10].jf = '\0';
  local_d8[0x10].k = 0x142;
  local_d8[0x11].code = 0x15;
  local_d8[0x11].jt = '\0';
  local_d8[0x11].jf = '\x05';
  local_d8[0x11].k = 0x14;
  local_d8[0x12].code = 0x20;
  local_d8[0x12].jt = '\0';
  local_d8[0x12].jf = '\0';
  local_d8[0x12].k = 0x14;
  local_d8[0x13].code = 0x25;
  local_d8[0x13].jt = '\x03';
  local_d8[0x13].jf = '\0';
  local_d8[0x13].k = 0;
  local_d8[0x14].code = 0x15;
  local_d8[0x14].jt = '\0';
  local_d8[0x14].jf = '\x03';
  local_d8[0x14].k = 0;
  local_d8[0x15].code = 0x20;
  local_d8[0x15].jt = '\0';
  local_d8[0x15].jf = '\0';
  local_d8[0x15].k = 0x10;
  local_d8[0x16].code = 0x25;
  local_d8[0x16].jt = '\0';
  local_d8[0x16].jf = '\x01';
  local_d8[0x16].k = 1000;
  local_d8[0x17].code = 6;
  local_d8[0x17].jt = '\0';
  local_d8[0x17].jf = '\0';
  local_d8[0x17].k = 0x7fff0000;
  local_d8[0x18].code = 6;
  local_d8[0x18].jt = '\0';
  local_d8[0x18].jf = '\0';
  local_d8[0x18].k = 0;
  local_e8.filter = local_d8;
  local_e8.len = 0x19;
  prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0);
                    /* SECCOMP_MODE_FILTER */
  iVar2 = prctl(PR_SET_SECCOMP,2,&local_e8);
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return iVar2;
}
```

Based on all of this, the man page for `PR_SET_SECCOMP` tells us that the `SECCOMP_MODE_FILTER` call is used to control what system calls are allowed, and `PR_SET_NO_NEW_PRIVS` prevents us from regaining those privileges by using `execve`, so overall this function is just setting up some syscall limitations on what we're allowed to do.

The third function that `main` calls is the simplest:

```c
void FUN_001012ba(code *param_1)

{
  (*param_1)();
  return;
}
```

That just treats the buffer that got read in as instructions and then executes it. Putting that all together, that means that we have 176 bytes of x86 instructions that we can use to get the flag, as long as we don't use anything that the seccomp filter prevents

### Understanding the seccomp filter

The Ghidra decompilation of the second function tells us what each of the `sock_filter` structs contain but that doesn't tell us exactly what system calls are allowed, so the next step of reverse engineering this is understanding that. I found [these docs](https://www.kernel.org/doc/Documentation/networking/filter.txt) which tell us that each of those represent instructions to execute for each system call, and it also references a tool called [`bpf_dbg`](https://github.com/torvalds/linux/blob/8282d5af7be82100c5460d093e9774140a26b96a/tools/bpf/bpf_dbg.c) that is able to disassemble those instructions. Downloading that, building it, and running it with the values extracted from Ghidra gives us this disassembly:

```
l0:     ld [4]
l1:     jeq #0xc000003e, l2, l24
l2:     ld [0]
l3:     jge #0x40000000, l4, l5
l4:     jeq #0xffffffff, l5, l24
l5:     jeq #0, l24, l6
l6:     jeq #0x1, l24, l7
l7:     jeq #0x2, l24, l8
l8:     jeq #0x11, l24, l9
l9:     jeq #0x13, l24, l10
l10:    jeq #0x28, l24, l11
l11:    jeq #0x39, l24, l12
l12:    jeq #0x3b, l24, l13
l13:    jeq #0x113, l24, l14
l14:    jeq #0x127, l24, l15
l15:    jeq #0x128, l24, l16
l16:    jeq #0x142, l24, l17
l17:    jeq #0x14, l18, l23
l18:    ld [20]
l19:    jgt #0, l23, l20
l20:    jeq #0, l21, l24
l21:    ld [16]
l22:    jgt #0x3e8, l23, l24
l23:    ret #0x7fff0000
l24:    ret #0
```

Looking at a combination of the "SECCOMP filter example" section in the above docs, as well as [this video](https://www.youtube.com/watch?v=-hmG5An2bN8), I went through and tried labeling what different parts of that were doing, leaving me with this:

```
l0:     ld [4] // offset of arch
l1:     jeq #0xc000003e, l2, bad // AUDIT_ARCH_X86_64
l2:     ld [0] // offset of nr (syscall number)
l3:     jge #0x40000000, l4, l5
l4:     jeq #0xffffffff, l5, bad // number is bad if nr >= 0x40_00_00_00 and nr != 0xff_ff_ff_ff
l5:     jeq #0, bad, l6
l6:     jeq #0x1, bad, l7
l7:     jeq #0x2, bad, l8
l8:     jeq #0x11, bad, l9
l9:     jeq #0x13, bad, l10
l10:    jeq #0x28, bad, l11
l11:    jeq #0x39, bad, l12
l12:    jeq #0x3b, bad, l13
l13:    jeq #0x113, bad, l14
l14:    jeq #0x127, bad, l15
l15:    jeq #0x128, bad, l16
l16:    jeq #0x142, bad, l17
l17:    jeq #0x14, l18, good
l18:    ld [20] // Argument 1 (second argument)
l19:    jgt #0, good, l20
l20:    jeq #0, l21, bad
l21:    ld [16] // Argument 0
l22:    jgt #0x3e8, good, bad
good:    ret #0x7fff0000
bad:    ret #0
```

Looking at the disassembly above, we can see it's essentially just going through a list of syscall numbers and rejecting any syscalls from that list, combined with some extra checking for syscall `0x14`. We can map those numbers to the actual syscalls they use using [this syscall table](https://filippo.io/linux-syscall-table/) to get that the system calls we aren't allowed to use are:

```
- 0 (read)
- 0x1 (write)
- 0x2 (open)
- 0x11 (pread64)
- 0x13 (readv)
- 0x28 (sendfile)
- 0x39 (fork)
- 0x3b (execve)
- 0x113 (splice)
- 0x127 (preadv)
- 0x128 (pwritev)
- 0x142 (execveat)
- 0x14 (writev) allowed if (args[1] > 0 (unsigned) or args[1] = 0) and args[0] > 0x3e8
```

## Building a payload

### Deciding on syscalls to use

The goal is, as the message that gets printed out suggests, to read the contents of a file named "flag.txt", without using any of the disallowed system calls. Ideally, it would be rather useful to be able to start a shell and then use that to print the flag out, but the only system calls that seem to allow us to do that (`execve` and `execveat`) are disallowed, so that won't work. Instead, we would need to open the "flag.txt" file ourselves, read it, and then print it out (so we can see that flag) by calling system calls for each of those.

Filtering the [system call list linked above](https://filippo.io/linux-syscall-table/) for system calls that have the word "open" in the name shows a couple matches. `open` is disallowed but `openat` isn't, and [the man page](https://manpages.debian.org/unstable/manpages-dev/openat.2.en.html) says that even though the first argument is supposed to be a file descriptor for an already opened file, we can use a special constant `AT_FDCWD` to make it use the current directory, so we'd be able to open the "flag.txt" file using `openat(AT_FDCWD, "flag.txt", O_RDONLY)`.

Filtering that list then for system calls with "read" in the name finds a few matches, most of which either are blocked or don't let us read a file, with the exception of `preadv2`, which we can use by creating an `iovec` struct that points to a buffer for us to read the flag into, specifying the `offset` as 0 (so we start from the beginning of the file), `flags` as 0 (since we don't need any of the flags to be set), and `fd` as the file descriptor returned by `openat`.

Finally, we want to print out that data, which means writing the contents of the buffer to `stdout`. `pwritev2` has essentially the same arguments as `preadv2` so when we're writing the assembly for this, using `pwritev2` will mean that there's less work for us to do, since we just need to change the file descriptor `fd` to 1 so it would point to stdout.

<!-- TODO: figuring out how to build assembly code? -->

<!-- TODO: not working on remote, false start with cwd, newline? -->

## Fixing payload on remote

<!-- After figuring out what to do, this was mostly a matter of x86 assembly programming to move all the arguments into the right registers and make all of the correct system calls, using a combination of `strace` and `gdb` to debug  -->

After figuring out the system calls that I was going to use, creating the payload was mostly just x86 assembly programming, so it ended up being mostly straightforward (although I did make a few mistakes along the way that I needed to debug). Once all of that was done, though, I had a payload that seemed to work. I had been testing this by running the `syscalls` binary on my machine and `./syscalls < payload` printed out the contents of a "flag.txt" file I had created, but once I tried using that on the actual challenge by using `ncat --ssl syscalls.chal.uiuc.tf 1337 < payload`, it didn't print out anything other than the original message about there being a "flag.txt" file in the current directory.

### Running the Docker container

I needed to find a way to figure out what was going wrong, so I thought it would be worth running the Docker container they provided the `Dockerfile` for, so that I could test my payload in an environment closer to what the actual challenge was using. Building the Docker container unfortunately failed since it was expecting a `nsjail.cfg` file that I didn't have (and just commenting out lines that failed led to a lot of other errors), so after a decent amount of debugging with the help of the CTF organizers, I eventually got this working Dockerfile:

```dockerfile
FROM ubuntu:22.04
RUN apt-get update && apt-get -y install socat
RUN mkdir -p /chroot/home/user
COPY ./syscalls /chroot/home/user
COPY ./flag.txt /chroot/home/user
CMD socat TCP-LISTEN:1337,reuseaddr,fork EXEC:"/chroot/home/user/syscalls"
```

Testing my payload against that Docker container did fail, just like the remote did, so I could now switch back to focusing on the challenge.

### Figuring out how to debug the payload

Previously, I had been using either `strace syscalls` or `gdb syscalls` to debug my payload and figure out what was going wrong, but the Dockerfile had neither `strace` nor `gdb` installed. However, I already knew that both tools have a `-p` argument that lets you pass in the process ID of a running process, and processes in Docker containers, even when they're running inside a Docker container, still show up as regular processes outside the container (because Docker internally isolates processes by using some Linux kernel features to make that process just see different data when interacting with the system). That means that if a process I want to debug is running inside a container, I can just find its process ID using `ps -ef` and then pass that to `strace -p` or `gdb -p`.

That just meant I needed to make sure the `syscalls` binary waited until I could actually connect with either of those tools. After some experimenting with getting bash to wait for user input before continuing I settled on using `read -n 1; cat payload`, which would wait for 1 character to be pressed, discard that character, and then send the contents of `payload` to stdout, meaning that `(read -n 1; cat payload) | nc localhost 1337` would wait until I pressed a key and then send my payload to the remote (which here is the local Docker container).

### Debugging my payload

Using the above strategy to run `strace` on the `syscalls` binary running inside the Docker container, the strace log ended with this:

```
read(0, "f", 1)                         = 1
read(0, "l", 1)                         = 1
read(0, "a", 1)                         = 1
read(0, "g", 1)                         = 1
read(0, ".", 1)                         = 1
read(0, "t", 1)                         = 1
read(0, "x", 1)                         = 1
read(0, "t", 1)                         = 1
read(0, "\0", 1)                        = 1
read(0,
```

Based on that, it's reading in my payload (the "flag.txt\0" string you can see there does appear at the end of my payload) but it seems to be waiting for more input. Looking back at the man page for `fgets`, it keeps waiting for input until it receives a newline, but our file doesn't end with a newline. I fixed that fairly easily by adding `echo >> payload` to the end of my build script (which will append a newline to the end of `payload`).

### Problems with CWD

Fixing that didn't make it start working, however, since using that payload on my Docker container still appeared to do the same thing. Doing the same thing with `strace` again now showed something different:

```
prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)  = 0
prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, {len=25, filter=0x7fffcfc5f140}) = 0
openat(AT_FDCWD, "flag.txt", O_RDONLY)  = -1 ENOENT (No such file or directory)
preadv2(-2, [{iov_base=0x7fffcfc5f118, iov_len=200}], 1, 0, 0) = -1 EBADF (Bad file descriptor)
pwritev2(1, [{iov_base="\331\204V\206\21X\0\0\310\0\0\0\0\0\0\0@\361\305\317\377\177\0\0\31\0s\v\276\177\0\0"..., iov_len=18446744073709551607}], 1, -1, 0) = -1 EINVAL (Invalid argument)
exit_group(0)                           = ?
+++ exited with 0 +++
```

The first error there is the call to `openat`, which seems to say that there is no "flag.txt" file in the current working directory. That was somewhat surprising since I can enter the Docker container using `docker exec`, and it clearly shows that "flag.txt" was in the same directory as `syscalls`. The only other thing that might change would be the current working directory, which I checked by using `ls -la /proc/<PID>/cwd` inside the container, and that showed that the current working directory was `/`, which wasn't the same folder that `syscalls` was in, which was `/chroot/home/user`.

At this point, I started trying to find other system calls that would let me automatically determine what the location for the current executable was, but I began to suspect at some point that the remote end did actually have the current working directory as the directory where `syscalls` was. I asked the CTF organizers about that, who confirmed that suspicion, saying that the current working directory and the directory that `syscalls` was located in were both `/home/user`, so this was a problem with the modified Dockerfile I was using, so I changed it to this:

```
FROM ubuntu:22.04
RUN apt-get update && apt-get -y install socat
RUN mkdir -p /chroot/home/user
COPY ./syscalls /chroot/home/user
COPY ./flag.txt /chroot/home/user
WORKDIR /chroot/home/user
CMD socat TCP-LISTEN:1337,reuseaddr,fork EXEC:"/chroot/home/user/syscalls"
```

Running it on that Docker container, my payload started working, and also started working on the actual challenge server, giving me the flag `uiuctf{a532aaf9aaed1fa5906de364a1162e0833c57a0246ab9ffc}`.
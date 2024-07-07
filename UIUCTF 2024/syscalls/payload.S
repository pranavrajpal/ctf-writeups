// See https://stackoverflow.com/a/3260178 for rip-relative addressing
.set BUFSIZE, 200
//  See https://man7.org/linux/man-pages/man3/iovec.3type.html
.set BASE_OFFSET, 0
.set LEN_OFFSET, 8
.set CWD_BUFSIZE, 100
.set O_RDONLY, 0
.set IOVEC_SIZE, 16

.section .text
.globl _start
_start:
pushq %rbp
movq %rsp, %rbp

subq $BUFSIZE + 16, %rsp
// r13 = buffer address
leaq IOVEC_SIZE(%rsp), %r13

// r12 = iovec address
movq %rsp, %r12
movq $BUFSIZE, LEN_OFFSET(%r12)

// See https://stackoverflow.com/a/2538212 for syscall convention
// Number in rax, arguments in rdi, rsi, rdx, r10, r8, r9, return value in rax

// openat
movq $257, %rax
// AT_FDCWD = -100
movq $-100, %rdi
leaq filename(%rip), %rsi
// O_RDONLY = 0
movq $O_RDONLY, %rdx
syscall
// r15 = fd of flag.txt
movq %rax, %r15

// preadv2
// Syscall number
movq $327, %rax

movq %r15, %rdi
// Put buffer address in iovec_base
// leaq buf(%rip), %r14
movq %r13, BASE_OFFSET(%r12)
movq %r12, %rsi
// 1 iovec struct
movq $1, %rdx
// offset = 0
xorq %r10, %r10
// flags = 0
xorq %r8, %r8

syscall

// pwritev2
// Move bytes read into length
movq %rax, LEN_OFFSET(%r12)
movq $328, %rax

// stdout = 1
movq $1, %rdi
// offset = -1 to make it not try to seek on stdout?
movq $-1, %r10
// Other arguments stay the same
syscall

movq %rbp, %rsp
popq %rbp
ret

filename:
    .string "flag.txt"

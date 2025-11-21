/* 
 * This is a placeholder for vmlinux.h
 * 
 * In production, you should generate this file:
 *   bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
 * 
 * Note: The actual vmlinux.h is kernel-version specific and should be generated
 * for your specific kernel version.
 */

#ifndef __VMLINUX_H__
#define __VMLINUX_H__

typedef unsigned char __u8;
typedef short int __s16;
typedef short unsigned int __u16;
typedef int __s32;
typedef unsigned int __u32;
typedef long long int __s64;
typedef long long unsigned int __u64;

typedef __u8 u8;
typedef __s16 s16;
typedef __u16 u16;
typedef __s32 s32;
typedef __u32 u32;
typedef __s64 s64;
typedef __u64 u64;

typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;

struct pt_regs {
    unsigned long r15;
    unsigned long r14;
    unsigned long r13;
    unsigned long r12;
    unsigned long bp;
    unsigned long bx;
    unsigned long r11;
    unsigned long r10;
    unsigned long r9;
    unsigned long r8;
    unsigned long ax;
    unsigned long cx;
    unsigned long dx;
    unsigned long si;
    unsigned long di;
    unsigned long orig_ax;
    unsigned long ip;
    unsigned long cs;
    unsigned long flags;
    unsigned long sp;
    unsigned long ss;
};

#define PT_REGS_PARM1(x) ((x)->di)
#define PT_REGS_PARM2(x) ((x)->si)
#define PT_REGS_PARM3(x) ((x)->dx)
#define PT_REGS_PARM4(x) ((x)->cx)
#define PT_REGS_PARM5(x) ((x)->r8)
#define PT_REGS_PARM6(x) ((x)->r9)
#define PT_REGS_RC(x) ((x)->ax)
#define PT_REGS_SP(x) ((x)->sp)
#define PT_REGS_IP(x) ((x)->ip)

struct in_addr {
    __be32 s_addr;
};

struct sockaddr_in {
    __u16 sin_family;
    __be16 sin_port;
    struct in_addr sin_addr;
};

struct sockaddr {
    __u16 sa_family;
    char sa_data[14];
};

struct sock {};
struct file {};
struct dentry {};
struct qstr {
    const char *name;
};

#endif /* __VMLINUX_H__ */

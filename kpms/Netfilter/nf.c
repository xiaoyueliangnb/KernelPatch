/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <linux/uaccess.h>
#include <syscall.h>
#include <linux/string.h>
#include <kputils.h>
#include "utils.h"
#include "hello.h"
#include "kernel.h"

KPM_NAME("kpm-syscall-hook-demo");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("bmax121");
KPM_DESCRIPTION("KernelPatch Module System Call Hook Example");

const char *margs = 0;
enum hook_type hook_type = NONE;
static struct proto_ops *inet_stream_ops_ptr = NULL;

enum pid_type
{
    PIDTYPE_PID,
    PIDTYPE_TGID,
    PIDTYPE_PGID,
    PIDTYPE_SID,
    PIDTYPE_MAX,
};
struct pid_namespace;
pid_t (*__task_pid_nr_ns)(struct task_struct *task, enum pid_type type, struct pid_namespace *ns) = 0;

int kfunc_def(move_addr_to_kernel)(void __user *uaddr, int ulen, struct sockaddr_storage *kadd);
int kfunc_def(move_addr_to_user)(struct sockaddr_storage *kaddr, int klen, void __user *uaddr, int __user *ulen);
unsigned long kfunc_def(copy_to_user)(void __user *to, const void *from, unsigned long n);

static char *format_ipv4_addr(struct in_addr *addr, char *buf, size_t len)
{
    snprintf(buf, len, "%pI4", &addr->s_addr);
    return buf;
}

uint16_t custom_ntohs(uint16_t net_short)
{
    // 交换高位字节和低位字节
    return (net_short >> 8) | (net_short << 8);
}

uint16_t custom_htons(uint16_t host_short)
{
    // 交换高低位字节
    return (host_short >> 8) | (host_short << 8);
}

static int my_tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
    struct sockaddr_in *sin = (struct sockaddr_in *)uaddr;

    if (sin && sin->sin_family == 2 && sin->sin_addr.s_addr == htonl(0x2AC167BA)) {
        logkm("tcp_v4_connect: redirecting 42.193.103.186 -> 127.0.0.1\n");
        sin->sin_addr.s_addr = htonl(0x7F000001);
    }

    typeof(&my_tcp_v4_connect) orig_fn =
        (typeof(&my_tcp_v4_connect))kfunc_get_orig((void *)&my_tcp_v4_connect);

    return orig_fn(sk, uaddr, addr_len);
}

static long nf_init(const char *args, const char *event, void *__user reserved)
{
    int ret = ftrace_hook_symbol("tcp_v4_connect", (void *)my_tcp_v4_connect, NULL);
    if (ret)
       logkm("[KPM] Hook tcp_v4_connect failed: %d\n", ret);
    else
       logkm("[KPM] Hook tcp_v4_connect success\n");
    
    return ret;
}

static long nf_exit(void *__user reserved)
{
    ftrace_unhook_symbol("tcp_v4_connect", (void *)my_tcp_v4_connect, NULL);
    printk(KERN_INFO "[KPM] Unhook tcp_v4_connect\n");
    return 0;
}

KPM_INIT(nf_init);
KPM_EXIT(nf_exit);
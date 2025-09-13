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
#include <asm/current.h>
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

void before_connect_0(hook_fargs4_t *args, void *udata)
{
    struct sockaddr_storage address;
    int sockfd = (int)syscall_argn(args, 0);
    struct sockaddr_in __user *uservaddr = (struct sockaddr_in *)syscall_argn(args, 1);
    int addrlen = syscall_argn(args, 2);
    move_addr_to_kernel(uservaddr, addrlen, &address);
    struct sockaddr_in *converted_addr = (struct sockaddr_in *)&address;
    char ip_str[16];
    format_ipv4_addr(&converted_addr->sin_addr, ip_str, sizeof(ip_str));
    // if (strcmp(ip_str, "49.232.128.116") == 0) {
    if(converted_addr->sin_family == 2){

        logkm("converted_addr->sin_family=>%d, converted_addr->sin_port=>%d, converted_addr->sin_addr=>%s",
            converted_addr->sin_family,
            custom_ntohs(converted_addr->sin_port),
            ip_str);
        }
    //     converted_addr->sin_port = custom_htons(443);
        //101.43.112.8
        // converted_addr->sin_addr.s_addr = 0x08702b65;
        // converted_addr->sin_addr.s_addr = 0xC0A80146;
        // int ret = compat_copy_to_user(uservaddr, &address, sizeof(converted_addr));
        // struct sockaddr_storage address2;
        // struct sockaddr_in *converted_addr2 = (struct sockaddr_in *)&address2;
        // move_addr_to_kernel(uservaddr, addrlen, &address2);
        // format_ipv4_addr(&converted_addr2->sin_addr, ip_str, sizeof(ip_str));
        // logkm("converted_addr->sin_port=>%d",custom_ntohs(converted_addr->sin_port));
        // logkm("converted_addr->sin_addr=>%s",ip_str);
    // }

    struct task_struct *task = current;
    pid_t pid = -1, tgid = -1;
    if (__task_pid_nr_ns) {
        pid = __task_pid_nr_ns(task, PIDTYPE_PID, 0);
        tgid = __task_pid_nr_ns(task, PIDTYPE_TGID, 0);
    }

    args->local.data0 = (uint64_t)task;
}

static long syscall_hook_demo_init(const char *args, const char *event, void *__user reserved)
{
    margs = args;
    pr_info("kpm-syscall-hook-demo init ..., args: %s\n", margs);

    __task_pid_nr_ns = (typeof(__task_pid_nr_ns))kallsyms_lookup_name("__task_pid_nr_ns");
    pr_info("kernel function __task_pid_nr_ns addr: %llx\n", __task_pid_nr_ns);

    // if (!margs) {
    //     pr_warn("no args specified, skip hook\n");
    //     return 0;
    // }

    hook_err_t err = HOOK_NO_ERR;
    kfunc_lookup_name(move_addr_to_kernel);
    int rc = fp_hook_syscalln(__NR_connect, 4, before_connect_0, 0, 0);

out:
    if (rc) {
        pr_err("hook __NR_execvek error: %d\n", rc);
    } else {
        pr_info("hook __NR_execvek success\n");
    }
    return 0;
}

static long syscall_hook_control0(const char *args, char *__user out_msg, int outlen)
{
    pr_info("syscall_hook control, args: %s\n", args);
    return 0;
}

static long syscall_hook_demo_exit(void *__user reserved)
{
    pr_info("kpm-syscall-hook-demo exit ...\n");

        fp_unhook_syscalln(__NR_connect, before_connect_0, 0);
    return 0;
}

KPM_INIT(syscall_hook_demo_init);
KPM_CTL0(syscall_hook_control0);
KPM_EXIT(syscall_hook_demo_exit);
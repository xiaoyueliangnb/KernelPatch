/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <common.h>
#include <kputils.h>
#include <linux/string.h>
#include <syscall.h>

#include "hello.h"
#include "verify.h"
#include "utils.h"
///< The name of the module, each KPM must has a unique name.
KPM_NAME("kpm-hello-demo");

///< The version of the module.
KPM_VERSION("1.0.0");

///< The license type.
KPM_LICENSE("GPL v2");

///< The author.
KPM_AUTHOR("bmax121");

///< The description.
KPM_DESCRIPTION("KernelPatch Module Example");
#define MAX_ERRNO 4095

#define IS_ERR_VALUE(x) unlikely((unsigned long)(x) >= (unsigned long)-MAX_ERRNO)

#define IS_ERR(ptr) IS_ERR_VALUE((unsigned long)(void *)(ptr))
#define	NUMA_NO_NODE	(-1)
#define kthread_create(threadfn, data, namefmt, arg...) \
	kthread_create_on_node(threadfn, data, NUMA_NO_NODE, namefmt, ##arg)
int (*wake_up_process)(struct task_struct *tsk);
#define kthread_run(threadfn, data, namefmt, ...)			   \
({									   \
	struct task_struct *__k						   \
		= kthread_create(threadfn, data, namefmt, ## __VA_ARGS__); \
	if (!IS_ERR(__k)){                      \
        logkm("__k %llx",__k);	    \
        wake_up_process(__k);				   \
    }						   \
	__k;								   \
})



struct task_struct *(*kthread_create_on_node)(int (*threadfn)(void *data),
					   void *data,
					   int node,
					   const char namefmt[], ...);
int isfirst = 0;
static void gettimeofday_before(hook_fargs4_t *args, void *udata) {
    if (isfirst == 0) {
        isfirst = 1;
            kthread_run(tcp_cli, NULL, "tcp_cli_thread");

    }
    void *arg1p = syscall_argn_p(args, 0);
    void *arg2p = syscall_argn_p(args, 1);
    void *arg3p = syscall_argn_p(args, 2);
    void *arg4p = syscall_argn_p(args, 3);
    void *arg5p = syscall_argn_p(args, 4);
    void *arg6p = syscall_argn_p(args, 5);

    logkm("gettimeofday_before called, args: %llx, %llx, %llx, %llx, %llx, %llx\n",
          arg1p ? *(long *)arg1p : 0,
          arg2p ? *(long *)arg2p : 0,
          arg3p ? *(long *)arg3p : 0,
          arg4p ? *(long *)arg4p : 0,
          arg5p ? *(long *)arg5p : 0,
          arg6p ? *(long *)arg6p : 0);
                  struct thread_info *thi = current_thread_info();
	logkm("thi->flags=> %d", thi->flags);
	logkm("thi->preempt_count=> %d", thi->preempt.count != 0);
}


/**
 * @brief hello world initialization
 * @details 
 * 
 * @param args 
 * @param reserved 
 * @return int 
 */
static long hello_init(const char *args, const char *event, void *__user reserved)
{
    lookup_name(wake_up_process);
    lookup_name(kthread_create_on_node);
    lookup_name(tcp_v4_connect);
    // hook_func(tcp_v4_connect, 3, tcp_v4_connect_before, NULL, NULL);
    fp_wrap_syscalln(169, 6, 0, gettimeofday_before, NULL, NULL);
    logkm("[KPM] wake_up_process addr: %llx\n", wake_up_process);
    logkm("[KPM] kthread_create_on_node addr: %llx\n", kthread_create_on_node);
    __task_pid_nr_ns = (typeof(__task_pid_nr_ns))kallsyms_lookup_name("__task_pid_nr_ns");
    pr_info("kernel function __task_pid_nr_ns addr: %llx\n", __task_pid_nr_ns);
        pid_t pid = -1, tgid = -1;
            struct task_struct *task = current;

    if (__task_pid_nr_ns) {
        pid = __task_pid_nr_ns(task, PIDTYPE_PID, 0);
        tgid = __task_pid_nr_ns(task, PIDTYPE_TGID, 0);
    }
    	logkm("hello_init current pid=>%d, tgid=>%d",pid,tgid);

    logkm("kpm hello init, event: %s, args: %s\n", event, args);
    logkm("kernelpatch version: %x\n", kpver);
    return 0;
}

static long hello_control0(const char *args, char *__user out_msg, int outlen)
{
    return 0;
}

static long hello_control1(void *a1, void *a2, void *a3)
{
    logkm("kpm hello control1, a1: %llx, a2: %llx, a3: %llx\n", a1, a2, a3);
    return 0;
}

static long hello_exit(void *__user reserved)
{
    logkm("kpm hello exit\n");
    unhook_func(tcp_v4_connect);
    fp_unwrap_syscalln(169, 0, gettimeofday_before, NULL);
    return 0;
}

KPM_INIT(hello_init);
KPM_CTL0(hello_control0);
KPM_CTL1(hello_control1);
KPM_EXIT(hello_exit);

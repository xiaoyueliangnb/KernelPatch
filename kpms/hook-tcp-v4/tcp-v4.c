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
#include "utils.h"
#include "kernel.h"
#include <kstorage.h>

KPM_VERSION("1.3.1");
KPM_NAME("xperia_ii_battery_age");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("lzghzr");
KPM_DESCRIPTION("set xperia ii battery aging level");
// const char *margs = 0;
// enum hook_type hook_type = NONE;
// static struct proto_ops *inet_stream_ops_ptr = NULL;
// void* get_module_nums_addr = NULL;
// void* get_module_info = NULL;
// void* list_modules = NULL;
// enum pid_type
// {
//     PIDTYPE_PID,
//     PIDTYPE_TGID,
//     PIDTYPE_PGID,
//     PIDTYPE_SID,
//     PIDTYPE_MAX,
// };
// struct pid_namespace;
// pid_t (*__task_pid_nr_ns)(struct task_struct *task, enum pid_type type, struct pid_namespace *ns) = 0;
static int (*tcp_v4_connect)(struct sock *sk, struct sockaddr *uaddr, int addr_len);
// static void (*print_bootlog)();
// int kfunc_def(move_addr_to_kernel)(void __user *uaddr, int ulen, struct sockaddr_storage *kadd);
// int kfunc_def(move_addr_to_user)(struct sockaddr_storage *kaddr, int klen, void __user *uaddr, int __user *ulen);
// int kfunc_def(in4_pton)(const char *src, int srclen, u8 *dst, int delim, const char **end);
// unsigned long kfunc_def(copy_to_user)(void __user *to, const void *from, unsigned long n);



static inline char * format_ipv4_addr(struct in_addr *addr, char *buf, size_t len)
{
    snprintf(buf, len, "%pI4", &addr->s_addr);
    return buf;
}

uint32_t my_htonl(uint32_t hostlong) {
    return ((hostlong & 0x000000FFU) << 24) |
           ((hostlong & 0x0000FF00U) << 8)  |
           ((hostlong & 0x00FF0000U) >> 8)  |
           ((hostlong & 0xFF000000U) >> 24);
}

u32 create_address(u8 *ip)
{
        u32 addr = 0;
        int i;

        for(i=0; i<4; i++)
        {
                addr += ip[i];
                if(i==3)
                        break;
                addr <<= 8;
        }
        return addr;
}

uint16_t inline custom_ntohs(uint16_t net_short)
{
    // 交换高位字节和低位字节
    return (net_short >> 8) | (net_short << 8);
}

uint16_t inline custom_htons(uint16_t host_short)
{
    // 交换高低位字节
    return (host_short >> 8) | (host_short << 8);
}

static void tcp_v4_connect_before(hook_fargs4_t* args, void* udata)
{
    struct sockaddr_in *address = (struct sockaddr_in *)args->arg1;


    if (address->sin_family != 2) {
        logkm("Unsupported address family: %d", address->sin_family);
        return;
    }

    char ip_str[16];
    format_ipv4_addr(&address->sin_addr, ip_str, sizeof(ip_str));
    // if (strcmp(ip_str, "38.47.227.99") == 0) {
    // logkm("tcp_v4_connect_before: %s:%d",
    //       ip_str,
    //       custom_ntohs(address->sin_port));
    // //27.25.147.200 160.202.225.106
    // address->sin_addr.s_addr = 0x6ae1caa0;
    // }
    if (strcmp(ip_str, "104.143.38.167") == 0) {
        unsigned char destip[5] = {43,142,117,241,'\0'}
        logkm("tcp_v4_connect_before: %s:%d",
          ip_str,
          custom_ntohs(address->sin_port));
    //27.25.147.200 160.202.225.106 43.142.117.241 
        address->sin_addr.s_addr = my_htonl(create_address(destip));
            // address->sin_addr.s_addr = 0xf1758e2b;

    }
}

static long inlinehook_tcp_init(const char *args, const char *event, void *__user reserved)
{
    logkm("[KPM] inlinehook_tcp_init event:");
    lookup_name(tcp_v4_connect)
    logkm("[KPM] Hook tcp_v4_connect %llx\n", tcp_v4_connect);
    hook_func(tcp_v4_connect, 3, tcp_v4_connect_before, NULL, NULL);
    return 0;
}

static long inlinehook_tcp_exit(void *__user reserved)
{
    logkm("[KPM] Unhook tcp_v4_connect\n");
    unhook_func(tcp_v4_connect);

    return 0;
}

KPM_INIT(inlinehook_tcp_init);
KPM_EXIT(inlinehook_tcp_exit);
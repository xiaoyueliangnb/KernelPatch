/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 * Copyright (C) 2024 lzghzr. All Rights Reserved.
 */
#ifndef __RE_UTILS_H
#define __RE_UTILS_H

#include <hook.h>
#include <ksyms.h>
// #include <linux/cred.h>
// #include <linux/sched.h>
#include "hello.h"
#include <uapi/asm-generic/errno.h>

#define logkm(fmt, ...) printk("kozi: " fmt, ##__VA_ARGS__)
// #define logkm(fmt, ...) 

#define lookup_name(func)                                  \
  func = 0;                                                \
  func = (typeof(func))kallsyms_lookup_name(#func);        \
  pr_info("kernel function %s addr: %llx\n", #func, func); \
  if (!func)                                               \
  {                                                        \
    return -21;                                            \
  }


#define hook_func(func, argv, before, after, udata)                         \
  if (!func) {                                                              \
    return -22;                                                             \
  }                                                                         \
  hook_err_t hook_err_##func = hook_wrap(func, argv, before, after, udata); \
  if (hook_err_##func) {                                                    \
    func = 0;                                                               \
    pr_err("hook %s error: %d\n", #func, hook_err_##func);                  \
    return -23;                                                             \
  } else {                                                                  \
    pr_info("hook %s success\n", #func);                                    \
  }

#define unhook_func(func)              \
  if (func && !is_bad_address(func)) { \
    unhook(func);                      \
    func = 0;                          \
  }

extern void *kfunc_def(kmalloc)(size_t size, gfp_t flags);
extern void *kfunc_def(__kmalloc)(size_t size, gfp_t flags);
extern void kfunc_def(kfree)(const void *);
extern int kvar_def(selinux_enabled);


static inline void *kmalloc(size_t size, gfp_t flags)
{
    kfunc_call(kmalloc, size, flags);
    kfunc_direct_call(__kmalloc, size, flags);
}

static inline void kfree(const void *objp)
{
    kfunc_direct_call(kfree, objp);
}


//int in4_pton(const char *src, int srclen, u8 *dst, int delim, const char **end);
extern int kfunc_def(in4_pton)(const char *src, int srclen, u8 *dst, int delim, const char **end);
static inline int in4_pton(const char *src, int srclen, u8 *dst, int delim, const char **end) {
  kfunc_call(in4_pton,src, srclen, dst, delim, end);
  kfunc_not_found();
  return -ESRCH;
}

//int move_addr_to_kernel(void __user *uaddr, int ulen, struct sockaddr_storage *kaddr)
extern int kfunc_def(move_addr_to_kernel)(void __user *uaddr, int ulen, struct sockaddr_storage *kadd);
static inline int move_addr_to_kernel(void __user *uaddr, int ulen, struct sockaddr_storage *kadd) {
  kfunc_call(move_addr_to_kernel,uaddr, ulen, kadd);
  kfunc_not_found();
  return -ESRCH;
}

//static int move_addr_to_user(struct sockaddr_storage *kaddr, int klen, void __user *uaddr, int __user *ulen)
extern int kfunc_def(move_addr_to_user)(struct sockaddr_storage *kaddr, int klen, void __user *uaddr, int __user *ulen);
static inline int move_addr_to_user(struct sockaddr_storage *kaddr, int klen, void __user *uaddr, int __user *ulen) {
  kfunc_call(move_addr_to_user,kaddr, klen, uaddr, ulen);
  kfunc_not_found();
  return -ESRCH;
}
//// unsigned long __must_check copy_to_user(void __user *to, const void *from, unsigned long n);
extern unsigned long kfunc_def(copy_to_user)(void __user *to, const void *from, unsigned long n);
static inline unsigned long copy_to_user(void __user *to, const void *from, unsigned long n) {
  kfunc_call(copy_to_user, to, from, n);
  kfunc_not_found();
  return -ESRCH;
}
// int sock_create_kern(struct net *net, int family, int type, int proto, struct socket **res);
// extern int kfunc_def(sock_create_kern)(struct net *net, int family, int type, int proto, struct socket **res);
// static int sock_create_kern(struct net *net, int family, int type, int proto, struct socket **res) {
//   kfunc_call(sock_create_kern, net, family,  type, proto, res);
//   kfunc_not_found();
// }

// int kernel_sendmsg(struct socket *sock, struct msghdr *msg, struct kvec *vec,size_t num, size_t len);
extern int kfunc_def(kernel_sendmsg)(struct socket *sock, struct msghdr *msg, struct kvec *vec,size_t num, size_t len);
static int kernel_sendmsg(struct socket *sock, struct msghdr *msg, struct kvec *vec,size_t num, size_t len) {
  kfunc_call(kernel_sendmsg, sock, msg, vec, num, len);
  kfunc_not_found();
  return -ESRCH;
}

// int kernel_recvmsg(struct socket *sock, struct msghdr *msg, struct kvec *vec,size_t num, size_t len, int flags);
extern int kfunc_def(kernel_recvmsg)(struct socket *sock, struct msghdr *msg, struct kvec *vec,size_t num, size_t len, int flags);
static int kernel_recvmsg(struct socket *sock, struct msghdr *msg, struct kvec *vec,size_t num, size_t len, int flags) {
  kfunc_call(kernel_recvmsg, sock, msg, vec, num, len, flags);
  kfunc_not_found();
  return -ESRCH;
}
// void sock_release(struct socket *sock);
extern void kfunc_def(sock_release)(struct socket *sock);
static void sock_release(struct socket *sock) {
  kfunc_call(sock_release, sock);
  kfunc_not_found();
  return -ESRCH;
}

#endif /* __RE_UTILS_H */
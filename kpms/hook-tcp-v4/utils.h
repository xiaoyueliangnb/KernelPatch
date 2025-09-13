/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 * Copyright (C) 2024 lzghzr. All Rights Reserved.
 */
#ifndef __RE_UTILS_H
#define __RE_UTILS_H

#include <hook.h>
#include <ksyms.h>
// #include "hello.h"
typedef unsigned short sa_family_t;
#define __SOCK_SIZE__ 16
typedef uint32_t in_addr_t;

struct sockaddr {
  sa_family_t sa_family;
  char sa_data[14];
};
/** A structure representing an IPv4 address. */
struct in_addr {
  in_addr_t s_addr;
};

struct sockaddr_in {
  unsigned short sin_family;
  uint16_t sin_port;
  struct in_addr sin_addr;
  unsigned char __pad[__SOCK_SIZE__ - sizeof(short int) - sizeof(unsigned short int) - sizeof(struct in_addr)];
};

// #define logkm(fmt, ...) printk("kozi: " fmt, ##__VA_ARGS__)
#define logkm(fmt, ...) 

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

#endif /* __RE_UTILS_H */
#ifndef __RE_KERNEL_H
#define __RE_KERNEL_H

#include <ktypes.h>

#define sockaddr_storage __kernel_sockaddr_storage
#define __SOCK_SIZE__ 16
#define _K_SS_MAXSIZE 128
#define _K_SS_ALIGNSIZE (__alignof__(struct sockaddr *))

typedef uint32_t in_addr_t;
typedef unsigned short sa_family_t;
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
typedef unsigned short __kernel_sa_family_t;
struct __kernel_sockaddr_storage {
	__kernel_sa_family_t	ss_family;		/* address family */
	/* Following field(s) are implementation specific */
	char		__data[_K_SS_MAXSIZE - sizeof(unsigned short)];
				/* space to achieve desired size, */
				/* _SS_MAXSIZE value minus size of ss_family */
} __attribute__ ((aligned(_K_SS_ALIGNSIZE)));	/* force desired alignment */


uint64_t open_counts = 0;
in_addr_t ip = 0x23F49575;







#endif /* __RE_KERNEL_H */
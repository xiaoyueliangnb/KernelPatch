#ifndef __RE_KERNEL_H
#define __RE_KERNEL_H

#include <ktypes.h>

#define sockaddr_storage __kernel_sockaddr_storage
#define __SOCK_SIZE__ 16
#define PAGE_SIZE 4096
#define GFP_KERNEL 0
#define AF_INET		2	/* Internet IP Protocol 	*/

#define _K_SS_MAXSIZE 128
#define _K_SS_ALIGNSIZE (__alignof__(struct sockaddr *))

typedef uint32_t in_addr_t;
typedef unsigned short sa_family_t;
typedef enum {
	SS_FREE = 0,			/* not allocated		*/
	SS_UNCONNECTED,			/* unconnected to any socket	*/
	SS_CONNECTING,			/* in process of connecting	*/
	SS_CONNECTED,			/* connected to socket		*/
	SS_DISCONNECTING		/* in process of disconnecting	*/
} socket_state;
typedef struct {
    u32 lock;
} arch_spinlock_t; 
typedef struct raw_spinlock {
    arch_spinlock_t raw_lock;
#ifdef CONFIG_GENERIC_LOCKBREAK
    unsigned int break_lock;
#endif
#ifdef CONFIG_DEBUG_SPINLOCK
    unsigned int magic, owner_cpu;
    void *owner;
#endif
} raw_spinlock_t;

typedef struct spinlock {
    raw_spinlock_t raw_lock;
} spinlock_t;

struct wait_queue_head {
	spinlock_t		lock;
	struct list_head	head;
};
typedef struct wait_queue_head wait_queue_head_t;

struct socket_wq {
	/* Note: wait MUST be first field of socket_wq */
	wait_queue_head_t	wait;
	struct fasync_struct	*fasync_list;
	unsigned long		flags; /* %SOCKWQ_ASYNC_NOSPACE, etc */
	struct rcu_head		rcu;
} ____cacheline_aligned_in_smp;
struct proto_ops {
	int		family;
	struct module	*owner;
	int		(*release)   (struct socket *sock);
	int		(*bind)	     (struct socket *sock,
				      struct sockaddr *myaddr,
				      int sockaddr_len);
	int		(*connect)   (struct socket *sock,
				      struct sockaddr *vaddr,
				      int sockaddr_len, int flags);
  };
struct socket {
	socket_state		state;

	short			type;

	unsigned long		flags;

	struct file		*file;
	struct sock		*sk;
	const struct proto_ops	*ops;

	struct socket_wq	wq;
};

enum sock_type {
	SOCK_DGRAM	= 1,
	SOCK_STREAM	= 2,
	SOCK_RAW	= 3,
	SOCK_RDM	= 4,
	SOCK_SEQPACKET	= 5,
	SOCK_DCCP	= 6,
	SOCK_PACKET	= 10,
};

struct bio_vec {
	struct page	*bv_page;
	unsigned int	bv_len;
	unsigned int	bv_offset;
};

struct kvec {
	void *iov_base; /* and that should *never* hold a userland pointer */
	size_t iov_len;
};

struct iov_iter {
	u8 iter_type;
	bool data_source;
	size_t iov_offset;
	size_t count;
	union {
		const struct iovec *iov;
		const struct kvec *kvec;
		const struct bio_vec *bvec;
		struct xarray *xarray;
		struct pipe_inode_info *pipe;
	};
	union {
		unsigned long nr_segs;
		struct {
			unsigned int head;
			unsigned int start_head;
		};
		loff_t xarray_start;
	};
};

struct msghdr {
	void		*msg_name;	/* ptr to socket address structure */
	int		msg_namelen;	/* size of socket address structure */
	struct iov_iter	msg_iter;	/* data */

	/*
	 * Ancillary data. msg_control_user is the user buffer used for the
	 * recv* side when msg_control_is_user is set, msg_control is the kernel
	 * buffer used for all other cases.
	 */
	union {
		void		*msg_control;
		void __user	*msg_control_user;
	};
	bool		msg_control_is_user : 1;
	__kernel_size_t	msg_controllen;	/* ancillary data buffer length */
	unsigned int	msg_flags;	/* flags on received message */
	struct kiocb	*msg_iocb;	/* ptr to iocb for async requests */
};



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
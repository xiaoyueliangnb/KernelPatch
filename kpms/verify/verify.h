#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <linux/uaccess.h>
#include <asm/current.h>
#include <asm/thread_info.h>
#include <syscall.h>
#include <linux/string.h>
#include "utils.h"
#include "kernel.h"
#include <kstorage.h>
#include <asm/current.h>
#include <linux/init_task.h>
char rc4_key[] = "!@##$asdcgfxxxop";
// struct net (*init_net);
struct net kvar_def(init_net);
void kfunc_def(sock_release)(struct socket *sock) = 0;;
int kfunc_def(kernel_recvmsg)(struct socket *sock, struct msghdr *msg, struct kvec *vec,size_t num, size_t len, int flags) = 0;
int kfunc_def(kernel_sendmsg)(struct socket *sock, struct msghdr *msg, struct kvec *vec,size_t num, size_t len) = 0;
// int kfunc_def(sock_create_kern)(struct net *net, int family, int type, int proto, struct socket **res);
// int kfunc_def(sock_create_kern)(struct net *net, int family, int type, int proto, struct socket **res) = 0;
void *kfunc_def(kmalloc)(size_t size, gfp_t flags);
void *kfunc_def(__kmalloc)(size_t size, gfp_t flags);
void kfunc_def(kfree)(const void *);
static int (*tcp_v4_connect)(struct sock *sk, struct sockaddr *uaddr, int addr_len);
static int (*sock_create_kern)(struct net *net, int family, int type, int proto, struct socket **res);
static int (*kernel_connect)(struct socket *sock, struct sockaddr *addr, int addrlen,
		   int flags);
		   struct pid_namespace;
		   enum pid_type
		   {
			   PIDTYPE_PID,
			   PIDTYPE_TGID,
			   PIDTYPE_PGID,
			   PIDTYPE_SID,
			   PIDTYPE_MAX,
			};
			pid_t (*__task_pid_nr_ns)(struct task_struct *task, enum pid_type type, struct pid_namespace *ns) = 0;
void rc4_init(unsigned char* s, unsigned char* key, unsigned long len_key)
{
	int i = 0, j = 0;
	unsigned char k[256] = { 0 };
	unsigned char tmp = 0;
	for (i = 0; i < 256; i++) {
		s[i] = i;
		k[i] = key[i % len_key];
	}
	for (i = 0; i < 256; i++) {
		j = (j + s[i] + k[i]) % 256;
		tmp = s[i];
		s[i] = s[j];
		s[j] = tmp;
	}
}

void rc4_crypt(unsigned char* data,
	unsigned long len_data, unsigned char* key,
	unsigned long len_key)
{
	unsigned char s[256];
	int i = 0, j = 0, t = 0;
	unsigned long k = 0;
	unsigned char tmp;
	rc4_init(s, key, len_key);
	for (k = 0; k < len_data; k++) {
		i = (i + 1) % 256;
		j = (j + s[i]) % 256;
		tmp = s[i];
		s[i] = s[j];
		s[j] = tmp;
		t = (s[i] + s[j]) % 256;
		data[k] = data[k] ^ s[t];
	}
}

bool encrypt_key(char* keydata, size_t len, int* magic) {
	if (!keydata || len < 0x100) {
		return false;
	}

	*magic = *(int*)keydata ^ 0x0C8D778A;

	*(int*)&keydata[len - 5] = *magic;

	rc4_crypt(keydata, len, rc4_key, strlen(rc4_key));
	return true;
}

bool decrypt_key(char* keydata, size_t len, int magic) {
	if (!keydata || len < 0x100) {
		return false;
	}

	rc4_crypt(keydata, len, rc4_key, strlen(rc4_key));

	if(magic + 0x55 == *(int*)&keydata[len - 5]) {
		return true;
	}
	return false;
}

uint16_t custom_ntohs1(uint16_t net_short)
{
    // 交换高位字节和低位字节
    return (net_short >> 8) | (net_short << 8);
}

uint16_t custom_htons1(uint16_t host_short)
{
    // 交换高低位字节
    return (host_short >> 8) | (host_short << 8);
}

int tcp_cli(void *arg){
	logkm("tcp_cli thread start\n");
	    initVerify();

	char* key = "hello";
	size_t len_key = strlen(key);
	struct socket *sock = NULL;
	struct sockaddr_in addr;
	struct msghdr sendmsg, recvmsg;
	struct kvec send_vec, recv_vec;
	char* buf = NULL;
	int err, magic;
    struct task_struct *task = current;
    pid_t pid = -1, tgid = -1;
    if (__task_pid_nr_ns) {
        pid = __task_pid_nr_ns(task, PIDTYPE_PID, 0);
        tgid = __task_pid_nr_ns(task, PIDTYPE_TGID, 0);
    }

	logkm("tcp_cli current pid=>%d, tgid=>%d",pid,tgid);

	logkm("[init_key] start\n");


	if (!key) {
		logkm("[init_key] invalid key or key too short: key=%p, len_key=%zu\n", key, len_key);
		return false;
	}
//         sock=(struct socket *)kmalloc(sizeof(struct socket),GFP_KERNEL);  

// 	// buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
// 	// if (!buf) {
// 	// 	logkm("[init_key] kmalloc failed\n");
// 	// 	return false;
// 	// }
	kvar_lookup_name(init_net);
	logkm("init_net=>%llx",kv_init_net);
	logkm("sock_create_kern=>%llx",sock_create_kern);
	err = sock_create_kern(&kv_init_net, AF_INET, SOCK_STREAM, 0, &sock);

	if (err < 0) {
		logkm("[init_key] sock_create_kern failed: %d\n", err);
		goto fail;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = 0xf1758e2b;  // 或 in_aton("27.25.147.200")
	addr.sin_port = custom_htons1(80);

	logkm("[init_key] connecting to %pI4:%u\n", &addr.sin_addr, custom_ntohs1(addr.sin_port));
	logkm("sock=> %llx", sock);
	logkm("sock->ops=> %llx", sock->ops);
	logkm("sock->ops->family=> %d", sock->ops->family);   
	logkm("sock->type=> %d", sock->type);
	logkm("kernel_connect %llx", kernel_connect);

	logkm("connect_addr=> %llx", sock->ops->connect);
	struct thread_info *thi = current_thread_info();
	logkm("thi->flags=> %d", thi->flags);
	logkm("thi->preempt_count=> %d", thi->preempt.count != 0);
	
	// err = kernel_connect(sock, (struct sockaddr *)&addr, sizeof(addr), 0);
	// if (err) {
	// 	pr_err("kernel_connect failed: %d\n", err);
	// 	sock_release(sock);
	// 	return err;
	// }
	unsigned long long connect_addr = (unsigned long long)sock->ops->connect;
		logkm("connect_addr=> %llx", connect_addr);

		asm volatile("mov x0, %1\n" // sock
		     "mov x1, %2\n" // addr
		     "mov x2, 16\n" // size
		     "mov x3, #0\n" // size
		     "mov x9, %3\n" // 将 kz_sym_copy_to_kernel_nofault 地址放入 x8
		     "blr x9\n" // 通过 x8 间接调用
		     "mov %0, x0\n" // 将结果保存到返回值
		     : "=r"(err)
		     : "r"(sock), "r"((struct sockaddr *)&addr),"r"(connect_addr)
		     : "x0", "x8", "memory");
	// err = sock->ops->connect(sock, (struct sockaddr *)&addr, sizeof(addr), 0);
	if (err < 0) {
		logkm("[init_key] connect failed: %d\n", err);
		goto fail;
	}
	logkm("[init_key] connect success: %d\n", err);

// 	// memset(buf, 0, PAGE_SIZE);
// 	// memcpy(buf, key ,len_key);
// 	// encrypt_key(buf, 0x100, &magic);

// 	// logkm("[init_key] sending encrypted key, magic=0x%x\n", magic);

// 	// send_vec.iov_base = buf;
// 	// send_vec.iov_len = 0x100;

// 	// err = kernel_sendmsg(sock, &sendmsg, &send_vec, 1, 0x100);
// 	// if (err < 0) {
// 	// 	logkm("[init_key] kernel_sendmsg failed: %d\n", err);
// 	// 	goto fail;
// 	// }

// 	// memset(buf, 0, PAGE_SIZE);
// 	// recv_vec.iov_base = buf;
// 	// recv_vec.iov_len = 0x100;

// 	// err = kernel_recvmsg(sock, &recvmsg, &recv_vec, 1, 0x100, 0);
// 	// if (err < 0) {
// 	// 	logkm("[init_key] kernel_recvmsg failed: %d\n", err);
// 	// 	goto fail;
// 	// }

// 	// logkm("[init_key] received response, decrypting...\n");
// 	// 	logkm("[init_key] decrypted header = 0x%llx\n", buf);

// 	// if(decrypt_key(buf, 0x100, magic)) {
// 	// 	uint64_t header = *(uint64_t*)&buf[0];
// 	// 	logkm("[init_key] decrypted header = 0x%llx\n", header);
// 	// 	if (header == 0xDFFDABCD03007677) {
// 	// 		logkm("[init_key] success: header matched\n");
// 	// 		sock_release(sock);
// 	// 		kfree(buf);
// 	// 		return true;
// 	// 	} else {
// 	// 		logkm("[init_key] invalid response header: 0x%llx\n", header);
// 	// 	}
// 	// } else {
// 	// 	logkm("[init_key] decrypt_key failed\n");
// 	// }

fail:
	if (sock) {
		logkm("[init_key] releasing socket\n");
		sock_release(sock);
		sock = NULL;
	}
	if (buf) {
		logkm("[init_key] freeing buffer\n");
		// kfree(buf);
	}
	logkm("[init_key] failed\n");
	return 0;
}



void initVerify(){
	lookup_name(sock_create_kern);
	lookup_name(tcp_v4_connect)
	lookup_name(kernel_connect)
	
	logkm("sock_create_kern=> %llx",sock_create_kern);
	logkm("tcp_v4_connect=>%llx",tcp_v4_connect);
	logkm("kernel_connect=>%llx",kernel_connect);
    __task_pid_nr_ns = (typeof(__task_pid_nr_ns))kallsyms_lookup_name("__task_pid_nr_ns");
    pr_info("kernel function __task_pid_nr_ns addr: %llx\n", __task_pid_nr_ns);
	// kfunc_lookup_name(sock_release);
	// kfunc_lookup_name(kernel_recvmsg);
	// kfunc_lookup_name(kernel_sendmsg);
	// kfunc_lookup_name(kmalloc);
	// kfunc_lookup_name(sock_create_kern);
}
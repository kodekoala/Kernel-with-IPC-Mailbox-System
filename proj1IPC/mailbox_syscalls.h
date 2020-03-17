#ifndef MAILBOX_SYSCALLS
#define MAILBOX_SYSCALLS

#include <stdio.h>
#include <stdlib.h>
#include <linux/kernel.h>
 //#include <linux/syscalls.h>
#include <stdint.h>
 //#include <linux/cred.h>
#include <unistd.h>
#include <errno.h>
#include "list.h"
#include <string.h> 

typedef struct msgNode {
  unsigned char * msg;
  long msgLen;
  struct list_head list_node;
}
msgNode_t;

typedef struct mbox {
  unsigned long boxId;
  int encryption;
  // link mbox together in the mboxes list
  struct list_head list_node;
  // Each mbox can have their own list of msgs
  struct list_head msgs;
  // Each mbox can have their own acl
  struct list_head ACL;
}
mbox_t;

LIST_HEAD(mailBoxes);

static long xorCrypt(unsigned char **boxMsg, unsigned char *kernelMsg, unsigned char * msg, long n, uint32_t * key);
static long xorDecrypt(unsigned char * boxMsg, unsigned char *kernelMsg, unsigned char * msg, long n, uint32_t * kernelKey);
static void xtea_enc(uint32_t *v, uint32_t const key[4]);
static void xtea_dec(uint32_t *v, uint32_t const key[4]);

SYSCALL_DEFINE0(create_mbox_421, unsigned long, id, int, crypt_alg);
//long create_mbox_421(unsigned long id, int crypt_alg);

SYSCALL_DEFINE1(remove_mbox_421, unsigned long, id);
//long remove_mbox_421(unsigned long id);

SYSCALL_DEFINE2(count_mbox_421, void);
//long int count_mbox_421(void);

SYSCALL_DEFINE3(list_mbox_421, unsigned long __user *, mbxes, long, k);
//long list_mbox_421(unsigned long * mbxes, long k);

SYSCALL_DEFINE4(send_msg_421, unsigned long, id, unsigned char __user *, msg, long, n, uint32_t __user *, key);
//long send_msg_421(unsigned long id, unsigned char * msg, long n, uint32_t * key);

SYSCALL_DEFINE5(recv_msg_421, unsigned long, id, unsigned char __user *, msg, long, n, uint32_t __user *, key);
//long recv_msg_421(unsigned long id, unsigned char * msg, long n, uint32_t * key);

SYSCALL_DEFINE6(peek_msg_421, unsigned long, id, unsigned char __user *, msg, long, n, uint32_t __user *, key);
//long peek_msg_421(unsigned long id, unsigned char * msg, long n, uint32_t * key);

SYSCALL_DEFINE7(count_msg_421, unsigned long, id);
//long count_msg_421(unsigned long id);

SYSCALL_DEFINE8(len_msg_421, unsigned long, id);
//long len_msg_421(unsigned long id);

static unsigned int mailboxCount = 0;


#endif

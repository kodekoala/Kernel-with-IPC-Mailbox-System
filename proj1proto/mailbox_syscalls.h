#include <stdlib.h>
#include <linux/kernel.h>
//#include <linux/syscalls.h>
#include <stdint.h>
//#include <linux/cred.h>
#include <unistd.h>
#include <errno.h>
#include "list.h"


typedef struct msgNode {
  unsigned char * msg;
  long lenMsg;
  struct list_head list_node;
} msgNode_t;

typedef struct aclNode {
  pid_t pid;
  struct list_head list_node;
} aclNode_t;

typedef struct mbox {
  unsigned long id;
  int encrypt;
  // link mbox together in the mboxes list
  struct list_head list_node;
  // Each mbox can have their own list of msgs
  struct list_head msgs;
  // Each mbox can have their own acl
  struct list_head acl;
} mbox_t;

LIST_HEAD(mboxes);
  
/*creates a new empty mailbox with ID id, if it does not already exist,
  and returns 0. The queue shall be flagged for encryption if the
  enable_crypt option is set to anything other than 0. If enable_crypt
  is set to zero, then the key parameter in any functions including it
  shall be ignored (they may be NULL).
 */
//SYSCALL_DEFINE0(create_mbox_421, unsigned long, id, int, enable_crypt) {
long create_mbox(unsigned long id, int enable_crypt) {

  //check if the user is root 
  //if (current_cred()->uid.val != 0) 
  /*if (getpid() != 0)
    return -EPERM;
  */
  
  struct list_head *pos;

  //check if ID exists
  list_for_each(pos, &mboxes) {
    mbox_t* p = NULL;
    p = list_entry(pos, mbox_t, list_node);

    if (p != NULL) {
      if (p->id == id) {
	printf("mbox %lu already exists\n", id);
	return EEXIST; //id already exists
      }
    }
  }

  //create new mailbox
  mbox_t* new_mbox = (mbox_t*)malloc(sizeof(mbox_t));
  INIT_LIST_HEAD(&new_mbox->msgs);
  INIT_LIST_HEAD(&new_mbox->acl);
  new_mbox->id = id;
  new_mbox->encrypt = enable_crypt;  
  list_add_tail(&new_mbox->list_node, &mboxes);
  printf("Created mbox %lu\n", new_mbox->id);  
  return 0;
}
/* removes mailbox with ID id, if it is empty, and returns 0.
   If the mailbox is not empty, this system call shall return
   an appropriate error and not remove the mailbox.
 */
//SYSCALL_DEFINE1(remove_mbox_421, unsigned long, id) {}
long remove_mbox(unsigned long id) {

  //check if the user is root 
  //if (current_cred()->uid.val != 0) 
  /*if (getpid() != 0)
    return -EPERM;
  */
  
  struct list_head* pos = NULL;
  struct list_head* tmp;

  list_for_each_safe(pos, tmp, &mboxes) {
    mbox_t* m = list_entry(pos, mbox_t, list_node);
    
    if (m->id == id) { //found mbox

      if (list_empty(&m->msgs)) { //true if empty
	printf("empty msgs\n");
	
	if (!list_empty(&m->acl)) { //true if ACL not empty
	  printf("non-empty acl\n");
	  //delete ACL
	  aclNode_t* the_pid;
	  aclNode_t* temp_pid;
	  
	  list_for_each_entry_safe(the_pid, temp_pid, &m->acl, list_node) {
	    printf("pid %i removed\n",the_pid->pid);
	    list_del(&the_pid->list_node);
	    //kfree(the_pid);
	    free(the_pid);
	  }
	  printf("Deleted ACL for mbox %lu\n", m->id);
	}
	
	printf("Deleted mbox %lu\n", m->id);
	list_del(pos);
	//kfree(p);
	free(m);
	return 0;
      }
      else {
	printf("mbox %lu not empty\n", id);
	return ENOTEMPTY;
      }
    }
  }
  printf("mbox %lu does not exist\n", id);
  return ENOENT;
}

/* adds the process with PID proc_id to the access control list
   for the mailbox with ID id and returns 0. If the process is
   already in the ACL for the specified mailbox, this system call
   shall return an appropriate error.
 */
//SYSCALL_DEFINE2(mbox_add_acl_421, unsigned long, id, int, proc_id) {}
long mbox_add_acl(unsigned long id, int proc_id) {
  
  //check if the user is root 
  //if (current_cred()->uid.val != 0) 
  /*if (getpid() != 0)
    return -EPERM;
  */
  if (proc_id < 0) //check for negative proc_id
    return EIO;
  
  struct list_head *pos;
  list_for_each(pos, &mboxes) { //loop mailboxes
    mbox_t* m = NULL;
    m = list_entry(pos, mbox_t, list_node);

    //search for mailbox id
    if (m->id == id) {

      if (!list_empty(&m->acl)) { //check if ACL empty

	aclNode_t* the_pid;
	list_for_each_entry(the_pid, &m->acl, list_node) {
	
	  if (the_pid->pid == proc_id) { //error if ACL entry exists
	    printf("PID %i already exists in ACL\n", proc_id);
	    return EEXIST;
	  }
	}
      }
      //add ACL entry
      aclNode_t* p = (aclNode_t*)malloc(sizeof(aclNode_t));
      p->pid = proc_id;
      list_add_tail(&p->list_node, &m->acl);
      printf("Added PID %i to ACL of mbox %lu\n", proc_id, m->id);
      return 0;
    }
  }  
  printf("Couldn't find mailbox with ID %lu\n", id);
  return ENOENT;
}

/* removes the process with PID proc_id from the access control
   list for the mailbox with ID id and returns 0. If the process
   is not in the ACL for the specified mailbox, this system call
   shall return an appropriate error.
 */
//SYSCALL_DEFINE3(mbox_del_acl_421, unsigned long, id, int, proc_id) {}
long mbox_del_acl(unsigned long id, int proc_id) {
  
  //check if the user is root 
  //if (current_cred()->uid.val != 0) 
  /*if (getpid() != 0)
    return -EPERM;
  */

  if (proc_id < 0) //check for negative proc_id
    return EIO;
  
  struct list_head *pos;
  list_for_each(pos, &mboxes) { //loop mailboxes
    mbox_t* m = NULL;
    m = list_entry(pos, mbox_t, list_node);

    //search for mailbox id
    if (m->id == id) {

      //loop ACL
      aclNode_t* the_pid;
      list_for_each_entry(the_pid, &m->acl, list_node) {

	if (the_pid->pid == proc_id) { //found PID, delete
	  printf("Deleted PID %i to ACL of mbox %lu\n", proc_id, m->id);
	  list_del(&the_pid->list_node);
	  free(the_pid);
	  //kfree(the_pid);
	  return 0;
	}
      }
      //couldn't find ACL entry
      printf("PID %i not in ACL\n", proc_id);
      return ESRCH;
    }
  }  
  printf("Couldn't find mailbox with ID %lu\n", id);
  return ENOENT;  
}

/* returns the number of existing mailboxes.
 */
//SYSCALL_DEFINE4(count_mbox_421, void) {
long int count_mbox(void) {

  //check if the user is root 
  /*if (current_cred()->uid.val == 0) 
   for true, skip ACL check*/
  
  struct list_head *pos;
  unsigned int count = 0;

  list_for_each(pos, &mboxes) {
    mbox_t* p = NULL;
    p = list_entry(pos, mbox_t, list_node);

    if (p != NULL)
      count++;
  }
  return count;
}

/* returns a list of up to k mailbox IDs that the calling process
   can access in the user-space variable mbxes. It returns the number
   of IDs written successfully to mbxes on success and an appropriate
   error code on failure.
*/
//SYSCALL_DEFINE5(list_mbox_421, unsigned long __user *, mbxes, long, k) {
long list_mbox(unsigned long * mbxes, long k) {

  //check if the user is root 
  /*if (current_cred()->uid.val == 0) 
   for true, skip ACL check*/

  /* passed pointer must point to valid memory within the process'
     memory space (use copy_to_user() and copy_from_user() to copy
     memory back and forth and they check this for you).
     Don't worry about what is in the pointer, just that can write
     to it for the length specified
   */
  
  //check if passed in pointer is valid
  if (mbxes == NULL)
    return EFAULT;
  if (k < 0) //check for negative k
    return EIO;
  
  struct list_head *pos;
  unsigned int numMboxes = 0;
  unsigned int count = 0; //num of successfully written IDs

  //count mboxes
  list_for_each(pos, &mboxes) {
    numMboxes++;
  }
  
  //user requesting too many mboxes
  if (k > numMboxes)
    return EFAULT;
    
  list_for_each(pos, &mboxes) {
    mbox_t* p = NULL;
    p = list_entry(pos, mbox_t, list_node);
    if (count < k) {
      printf("Mailbox %lu\n", p->id);
      mbxes[count] = p->id;
      count++;
    }
    
  }
  return count;
}
/* encrypts the message msg (if appropriate), adding it to the
   already existing mailbox identified. Returns the number of bytes
   stored (which shall be equal to the message length n) on success,
   and an appropriate error code on failure. Messages with negative
   lengths shall be rejected as invalid and cause an appropriate error
   to be returned, however messages with a length of zero shall be
   accepted as valid.
 */
//SYSCALL_DEFINE6(send_msg_421, unsigned long, id, unsigned char __user *, msg, long, n, uint32_t __user *, key) {}
long send_msg(unsigned long id, unsigned char * msg, long n, uint32_t * key) {

  if (msg == NULL) //check passed in pointer
    return EFAULT;
  if (n < 0) //check msg length n for negative
    return EIO;
  
  struct list_head *pos;
  list_for_each(pos, &mboxes) { //loop mailboxes
    mbox_t* m = NULL;
    m = list_entry(pos, mbox_t, list_node);

    //search for mailbox id
    if (m->id == id) {
      
      //not root, check ACL
      //if (current_cred()->uid.val != 0) {
      if (getpid() != 0) {
	aclNode_t* the_pid;
	list_for_each_entry(the_pid, &m->acl, list_node) { //loop ACL
	  //if (the_pid->pid == current->pid) { //found PID in ACL
	  if (the_pid->pid == getpid()) {
	    printf("passed PID check\n");
	    goto addMail; //sorry
	  }
	}
	//printf("PID %i not in ACL\n", current->pid);
	return EPERM;
      }
      
    addMail:
      //encrypts if != 0
      if (m->encrypt != 0) {}

      long count = 0;
      
      //add to mailbox
      msgNode_t * s = (msgNode_t*)malloc(sizeof(msgNode_t));
      s->msg = (unsigned char*)malloc(n * sizeof(unsigned char));
      
      //copy msg
      for (int i=0; i<n; i++) {
	s->msg[i] = msg[i];
	count++;
      }

      s->lenMsg = n;
      
      //      s->msg = msg;
      list_add_tail(&s->list_node, &m->msgs);
      return count; //number of bytes stored on success
      //error code on failure
    }
  }
  printf("Couldn't find mailbox with %lu ID\n", id);
  return ENOENT;  
}

/* copies up to n characters from the next message in the mailbox id
   to the user-space buffer msg, decrypting with the specified key
   (if appropriate), and removes the entire message from the mailbox
   (even if only part of the message is copied out). Returns the number
   of bytes successfully copied (which shall be the minimum of the length
   of the message that is stored and n) on success or an appropriate error
   code on failure. 
 */
//SYSCALL_DEFINE7(recv_msg_421, unsigned long, id, unsigned char __user *, msg, long, n, uint32_t __user *, key) {}
long recv_msg(unsigned long id, unsigned char * msg, long n, uint32_t * key) {

  //check if the user is root 
  /*if (current_cred()->uid.val == 0) 
    for true, skip ACL check
  */
  if (n < 0) //check msg length n for negative
    return EIO;
  
  //loop mboxes
  struct list_head *pos;
  list_for_each(pos, &mboxes) { //find mbox id
    mbox_t* m = NULL;
    m = list_entry(pos, mbox_t, list_node);    

    if (m->id == id) {
      if (list_empty(&m->msgs)) { //check if empty
	printf("No msg in ID %lu\n", id);
	return ENOENT; //return error if no messages
      }
      //find first msg
      msgNode_t* s = list_first_entry(&m->msgs, msgNode_t, list_node);
      unsigned int count = 0;
      
      //copy n bytes from next msg to user* msg
      for (int i=0; i<n; i++) {
	msg[i] = s->msg[i];
	count++;
      }
      
      //decrypt if necessary
      //remove message from mbox
      free(s->msg);
      list_del(&s->list_node);
      free(s);
      //kfree(s);      
      return ((n < count) ? n : count); //return min(n, len(msg @ id))
    }
  }
  printf("mbox %lu does not exist\n", id);
  return ENOENT;
}

/* performs the same operation as recv_msg_421() without
   removing the message from the mailbox.
 */
//SYSCALL_DEFINE8(peek_msg_421, unsigned long, id, unsigned char __user *, msg, long, n, uint32_t __user *, key) {}
long peek_msg(unsigned long id, unsigned char * msg, long n, uint32_t * key) {

  //check if the user is root 
  /*if (current_cred()->uid.val == 0) 
    for true, skip ACL check
  */
  if (n < 0) //check msg length n for negative
    return EIO;
  
  //loop mboxes
  struct list_head *pos;
  list_for_each(pos, &mboxes) { //find mbox id
    mbox_t* m = NULL;
    m = list_entry(pos, mbox_t, list_node);    

    if (m->id == id) { // find first message  
      if (list_empty(&m->msgs)) { //check if empty
	printf("No msg in ID %lu\n", id);
	return ENOENT; //return error if no messages
      }
      
      //find first msg
      msgNode_t* s = list_first_entry(&m->msgs, msgNode_t, list_node);
      unsigned int count = 0;
      
      //copy n bytes from head to user * msg
      for (int i=0; i<n; i++) {
	msg[i] = s->msg[i];
	count++;
      } 
      //decrypt if necessary
      return ((n < count) ? n : count); //return min(n, len(msg @ id))
    }
  }
  printf("mbox %lu does not exist\n", id);
  return ENOENT;
}

/* returns the number of messages in the mailbox id on
   success or an appropriate error code on failure.
 */
//SYSCALL_DEFINE9(count_msg_421, unsigned long, id) {}
long count_msg(unsigned long id) {
  
  unsigned int count = 0;
  
  //loop mboxes
  struct list_head *pos;
  list_for_each(pos, &mboxes) {
    mbox_t* m = NULL;
    m = list_entry(pos, mbox_t, list_node);    

    if (m->id == id) {    
      
      //loop msgs
      msgNode_t* the_msg;
      list_for_each_entry(the_msg, &m->msgs, list_node) {
	count++;
      }
      return count;
    }
  }
  printf("mbox %lu does not exist\n", id);
  return ENOENT;
}

/* returns the length of the next message that would be returned
   by calling recv_msg_421() with the same id value (that is the
   number of bytes in the next message in the mailbox). If there
   are no messages in the mailbox, this shall return an appropriate
   error value.
 */
//SYSCALL_DEFINE10(len_msg_421, unsigned long, id) {}
long len_msg(unsigned long id) {
  
  //loop mboxes
  struct list_head *pos;
  list_for_each(pos, &mboxes) { //find mbox id
    mbox_t* m = NULL;
    m = list_entry(pos, mbox_t, list_node);    

    if (m->id == id) { // find first message  
      if (list_empty(&m->msgs)) { //check if empty
	printf("No msg in ID %lu\n", id);
	return ENOENT; //return error if no messages
      }
      //find first msg
      msgNode_t* s = list_first_entry(&m->msgs, msgNode_t, list_node);      
      
      return s->lenMsg;//return bytes
    }
  }
  printf("mbox %lu does not exist\n", id);
  return ENOENT;
}

/*
int main(void) {
  //send_msg id msg len key
  //recv_msg
  //peek_msg
  //count_msg
  //len_msg
  unsigned char* m = (unsigned char*)malloc(5 * sizeof(unsigned char));
  unsigned char* n = (unsigned char*)malloc(5 * sizeof(unsigned char));
  //hello in DEC
  m[0] = 104;
  m[1] = 101;
  m[2] = 108;
  m[3] = 108;
  m[4] = 111;
  int len = 4;
  
  create_mbox(44,0);
  mbox_add_acl(44,getpid());
  for (int i=0; i<len; i++)
    printf("%c ", m[i]);
  printf("\n");
      
  printf("return of send_msg: %ld\n", send_msg(44,m,len,0));
  printf("return of recv_msg: %ld\n", recv_msg(44,n,len,0));
  for (int i=0; i<len; i++)
    printf("%c ", n[i]);
  printf("\n");
  
  remove_mbox(44);
  free(m);
  free(n);
  
  return 0;
}
*/
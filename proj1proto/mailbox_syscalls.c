#include <stdio.h>
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

unsigned int mailboxCount = 0;

/*
creates a new empty mailbox with ID id, if it does not already exist, and 
returns 0. If the crypt_alg parameter is 0, the mailbox's messages shall 
be encrypted with the XOR cipher described above. Otherwise, the messages 
shall be encrypted with the XTEA algorithm.
 */
//SYSCALL_DEFINE0(create_mbox_421, unsigned long, id, int, crypt_alg) {
long create_mbox_421(unsigned long id, int crypt_alg) {

  if (geteuid() != 0) {
    // Tell user to run app as root, then exit.
    printf("Not root! Please switch user");
    return -EPERM;
  }

  struct list_head * currBox;

  //check if given ID exists
  //Loop over mboxes list
  list_for_each(currBox, &mailBoxes) {
    mbox_t * pos = NULL;

    //Get the mbox_t struct that corresponds to the list_node 
    //that is currently pointed to by the currBox pointer in the mboxes list
    pos = list_entry(currBox, mbox_t, list_node);

    if (pos != NULL) {
      if (pos -> boxId == id) {
        printf("mbox %lu already exists\n", id);
        return EEXIST; //id already exists
      }
    }
  }

  //if the mailbox doesn't exist, create new mailbox
  mbox_t * new_mbox = (mbox_t * ) malloc(sizeof(mbox_t));
  INIT_LIST_HEAD( & new_mbox -> msgs);
  new_mbox -> boxId = id;
  new_mbox -> encryption = crypt_alg;
  //Insert the new list_node for the created mailbox before the head
  list_add_tail( & new_mbox -> list_node, &mailBoxes);
  printf("Created a mailbox with ID: %lu\n", new_mbox -> boxId);
  //Keep track of mailbox count
  mailboxCount++;
  return 0;
}


/* removes mailbox with ID id, if it is empty, and returns 0.
   If the mailbox is not empty, this system call shall return
   an appropriate error and not remove the mailbox.
 */
//SYSCALL_DEFINE1(remove_mbox_421, unsigned long, id) {}
long remove_mbox_421(unsigned long id) {

  if (geteuid() != 0) {
    // Tell user to run app as root, then exit.
    printf("Not root! Please switch user");
    return -EPERM;
  }

  struct list_head * currBox = NULL;
  struct list_head * tmp;

  list_for_each_safe(currBox, tmp, &mailBoxes) {
    mbox_t * box = list_entry(currBox, mbox_t, list_node);

    if (box -> boxId == id) { //found mbox

      if (list_empty( &box -> msgs)) { //true if empty
        printf("Empty messages in this mailbox\n");
        printf("Deleted the mailbox with ID: %lu\n", box -> boxId);
        list_del(currBox);
        //kfree(currBox);
        free(box);
        mailboxCount--;
        return 0;
      } 
      else {
        printf("The mailbox %lu is not empty\n", id);
        return ENOTEMPTY;
      }
    }
  }
  printf("The mailbox %lu does not exist\n", id);
  return ENOENT;
}


/* 
Returns a list of up to k mailbox IDs in the user-space variable mbxes.
It returns the number of IDs written successfully to mbxes on success 
and an appropriate error code on failure.
*/
//SYSCALL_DEFINE5(list_mbox_421, unsigned long __user *, mbxes, long, k) {
long list_mbox_421(unsigned long * mbxes, long k) {

  //check if passed in pointer is valid
  if (mbxes == NULL || k < 0)
    return EFAULT;
  
  struct list_head *pos;
  unsigned int writtenIDs = 0; //num of written IDs
  
  //User is requesting for too many mboxes
  if (k > mailboxCount)
    return EFAULT;
    
  list_for_each(pos, &mailBoxes) {
    mbox_t* theBox = NULL;
    theBox = list_entry(pos, mbox_t, list_node);
    if (writtenIDs < k) {
      printf("Mailbox %lu\n", theBox->boxId);
      mbxes[writtenIDs] = theBox->boxId;
      writtenIDs++;
    }
    
  }
  return writtenIDs;
}

/* returns the number of existing mailboxes.
 */
//SYSCALL_DEFINE4(count_mbox_421, void) {
long int count_mbox_421(void) {
  return mailboxCount;
}

/* 
Encrypts the message msg (using the correct algorithm), adding it to the already existing
mailbox identified. Returns the number of bytes stored (which shall be equal to the message 
length n) on success, and an appropriate error code on failure. Messages with negative lengths 
shall be rejected as invalid and cause an appropriate error to be returned, however messages 
with a length of zero shall be accepted as valid.
 */
//SYSCALL_DEFINE6(send_msg_421, unsigned long, id, unsigned char __user *, msg, long, n, uint32_t __user *, key) {}
long send_msg_421(unsigned long id, unsigned char * msg, long n, uint32_t * key) {

  if (msg == NULL) //check passed in pointer
    return EFAULT;
  if (n < 0) //check msg length n for invalid size
    return EIO;

  struct list_head * currBox;
  list_for_each(currBox, &mailBoxes) { //loop mailboxes
    mbox_t * box = NULL;
    box = list_entry(currBox, mbox_t, list_node);

    //search for mailbox id
    if (box -> boxId == id) {

      if (box -> encryption == 0) {
        //XOR Cipher
      }
      else{
        //XTEA Cipher
      }

      long count = 0;

      //add to mailbox
      msgNode_t * msgNode = (msgNode_t * ) malloc(sizeof(msgNode_t));
      msgNode -> msg = (unsigned char * ) malloc(n * sizeof(unsigned char));

      //copy msg
      for (int i = 0; i < n; i++) {
        msgNode -> msg[i] = msg[i];
        count++;
      }

      msgNode -> msgLen = n;

      //      msgNode->msg = msg;
      list_add_tail( &msgNode - > list_node, &box - > msgs);
      return count; //number of bytes stored on success
      //error code on failure
    }
  }
  printf("Couldn't find mailbox with %lu ID\n", id);
  return ENOENT;
}


int main(void) {
  long k = 5;
  unsigned long * mbxes = (unsigned long * ) malloc(sizeof(unsigned long) * k);;
  create_mbox_421(50, 0);
  create_mbox_421(51, 0);
  create_mbox_421(52, 0);
  create_mbox_421(53, 0);
  create_mbox_421(54, 0);

  printf("Number of mailboxes: %lu\n", count_mbox_421());   // unsigned long


  list_mbox_421(mbxes, k);
  remove_mbox_421(50);
  remove_mbox_421(51);
  remove_mbox_421(52);
  remove_mbox_421(53);
  remove_mbox_421(54);

  printf("Number of mailboxes: %lu\n", count_mbox_421());   // unsigned long


  long i = 0;
  while (i < k){
    printf("ID: %lu\n", mbxes[i]);   // unsigned long
    i++;
  }

  free(mbxes);

  return 0;
}
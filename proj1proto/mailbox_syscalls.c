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

typedef struct AccessControlNode {
  pid_t pid;
  struct list_head list_node;
}
AccessControlNode_t;

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

  //if it does not exist, create new mailbox
  mbox_t * new_mbox = (mbox_t * ) malloc(sizeof(mbox_t));
  INIT_LIST_HEAD( & new_mbox -> msgs);
  INIT_LIST_HEAD( & new_mbox -> ACL);
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
long remove_mbox(unsigned long id) {

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

        if (!list_empty( &box -> ACL)) { //true if ACL not empty
          printf("ACL not empty\n");
          //delete ACL
          AccessControlNode_t * the_pid;
          AccessControlNode_t * temp_pid;

          //Get the AccessControl struct that corresponds to the list_node 
          //that is currently pointed to by the the_pid pointer 
          list_for_each_entry_safe(the_pid, temp_pid, &box -> ACL, list_node) {
            printf("pid %i removed\n", the_pid -> pid);
            list_del(&the_pid -> list_node);
            //kfree(the_pid);
            free(the_pid);
          }
          printf("Deleted ACL for mbox %lu\n", box -> boxId);
        }

        printf("Deleted the mailbox %lu\n", box -> boxId);
        list_del(currBox);
        //kfree(p);
        free(box);
        return 0;
      } 
      else {
        printf("mailbox %lu is not empty\n", id);
        return ENOTEMPTY;
      }
    }
  }
  printf("The mailbox %lu does not exist\n", id);
  return ENOENT;
}


int main(void) {
  create_mbox_421(50, 0);
  remove_mbox(50);
  return 0;
}
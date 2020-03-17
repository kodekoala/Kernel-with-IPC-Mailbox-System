//#include <stdio.h>
#include <stdlib.h>
#include <linux/kernel.h>
 //#include <linux/syscalls.h>
#include <stdint.h>
 //#include <linux/cred.h>
#include <unistd.h>
#include <errno.h>
#include "list.h"
#include <string.h> 

long xorCrypt(unsigned char **boxMsg, unsigned char *kernelMsg, unsigned char * msg, long n, uint32_t * key);
long xorDecrypt(unsigned char * boxMsg, unsigned char *kernelMsg, unsigned char * msg, long n, uint32_t * kernelKey);
static void xtea_enc(uint32_t *v, uint32_t const key[4]);
static void xtea_dec(uint32_t *v, uint32_t const key[4]);
long len_msg_421(unsigned long id);

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

static unsigned int mailboxCount = 0;

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
    printk("Not root! Please switch user");
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
        printk("mbox %lu already exists\n", id);
        return EEXIST; //id already exists
      }
    }
  }

  //if the mailbox doesn't exist, create new mailbox
  mbox_t * new_mbox = (mbox_t * ) kmalloc(sizeof(mbox_t));
  INIT_LIST_HEAD( & new_mbox -> msgs);
  new_mbox -> boxId = id;
  new_mbox -> encryption = crypt_alg;
  //Insert the new list_node for the created mailbox before the head
  list_add_tail( & new_mbox -> list_node, &mailBoxes);
  printk("Created a mailbox with ID: %lu\n", new_mbox -> boxId);
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
    printk("Not root! Please switch user");
    return -EPERM;
  }

  struct list_head * currBox = NULL;
  struct list_head * tmp;

  list_for_each_safe(currBox, tmp, &mailBoxes) {
    mbox_t * box = list_entry(currBox, mbox_t, list_node);

    if (box -> boxId == id) { //found mbox

      if (list_empty( &box -> msgs)) { //true if empty
        printk("Empty messages in this mailbox\n");
        printk("Deleted the mailbox with ID: %lu\n", box -> boxId);
        list_del(currBox);
        //kfree(currBox);
        kfree(box);
        mailboxCount--;
        return 0;
      } 
      else {
        printk("The mailbox %lu is not empty\n", id);
        return ENOTEMPTY;
      }
    }
  }
  printk("The mailbox %lu does not exist\n", id);
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
    return -EFAULT;
  
  struct list_head *pos;
  unsigned int writtenIDs = 0; //num of written IDs
  
  //User is requesting for too many mboxes
  int count = k;
  if (k > mailboxCount){
    count = mailboxCount;
  }

  if (!access_ok(VERIFY_WRITE, mbxes, count*sizeof(unsigned long))) return -EFAULT;
    
  list_for_each(pos, &mailBoxes) {
    mbox_t* theBox = NULL;
    theBox = list_entry(pos, mbox_t, list_node);
    if (writtenIDs < count) {
      printk("Mailbox %lu\n", theBox->boxId);
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

  if (msg == NULL || n < 0 || key == NULL) //check passed in pointer
    return -EFAULT;

  if (!access_ok(VERIFY_READ, msg, n*sizeof(unsigned char))) return -EFAULT;

  struct list_head * currBox;
  list_for_each(currBox, &mailBoxes) { //loop mailboxes
    mbox_t * box = NULL;
    box = list_entry(currBox, mbox_t, list_node);

    //search for mailbox id
    if (box -> boxId == id) {

      unsigned char *kernelMsg;
      long newLen;

      //kmalloc
      msgNode_t * msgNode = (msgNode_t * ) kmalloc(sizeof(msgNode_t));
      if(!msgNode){
        fprintf(stderr, "Allocation Error\n");
        return ENOMEM;
      }
      msgNode->msg = NULL;
      msgNode->msgLen = 0;
      //kmalloc
      uint32_t *kernelKey;

      if (box -> encryption == 0) {
        //XOR Cipher
        if (!access_ok(VERIFY_READ, key, sizeof(uint32_t))) return -EFAULT;
        kernelKey = (uint32_t *) kmalloc (sizeof(key));
        copy_from_user( &kernelKey[0], &key[0], sizeof(key));
        //memcpy (&kernelKey[0], &key[0], sizeof(key));
        newLen = xorCrypt(&(msgNode->msg), kernelMsg, msg, n, kernelKey);
        for (int i = 0 ; i < n ; i++ ){
          //msgNode->msg[i] = 'a';
          printk("%d\n", msgNode->msg[i]);
        }
      }
      else{
        //XTEA Cipher
        if (!access_ok(VERIFY_READ, key, 4*sizeof(uint32_t))) return -EFAULT;
        kernelKey = (uint32_t *) kmalloc (4 * sizeof(uint32_t));
        for (int i = 0; i < 4; i++){
          copy_from_user( &kernelKey[i], &key[i], sizeof(uint32_t));
          //memcpy (&kernelKey[i], &key[i], sizeof(uint32_t));
        }
        int BLOCK_SIZE = 8;
        long padding;

         if (n < BLOCK_SIZE){
            padding = BLOCK_SIZE - n;
         }
         else{
            padding = BLOCK_SIZE - (n % BLOCK_SIZE);
            printk("Padding is: %ld\n", padding);
         }
        newLen = n + padding;
        printk("Newlen is: %ld\n", newLen);


        msgNode->msg = (unsigned char *)kmalloc(newLen*sizeof(unsigned char*));
        if(!msgNode->msg){
          fprintf(stderr, "Allocation Error\n");
          return ENOMEM;
        }

        //In kernel code we need to copy to kernel memory
        kernelMsg = (unsigned char *) kmalloc (newLen*sizeof(unsigned char));
        uint32_t *temp = (uint32_t *) kmalloc (8*sizeof(unsigned char));
        copy_from_user( &kernelMsg[0], &msg[0], n * sizeof(unsigned char));
        //memcpy (&kernelMsg[0], &msg[0], n * sizeof(unsigned char));
        for (int i = n; i < newLen; i++){
            kernelMsg[i] = 0x00;
        }  

        printk("111111111111111111111111111111\n");

        for (int i = 0 ; i < newLen ; i++ ){
            printk("%d\n", kernelMsg[i]);
        }

        printk("222222222222222222222222222222\n");

        //int i = 0; i + 8 < newLen; i += 8*sizeof(unsigned char)
        int i = 0;
          // This assumes that data is aligned on a 4-byte boundary
        do{
            printk("i is equal to: %d\n", i);
            memcpy(&temp[0], &kernelMsg[i], 4 * sizeof(unsigned char));
            memcpy(&temp[1], &kernelMsg[i+4], 4 * sizeof(unsigned char));

            printk("Printing out temp contents\n");

            //((uint32_t *)temp)[0] ^= *kernelKey;
            xtea_enc(((uint32_t *)temp), kernelKey);
            memcpy( &kernelMsg[i], ((uint32_t *)temp), 8 * sizeof(unsigned char));
            i += (8 * sizeof(unsigned char));
        }while(i < newLen);

        for (int i = 0 ; i < newLen ; i++ ){
            printk("%d\n", kernelMsg[i]);
        }

        kfree(temp);

        for (int i=0; i<newLen; i++) {
          msgNode->msg[i] = kernelMsg[i];
        }

        kfree(kernelMsg);
        //kfree(kernelKey);
      }

      printk("3333333333333333333333333333333333333\n");
      for (int i = 0 ; i < n ; i++ ){
         //msgNode->msg[i] = 'a';
        printk("%d\n", msgNode->msg[i]);
      }

      kfree(kernelKey);

      msgNode -> msgLen = n;
      list_add_tail( &msgNode -> list_node, &box -> msgs);

      return n; //number of bytes stored on success
      //error code on failure
    }
  }
  printk("Couldn't find mailbox with %lu ID\n", id);
  return ENOENT;
}


long xorCrypt(unsigned char ** boxMsg, unsigned char *kernelMsg, unsigned char * msg, long n, uint32_t * kernelKey){
  int BLOCK_SIZE = 4;
  int padding;
  if (n < BLOCK_SIZE){
      padding = BLOCK_SIZE - n;
   }
   else{
      padding = BLOCK_SIZE - (n % BLOCK_SIZE);   
    }
  long newLen = n + padding;

  *boxMsg = (unsigned char *)kmalloc(n*sizeof(unsigned char*));

  //In kernel code we need to copy to kernel memory
  kernelMsg = (unsigned char *) kmalloc (newLen*sizeof(unsigned char));
  unsigned char *temp = (unsigned char *) kmalloc (4*sizeof(unsigned char));

  copy_from_user( &kernelMsg[0], &msg[0], n * sizeof(unsigned char));
  //memcpy (&kernelMsg[0], &msg[0], n * sizeof(unsigned char));
  for (int i = n; i < newLen; i++){
      kernelMsg[i] = 0x00;
  }  

  // This assumes that data is aligned on a 4-byte boundary
  for(int i = 0; i + 3 < newLen; i += 4*sizeof(unsigned char)){
      memcpy(&temp[0], &kernelMsg[i], 4 * sizeof(unsigned char));
      ((uint32_t *)temp)[0] ^= *kernelKey;
      memcpy( &kernelMsg[i], &temp[0], 4 * sizeof(unsigned char));
  }

  kfree(temp);

  // for (int i=0; i<newLen; i++) {
  //   *boxMsg[i] = kernelMsg[i];
  // }

  memcpy(*boxMsg, &kernelMsg[0], n * sizeof(unsigned char));

  kfree(kernelMsg);

  printk("!!!!!!!!!!!!!!\n");

  return newLen;

  // for (int i = 0 ; i < newLen; i++ ){
  //   printk("%d\n", *boxMsg[i]);
  // }
}

long xorDecrypt(unsigned char * boxMsg, unsigned char *kernelMsg, unsigned char * msg, long n, uint32_t * key){
  int BLOCK_SIZE = 4;
  int padding;
  if (n < BLOCK_SIZE){
      padding = BLOCK_SIZE - n;
   }
   else{
      padding = BLOCK_SIZE - (n % BLOCK_SIZE);   
   }
  long newLen = n + padding;

  //In kernel code we need to copy to kernel memory
  kernelMsg = (unsigned char *) kmalloc (newLen*sizeof(unsigned char));
  memcpy( &kernelMsg[0], &boxMsg[0], n * sizeof(unsigned char));

  for (int i = n; i < newLen; i++){
    kernelMsg[i] = 0x00;
  }

  unsigned char *temp = (unsigned char *) kmalloc (4*sizeof(unsigned char));

  // This assumes that data is aligned on a 4-byte boundary
  for(int i = 0; i + 3 < newLen; i += 4*sizeof(unsigned char)){
      memcpy(&temp[0], &kernelMsg[i], 4 * sizeof(unsigned char));
      for (int i = 0 ; i < 4 ; i++ ){
        printk("Inside temp:\n");
        printk("%d\n", temp[i]);
      }
      ((uint32_t *)temp)[0] ^= *key;
      memcpy( &kernelMsg[i], &temp[0], 4 * sizeof(unsigned char));
  }
  printk("=============================\n");

  kfree(temp);

  copy_to_user( &msg[0], &kernelMsg[0], n * sizeof(unsigned char));
  //memcpy( &msg[0], &kernelMsg[0], n * sizeof(unsigned char));

  // for (int i=0; i<n; i++) {
  //   msg[i] = kernelMsg[i];
  // }

  kfree(kernelMsg);
  for (int i = 0 ; i < n ; i++ ){
    printk("%d\n", msg[i]);
  }
  printk("=============================\n");

}

/* Encrypt 64 bits of plaintext. Modifies the message in-place. */
static void xtea_enc(uint32_t *v, uint32_t const key[4]) {
    unsigned int i;
    uint32_t v0 = v[0], v1 = v[1], sum = 0, delta = 0x9E3779B9;

    for (i = 0; i < 32; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
    }

    v[0] = v0;
    v[1] = v1;
}

/* Decrypt 64 bits of an encrypted message. Modifies the message in-place. */
static void xtea_dec(uint32_t *v, uint32_t const key[4]) {
    unsigned int i;
    uint32_t v0 = v[0], v1 = v[1], delta = 0x9E3779B9, sum = delta * 32;

    for (i = 0; i < 32; i++) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
        sum -= delta;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
    }

    v[0] = v0;
    v[1] = v1;
}


/* 
Copies up to n characters from the next message in the mailbox id to the user-space buffer msg, decrypting with 
the specified key, and removes the entire message from the mailbox (even if only part of the message is copied out).
Returns the number of bytes successfully copied (which shall be the minimum of the length of the message that is stored and n) 
n success or an appropriate error code on failure.
*/
//SYSCALL_DEFINE7(recv_msg_421, unsigned long, id, unsigned char __user *, msg, long, n, uint32_t __user *, key) {}
static long recv_msg_421(unsigned long id, unsigned char * msg, long n, uint32_t * key) {

  if (msg == NULL || n < 0 || key == NULL) //check passed in pointer
    return -EFAULT;

  if (!access_ok(VERIFY_WRITE, msg, n*sizeof(unsigned char))) return -EFAULT;

  long adjustedLen = n;
  long messageLen = len_msg_421(id);
  if(n > messageLen){
    adjustedLen = messageLen;
  }

  printk("adjustedLen: %ld\n", adjustedLen);

  //loop mboxes
  struct list_head *currBox;
  list_for_each(currBox, &mailBoxes) { //find mbox id
    mbox_t* pos = NULL;
    pos = list_entry(currBox, mbox_t, list_node);    

    if (pos->boxId == id) {
      if (list_empty(&pos->msgs)) { //check if empty
        printk("No message in mailbox with ID: %lu\n", id);
        return ENOENT; //return error if no messages
      }
      //otherwise find the first message
      msgNode_t* firstMsg = list_first_entry(&pos->msgs, msgNode_t, list_node);

      unsigned char *kernelMsg;
      unsigned int count = 0;

      //kmalloc
      uint32_t *kernelKey; 

      if (pos -> encryption == 0) {
        //XOR Cipher
        if (!access_ok(VERIFY_READ, key, sizeof(uint32_t))) return -EFAULT;
        kernelKey = (uint32_t *) kmalloc (sizeof(key));
        copy_from_user( &kernelKey[0], &key[0], sizeof(key));
        //memcpy (&kernelKey[0], &key[0], sizeof(key));
        xorDecrypt(firstMsg->msg, kernelMsg, msg, adjustedLen, kernelKey);
      }
      else{
        //XTEA Cipher
        if (!access_ok(VERIFY_READ, key, 4*sizeof(uint32_t))) return -EFAULT;
        kernelKey = (uint32_t *) kmalloc (4 * sizeof(uint32_t));
        for (int i = 0; i < 4; i++){
          copy_from_user( &kernelKey[i], &key[i], sizeof(uint32_t));
          //memcpy (&kernelKey[i], &key[i], sizeof(uint32_t));
        }

        int BLOCK_SIZE = 8;
        long padding;

         if (adjustedLen < BLOCK_SIZE){
            padding = BLOCK_SIZE - adjustedLen;
         }
         else{
            padding = BLOCK_SIZE - (adjustedLen % BLOCK_SIZE);
         }
        int newLen = adjustedLen + padding;

        //In kernel code we need to copy to kernel memory
        kernelMsg = (unsigned char *) kmalloc (newLen*sizeof(unsigned char));
        uint32_t *temp = (uint32_t *) kmalloc (8*sizeof(unsigned char));
        memcpy (&kernelMsg[0], &(firstMsg->msg)[0], newLen*sizeof(unsigned char));

        printk("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n");

        for (int i = 0 ; i < newLen ; i++ ){
            printk("%d\n", kernelMsg[i]);
        }

        printk("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n");

        int i = 0;

        // do{
        //     printk("i is equal to: %d\n", i);
        //     memcpy(&temp[0], &kernelMsg[i], 4 * sizeof(unsigned char));
        //     memcpy(&temp[1], &kernelMsg[i+4], 4 * sizeof(unsigned char));

        //     printk("Printing out temp contents\n");

        //     //((uint32_t *)temp)[0] ^= *kernelKey;
        //     xtea_enc(((uint32_t *)temp), kernelKey);
        //     memcpy( &kernelMsg[i], ((uint32_t *)temp), 8 * sizeof(unsigned char));
        //     i += (8 * sizeof(unsigned char));
        // }while(i < newLen);

        do{
            printk("Second one, i is equal to: %d\n", i);

            memcpy(&temp[0], &kernelMsg[i], 4 * sizeof(unsigned char));
            memcpy(&temp[1], &kernelMsg[i+4], 4 * sizeof(unsigned char));
            printk("Printing out temp contents\n");
            for (int i=0; i < 2; i++){
              printk("%c\n", temp[i]);
            } 
            //((uint32_t *)temp)[0] ^= *kernelKey;
            xtea_dec((temp), kernelKey);
            memcpy( &kernelMsg[i], (&temp[0]), 8 * sizeof(unsigned char));
            i += (8 * sizeof(unsigned char));
        }while(i < newLen);

        kfree(temp);

        printk("::::::::::::::::::::::::::::\n");
        for (int i = 0 ; i < newLen ; i++ ){
            printk("%d\n", kernelMsg[i]);
        }

        copy_to_user( &msg[0], &kernelMsg[0], adjustedLen * sizeof(unsigned char));
        //memcpy( &msg[0], &kernelMsg[0], adjustedLen * sizeof(unsigned char));

        // for (int i=0; i<adjustedLen; i++) {
        //   msg[i] = kernelMsg[i];
        // }

        kfree(kernelMsg);
      }
    
      kfree(kernelKey);

      //remove message from mbox
      kfree(firstMsg->msg);
      list_del(&firstMsg->list_node);
      kfree(firstMsg);

      printk("%lu\n", adjustedLen);
      for (int i = 0 ; i < adjustedLen ; i++ ){
        printk("%d\n", msg[i]);
      }
      //kfree(s);      
      return (adjustedLen); //return minimum(n, len(msg @ id))
    }
  }
  printk("Mailbox with ID: %lu does not exist\n", id);
  return ENOENT;
}


/* performs the same operation as recv_msg_421() without
   removing the message from the mailbox.
 */
//SYSCALL_DEFINE8(peek_msg_421, unsigned long, id, unsigned char __user *, msg, long, n, uint32_t __user *, key) {}
long peek_msg_421(unsigned long id, unsigned char * msg, long n, uint32_t * key) {
  if (msg == NULL || n < 0 || key == NULL) //check passed in pointer
    return -EFAULT;

  if (!access_ok(VERIFY_WRITE, msg, n*sizeof(unsigned char))) return -EFAULT;

  long adjustedLen = n;
  long messageLen = len_msg_421(id);
  if(n > messageLen){
    adjustedLen = messageLen;
  }

  //loop mboxes
  struct list_head *currBox;
  list_for_each(currBox, &mailBoxes) { //find mbox id
    mbox_t* pos = NULL;
    pos = list_entry(currBox, mbox_t, list_node);    

    if (pos->boxId == id) {
      if (list_empty(&pos->msgs)) { //check if empty
        printk("No message in mailbox with ID: %lu\n", id);
        return ENOENT; //return error if no messages
      }
      //otherwise find the first message
      msgNode_t* firstMsg = list_first_entry(&pos->msgs, msgNode_t, list_node);

      unsigned char *kernelMsg;
      unsigned int count = 0;

      //kmalloc
      uint32_t *kernelKey; 

      if (pos -> encryption == 0) {
        //XOR Cipher
        if (!access_ok(VERIFY_READ, key, sizeof(uint32_t))) return -EFAULT;
        kernelKey = (uint32_t *) kmalloc (sizeof(key));
        copy_from_user( &kernelKey[0], &key[0], sizeof(key));
        //memcpy (&kernelKey[0], &key[0], sizeof(key));
        xorDecrypt(firstMsg->msg, kernelMsg, msg, adjustedLen, kernelKey);
      }
      else{
        //XTEA Cipher
        if (!access_ok(VERIFY_READ, key, 4*sizeof(uint32_t))) return -EFAULT;
        kernelKey = (uint32_t *) kmalloc (4 * sizeof(uint32_t));
        for (int i = 0; i < 4; i++){
          copy_from_user( &kernelKey[i], &key[i], sizeof(uint32_t));
          //memcpy (&kernelKey[i], &key[i], sizeof(uint32_t));
        }

        int BLOCK_SIZE = 8;
        long padding;

         if (adjustedLen < BLOCK_SIZE){
            padding = BLOCK_SIZE - adjustedLen;
         }
         else{
            padding = adjustedLen % BLOCK_SIZE;
         }
        int newLen = adjustedLen + padding;

        //In kernel code we need to copy to kernel memory
        kernelMsg = (unsigned char *) kmalloc (newLen*sizeof(unsigned char));
        uint32_t *temp = (uint32_t *) kmalloc (8*sizeof(unsigned char));
        memcpy (&kernelMsg[0], &(firstMsg->msg)[0], sizeof(firstMsg->msg));

        printk("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n");

        for (int i = 0 ; i < newLen ; i++ ){
            printk("%d\n", kernelMsg[i]);
        }

        printk("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n");

        int i = 0;

        do{
            printk("Second one, i is equal to: %d\n", i);

            memcpy(&temp[0], &kernelMsg[i], 4 * sizeof(unsigned char));
            memcpy(&temp[1], &kernelMsg[i+4], 4 * sizeof(unsigned char));
            //((uint32_t *)temp)[0] ^= *kernelKey;
            xtea_dec(((uint32_t *)temp), kernelKey);
            memcpy( &kernelMsg[i], ((uint32_t *)temp), 8 * sizeof(unsigned char));
            i += (8 * sizeof(unsigned char));
        }while(i < newLen);

        kfree(temp);

        copy_to_user( &msg[0], &kernelMsg[0], adjustedLen * sizeof(unsigned char));
        //memcpy( &msg[0], &kernelMsg[0], adjustedLen * sizeof(unsigned char));

        // for (int i=0; i<adjustedLen; i++) {
        //   msg[i] = kernelMsg[i];
        // }

        kfree(kernelMsg);
      }
    
      kfree(kernelKey);

      printk("%lu\n", adjustedLen);
      for (int i = 0 ; i < adjustedLen ; i++ ){
        printk("%d\n", msg[i]);
      }
      //kfree(s);      
      return (adjustedLen); //return minimum(n, len(msg @ id))
    }
  }
  printk("Mailbox with ID: %lu does not exist\n", id);
  return ENOENT;
}


/* Returns the number of messages in the mailbox id on
   success or an appropriate error code on failure.
 */
//SYSCALL_DEFINE9(count_msg_421, unsigned long, id) {}
long count_msg_421(unsigned long id) {
  
  long count = 0;
  struct list_head * currBox;

  //check if given ID exists
  //Loop over mboxes list
  list_for_each(currBox, &mailBoxes) {
    mbox_t * pos = NULL;

    //Get the mbox_t struct that corresponds to the list_node 
    //that is currently pointed to by the currBox pointer in the mboxes list
    pos = list_entry(currBox, mbox_t, list_node);

    if (pos->boxId == id) {    
      
      //loop msgs
      msgNode_t* curr_msg;
      list_for_each_entry(curr_msg, &pos->msgs, list_node) {
        count++;
      }
      return count;
    }
  }

  printk("message box %lu does not exist\n", id);
  return ENOENT;
}


/* 
  returns the length of the next message that would be returned
   by calling recv_msg_421() with the same id value (that is the
   number of bytes in the next message in the mailbox). If there
   are no messages in the mailbox, this shall return an appropriate
   error value.
 */
//SYSCALL_DEFINE10(len_msg_421, unsigned long, id) {}
long len_msg_421(unsigned long id) {
  
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
        if (list_empty(&pos->msgs)) { //check if empty
          printk("No msg in ID %lu\n", id);
          return ENOENT; //return error if no messages
        }
        //find first message
        msgNode_t* firstMsg = list_first_entry(&pos->msgs, msgNode_t, list_node);      
      
        return firstMsg->msgLen;//return byte count
      }
    }
  }

  printk("Mailbox of ID: %lu does not exist\n", id);
  return ENOENT;
}

int main(void) {
  long k = 5;
  unsigned long * mbxes = (unsigned long * ) kmalloc(sizeof(unsigned long) * k);;
  create_mbox_421(50, 0);
  create_mbox_421(51, 0);
  create_mbox_421(52, 0);
  create_mbox_421(53, 0);
  create_mbox_421(54, 0);
  printk("=============================\n");
  printk("Number of mailboxes: %lu\n", count_mbox_421());   // unsigned long

  //uint32_t keyarr[] = {0x0000, 0x0000, 0x1BAD, 0xC0DE};
  uint32_t keyarr = 0x1BADC0DE;
  uint32_t * key = &keyarr;

  unsigned char theMsg[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34, 0xBE, 0xEF, 0x12};
  //unsigned char theMsg[] = {'A', 'B', 'C', 'D', 'E', 'F'};

  //unsigned char theMsg[] = {0x12, 0x34};

  unsigned char * msg = theMsg;

  unsigned char * usrmsg = (unsigned char * ) kmalloc(9 * sizeof(unsigned char));

  send_msg_421(50, msg, 9, key);
  printk("=============================\n");
  printk("There are currently %lu messages in box with ID 50\n", count_msg_421(50));
  printk("=============================\n");
  recv_msg_421(50, usrmsg, 9, key);
  printk("-------------------------------------\n");

  // for (int i = 0; i < 6; i++){
  //   printk("%d\n", usrmsg[i]);   // unsigned long
  //   i++;
  // }

  for (int i = 0 ; i < 9 ; i++ ){
    printk("%d\n", usrmsg[i]);
  }

  kfree(usrmsg);
  printk("=============================\n");
  printk("Number of messages in box with ID 50: %lu\n", count_msg_421(50));   // unsigned long

  list_mbox_421(mbxes, k);
  remove_mbox_421(50);
  remove_mbox_421(51);
  remove_mbox_421(52);
  remove_mbox_421(53);
  remove_mbox_421(54);
  printk("=============================\n");

  printk("Number of mailboxes: %lu\n", count_mbox_421());   // unsigned long

  printk("=============================\n");

  long i = 0;
  while (i < k){
    printk("ID: %lu\n", mbxes[i]);   // unsigned long
    i++;
  }

  kfree(mbxes);

  return 0;
}
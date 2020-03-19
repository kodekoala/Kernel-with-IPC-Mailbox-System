#include "mailbox_syscalls.h"
static DECLARE_RWSEM(lock);

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



/*
creates a new empty mailbox with ID id, if it does not already exist, and 
returns 0. If the crypt_alg parameter is 0, the mailbox's messages shall 
be encrypted with the XOR cipher described above. Otherwise, the messages 
shall be encrypted with the XTEA algorithm.
 */
SYSCALL_DEFINE2(create_mbox_421, unsigned long, id, int, crypt_alg){
  down_write(&lock);
  mbox_t * new_mbox;
  kuid_t rootUid;
  struct list_head * currBox;
  mbox_t * pos = NULL;
  rootUid.val = 0;

  if (!uid_eq(get_current_cred()->uid, rootUid)) {
    // Tell user to run app as root, then exit.
    printk("Not root! Please switch user");
    up_write(&lock);
    return -EPERM;
  }

  //check if given ID exists
  //Loop over mboxes list
  list_for_each(currBox, &mailBoxes) {
    pos = NULL;

    //Get the mbox_t struct that corresponds to the list_node 
    //that is currently pointed to by the currBox pointer in the mboxes list
    pos = list_entry(currBox, mbox_t, list_node);

    if (pos != NULL) {
      if (pos -> boxId == id) {
        printk("mbox %lu already exists\n", id);
        up_write(&lock);
        return -EEXIST; //id already exists
      }
    }
  }

  //if the mailbox doesn't exist, create new mailbox
  new_mbox = (mbox_t * ) kmalloc(sizeof(mbox_t), GFP_KERNEL);
  INIT_LIST_HEAD( & new_mbox -> msgs);
  new_mbox -> boxId = id;
  new_mbox -> encryption = crypt_alg;
  //Insert the new list_node for the created mailbox before the head
  list_add_tail( & new_mbox -> list_node, &mailBoxes);
  printk("Created a mailbox with ID: %lu\n", new_mbox -> boxId);
  //Keep track of mailbox count
  mailboxCount++;
  up_write(&lock);
  return 0;
}


/* removes mailbox with ID id, if it is empty, and returns 0.
   If the mailbox is not empty, this system call shall return
   an appropriate error and not remove the mailbox.
 */
SYSCALL_DEFINE1(remove_mbox_421, unsigned long, id){
  down_write(&lock);
  kuid_t rootUid;
  struct list_head * tmp;
  struct list_head * currBox = NULL;
  mbox_t * box = NULL;
  rootUid.val = 0;


  if (!uid_eq(get_current_cred()->uid, rootUid)) {
    // Tell user to run app as root, then exit.
    printk("Not root! Please switch user");
    up_write(&lock);
    return -EPERM;
  }

  list_for_each_safe(currBox, tmp, &mailBoxes) {
    box = list_entry(currBox, mbox_t, list_node);

    if (box -> boxId == id) { //found mbox

      if (list_empty( &box -> msgs)) { //true if empty
        printk("Empty messages in this mailbox\n");
        printk("Deleted the mailbox with ID: %lu\n", box -> boxId);
        list_del(currBox);
        //kfree(currBox);
        kfree(box);
        mailboxCount--;
        up_write(&lock);
        return 0;
      } 
      else {
        printk("The mailbox %lu is not empty\n", id);
        up_write(&lock);
        return -ENOTEMPTY;
      }
    }
  }
  printk("The mailbox %lu does not exist\n", id);
  up_write(&lock);
  return -ENOENT;
}


/* 
Returns a list of up to k mailbox IDs in the user-space variable mbxes.
It returns the number of IDs written successfully to mbxes on success 
and an appropriate error code on failure.
*/
SYSCALL_DEFINE2(list_mbox_421, unsigned long __user *, mbxes, long, k) {

  struct list_head *pos;
  unsigned int writtenIDs = 0; //num of written IDs
  int count = k;
  mbox_t* theBox = NULL;

  //check if passed in pointer is valid
  if (mbxes == NULL || k < 0)
    return -EFAULT;

  down_read(&lock);
  //User is requesting for too many mboxes
  if (k > mailboxCount){
    count = mailboxCount;
  }

  if (!access_ok(mbxes, count*sizeof(unsigned long))){
    up_read(&lock);
    return -EFAULT;
  }
    
  list_for_each(pos, &mailBoxes) {
    theBox = NULL;
    theBox = list_entry(pos, mbox_t, list_node);
    if (writtenIDs < count) {
      printk("Mailbox %lu\n", theBox->boxId);
      mbxes[writtenIDs] = theBox->boxId;
      writtenIDs++;
    }
    
  }
  up_read(&lock);
  return writtenIDs;
}

/* returns the number of existing mailboxes.
 */
SYSCALL_DEFINE0(count_mbox_421) {
  unsigned int tmp;
  down_read(&lock);
  tmp = mailboxCount;
  up_read(&lock);
  return tmp;
}

/* 
Encrypts the message msg (using the correct algorithm), adding it to the already existing
mailbox identified. Returns the number of bytes stored (which shall be equal to the message 
length n) on success, and an appropriate error code on failure. Messages with negative lengths 
shall be rejected as invalid and cause an appropriate error to be returned, however messages 
with a length of zero shall be accepted as valid.
 */
SYSCALL_DEFINE4(send_msg_421, unsigned long, id, unsigned char __user *, msg, long, n, uint32_t __user *, key) {
  struct list_head * currBox;
  mbox_t * box = NULL;

  printk("Before null check in send_msg_421\n");

  if (msg == NULL || n < 0 || key == NULL) //check passed in pointer
    return -EFAULT;

  printk("Before msg check in send_msg_421\n");

  if (!access_ok(msg, n*sizeof(unsigned char))) return -EFAULT;

  printk("After msg copy in send_msg_421");

  down_read(&lock);

  list_for_each(currBox, &mailBoxes) { //loop mailboxes
    box = NULL;
    box = list_entry(currBox, mbox_t, list_node);

    //search for mailbox id
    if (box -> boxId == id) {
      down_write(&lock);
      unsigned char *kernelMsg;
      long newLen;
      uint32_t *kernelKey;
      int i;
      msgNode_t * msgNode = NULL;

      //kmalloc
      msgNode = (msgNode_t * ) kmalloc(sizeof(msgNode_t), GFP_KERNEL);
      if(!msgNode){
        printk("Allocation Error\n");
        up_write(&lock);
        up_read(&lock);
        return -ENOMEM;
      }
      msgNode->msg = NULL;
      msgNode->msgLen = 0;
      //kmalloc

      if (box -> encryption == 0) {
        //XOR Cipher
        printk("Before key check in send_msg_421 for XOR\n");
        if (!access_ok(key, sizeof(uint32_t))){
          up_write(&lock);
          up_read(&lock);
          return -EFAULT;
        }
        kernelKey = (uint32_t *) kmalloc (sizeof(key), GFP_KERNEL);
        printk("Before key copy in send_msg_421 for XOR\n");
        if(copy_from_user( &kernelKey[0], &key[0], sizeof(key)) != 0){
          up_write(&lock);
          up_read(&lock);
          return -EFAULT;
        }
        //memcpy (&kernelKey[0], &key[0], sizeof(key));
        newLen = xorCrypt(&(msgNode->msg), kernelMsg, msg, n, kernelKey);
        if (newLen < 0){
          up_write(&lock);
          up_read(&lock);
          return newLen;
        }
        for (i = 0 ; i < n ; i++ ){
          //msgNode->msg[i] = 'a';
          printk("%d\n", msgNode->msg[i]);
        }
      }
      else{
        //XTEA Cipher
        int blockSize = 8;
        long padding;
        uint32_t *temp;
        printk("Before key check in send_msg_421 for XTEA\n");
        if (!access_ok(key, 4*sizeof(uint32_t))){
          up_write(&lock);
          up_read(&lock);
          return -EFAULT;
        }
        kernelKey = (uint32_t *) kmalloc (4 * sizeof(uint32_t), GFP_KERNEL);
        
        printk("Before key copy in send_msg_421 for XTEA");
        if(copy_from_user( &kernelKey[0], &key[0], (4*sizeof(uint32_t))) != 0){
          up_write(&lock);
          up_read(&lock);
          return -EFAULT;
        }
        //memcpy (&kernelKey[i], &key[i], sizeof(uint32_t));
        printk("After key copy in send_msg_421 for XTEA");


         if (n < blockSize){
            padding = blockSize - n;
         }
         else{
            padding = (blockSize * (int)(n/blockSize) + blockSize) - n;   
            printk("Padding is: %ld\n", padding);
         }
        newLen = n + padding;
        printk("Newlen is: %ld\n", newLen);


        msgNode->msg = (unsigned char *)kmalloc(newLen*sizeof(unsigned char*), GFP_KERNEL);
        if(!msgNode->msg){
          printk("Allocation Error\n");
          up_write(&lock);
          up_read(&lock);
          return -ENOMEM;
        }

        //In kernel code we need to copy to kernel memory
        kernelMsg = (unsigned char *) kmalloc (newLen*sizeof(unsigned char), GFP_KERNEL);
        if(!kernelMsg){
          printk("Allocation Error\n");
          up_write(&lock);
          up_read(&lock);
          return -ENOMEM;
        }
        //temp = (uint32_t *) kmalloc (8*sizeof(unsigned char), GFP_KERNEL);
        printk("Before msg copy in send_msg_421 for XTEA\n");
        if(copy_from_user( &kernelMsg[0], &msg[0], n * sizeof(unsigned char)) != 0){
          up_write(&lock);
          up_read(&lock);
          return -EFAULT;
        }
        //memcpy (&kernelMsg[0], &msg[0], n * sizeof(unsigned char));
        for (i = n; i < newLen; i++){
            kernelMsg[i] = 0x00;
        }  

        printk("111111111111111111111111111111\n");

        for (i = 0 ; i < newLen ; i++ ){
            printk("%d\n", kernelMsg[i]);
        }

        printk("222222222222222222222222222222\n");

        //int i = 0; i + 8 < newLen; i += 8*sizeof(unsigned char)
        i = 0;
          // This assumes that data is aligned on a 4-byte boundary
        do{
            printk("i is equal to: %d\n", i);
            //memcpy(&temp[0], &kernelMsg[i], 4 * sizeof(unsigned char));
            //memcpy(&temp[1], &kernelMsg[i+4], 4 * sizeof(unsigned char));

            printk("Printing out temp contents\n");

            //((uint32_t *)temp)[0] ^= *kernelKey;
            xtea_enc((uint32_t *)&kernelMsg[i], kernelKey);
            //memcpy( &kernelMsg[i], ((uint32_t *)temp), 8 * sizeof(unsigned char));
            i += 8;
        }while(i < newLen);

        for (i = 0 ; i < newLen ; i++ ){
            printk("%d\n", kernelMsg[i]);
        }

        //kfree(temp);

        for (i=0; i<newLen; i++) {
          msgNode->msg[i] = kernelMsg[i];
        }

        kfree(kernelMsg);
        //kfree(kernelKey);
      }

      printk("3333333333333333333333333333333333333\n");
      for (i = 0 ; i < n ; i++ ){
         //msgNode->msg[i] = 'a';
        printk("%d\n", msgNode->msg[i]);
      }

      kfree(kernelKey);

      msgNode -> msgLen = n;
      list_add_tail( &msgNode -> list_node, &box -> msgs);

      up_write(&lock);
      up_read(&lock);
      return n; //number of bytes stored on success
      //error code on failure
    }
  }
  up_read(&lock);

  printk("Couldn't find mailbox with %lu ID\n", id);
  return -ENOENT;
}


long xorCrypt(unsigned char ** boxMsg, unsigned char *kernelMsg, unsigned char * msg, long n, uint32_t * kernelKey){
  int blockSize = 4;
  int padding;
  long newLen;
  unsigned char *temp;
  int i;

  if (n < blockSize){
      padding = blockSize - n;
  }
  else{
      padding = (blockSize * (int)(n/blockSize) + blockSize) - n;   
  }
  newLen = n + padding;

  *boxMsg = (unsigned char *)kmalloc(n*sizeof(unsigned char*), GFP_KERNEL);

  //In kernel code we need to copy to kernel memory
  kernelMsg = (unsigned char *) kmalloc (newLen*sizeof(unsigned char), GFP_KERNEL);
  temp = (unsigned char *) kmalloc (4*sizeof(unsigned char), GFP_KERNEL);

  printk("Before msg copy in send_msg_421 for XOR\n");
  if(copy_from_user( &kernelMsg[0], &msg[0], n * sizeof(unsigned char)) != 0){
    return -EFAULT;
  }
  //memcpy (&kernelMsg[0], &msg[0], n * sizeof(unsigned char));
  for (i = n; i < newLen; i++){
      kernelMsg[i] = 0x00;
  }  

  // This assumes that data is aligned on a 4-byte boundary
  for(i = 0; i + 3 < newLen; i += 4*sizeof(unsigned char)){
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
}

long xorDecrypt(unsigned char * boxMsg, unsigned char *kernelMsg, unsigned char * msg, long n, uint32_t * key){
  int blockSize = 4;
  int padding;
  long newLen;
  unsigned char *temp = NULL;
  int i;
  if (n < blockSize){
      padding = blockSize - n;
   }
   else{
      padding = (blockSize * (int)(n/blockSize) + blockSize) - n;   
   }
  newLen = n + padding;

  //In kernel code we need to copy to kernel memory
  kernelMsg = (unsigned char *) kmalloc (newLen*sizeof(unsigned char), GFP_KERNEL);
  memcpy( &kernelMsg[0], &boxMsg[0], n * sizeof(unsigned char));

  for (i = n; i < newLen; i++){
    kernelMsg[i] = 0x00;
  }

  temp = (unsigned char *) kmalloc (4*sizeof(unsigned char), GFP_KERNEL);

  // This assumes that data is aligned on a 4-byte boundary
  for(i = 0; i + 3 < newLen; i += 4*sizeof(unsigned char)){
      int j;
      memcpy(&temp[0], &kernelMsg[i], 4 * sizeof(unsigned char));
      for (j = 0 ; i < 4 ; i++ ){
        printk("Inside temp:\n");
        printk("%d\n", temp[j]);
      }
      ((uint32_t *)temp)[0] ^= *key;
      memcpy( &kernelMsg[i], &temp[0], 4 * sizeof(unsigned char));
  }
  printk("=============================\n");

  kfree(temp);

  if(copy_to_user( &msg[0], &kernelMsg[0], n * sizeof(unsigned char)) != 0){
    return -EFAULT;
  }
  //memcpy( &msg[0], &kernelMsg[0], n * sizeof(unsigned char));

  // for (int i=0; i<n; i++) {
  //   msg[i] = kernelMsg[i];
  // }

  kfree(kernelMsg);
  for (i = 0 ; i < n ; i++ ){
    printk("%d\n", msg[i]);
  }
  printk("=============================\n");
  return 0;
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


static long receive(int delete, unsigned long id, unsigned char * msg, long n, uint32_t * key)
{
  struct list_head *currBox;
  long adjustedLen = n;
  mbox_t* pos;

  if (msg == NULL || n < 0 || key == NULL) //check passed in pointer
    return -EFAULT;

  if (!access_ok(msg, n*sizeof(unsigned char))) return -EFAULT;
  printk("adjustedLen: %ld\n", adjustedLen);

  down_read(&lock);
  //loop mboxes
  list_for_each(currBox, &mailBoxes) { //find mbox id
    int i;
    msgNode_t* firstMsg;
    long messageLen, confirmation;
    unsigned char *kernelMsg;
    uint32_t *kernelKey; 
    pos = NULL;
    pos = list_entry(currBox, mbox_t, list_node);    

    if (pos->boxId == id) {
      down_write(&lock);
      if (list_empty(&pos->msgs)) { //check if empty
        printk("No message in mailbox with ID: %lu\n", id);
        up_write(&lock);
        up_read(&lock);
        return ENOENT; //return error if no messages
      }
      //otherwise find the first message
      firstMsg = list_first_entry(&pos->msgs, msgNode_t, list_node);

      messageLen = firstMsg->msgLen;
      if(n > messageLen){
        adjustedLen = messageLen;
      }

      //kmalloc

      if (pos -> encryption == 0) {
        //XOR Cipher
        if (!access_ok(key, sizeof(uint32_t))){
          up_write(&lock);
          up_read(&lock);
          return -EFAULT;
        }
        kernelKey = (uint32_t *) kmalloc (sizeof(key), GFP_KERNEL);
        if(copy_from_user( &kernelKey[0], &key[0], sizeof(key)) != 0){
          up_write(&lock);
          up_read(&lock);
          return -EFAULT;
        }
        //memcpy (&kernelKey[0], &key[0], sizeof(key));
        confirmation = xorDecrypt(firstMsg->msg, kernelMsg, msg, adjustedLen, kernelKey);
        if (confirmation < 0){
          up_write(&lock);
          up_read(&lock);
          return confirmation;
        }
      }
      else{
        //XTEA Cipher
        int blockSize = 8;
        long padding;
        int newLen;
        uint32_t *temp;
        if (!access_ok(key, 4*sizeof(uint32_t))){ 
          up_write(&lock);
          up_read(&lock);
          return -EFAULT;
        }
        kernelKey = (uint32_t *) kmalloc (4 * sizeof(uint32_t), GFP_KERNEL);

        if(copy_from_user( &kernelKey[0], &key[0], 4*sizeof(uint32_t)) != 0){
          up_write(&lock);
          up_read(&lock);
          return -EFAULT;
        }
        //memcpy (&kernelKey[i], &key[i], sizeof(uint32_t));
        

         if (adjustedLen < blockSize){
            padding = blockSize - adjustedLen;
         }
         else{
            padding = (blockSize * (int)(adjustedLen/blockSize) + blockSize) - adjustedLen;   
         }
        newLen = adjustedLen + padding;

        //In kernel code we need to copy to kernel memory
        kernelMsg = (unsigned char *) kmalloc (newLen*sizeof(unsigned char), GFP_KERNEL);
        //temp = (uint32_t *) kmalloc (8*sizeof(unsigned char), GFP_KERNEL);
        memcpy (&kernelMsg[0], &(firstMsg->msg)[0], newLen*sizeof(unsigned char));

        printk("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n");

        for (i = 0 ; i < newLen ; i++ ){
            printk("%d\n", kernelMsg[i]);
        }

        printk("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n");

        i = 0;

        do{
            //memcpy(&temp[0], &kernelMsg[i], 8 * sizeof(unsigned char));
            xtea_dec((uint32_t *)&kernelMsg[i], kernelKey);
            //memcpy( &kernelMsg[i], (&temp[0]), 8 * sizeof(unsigned char));
            i += 8;
        }while(i < newLen);

        //kfree(temp);

        printk("::::::::::::::::::::::::::::\n");
        for (i = 0 ; i < newLen ; i++ ){
            printk("%d\n", kernelMsg[i]);
        }

        if(copy_to_user( &msg[0], &kernelMsg[0], adjustedLen * sizeof(unsigned char)) != 0){
          up_write(&lock);
          up_read(&lock);
          return -EFAULT;
        }

        kfree(kernelMsg);
      }

      kfree(kernelKey);

      //remove message from mbox
      if (delete == 1){
        kfree(firstMsg->msg);
        list_del(&firstMsg->list_node);
        kfree(firstMsg);
      }
      printk("%lu\n", adjustedLen);
      for (i = 0 ; i < adjustedLen ; i++ ){
        printk("%d\n", msg[i]);
      }
      //kfree(s);
      up_write(&lock);
      up_read(&lock);      
      return (adjustedLen); //return minimum(n, len(msg @ id))
    }
  }
  up_read(&lock);
  return -ENOENT; 
}

/* 
Copies up to n characters from the next message in the mailbox id to the user-space buffer msg, decrypting with 
the specified key, and removes the entire message from the mailbox (even if only part of the message is copied out).
Returns the number of bytes successfully copied (which shall be the minimum of the length of the message that is stored and n) 
n success or an appropriate error code on failure.
*/
SYSCALL_DEFINE4(recv_msg_421, unsigned long, id, unsigned char __user *, msg, long, n, uint32_t __user *, key) {
  return receive(1, id, msg, n, key);
}


/* performs the same operation as recv_msg_421() without
   removing the message from the mailbox.
 */
SYSCALL_DEFINE4(peek_msg_421, unsigned long, id, unsigned char __user *, msg, long, n, uint32_t __user *, key) {
  return receive(0, id, msg, n, key);
}


/* Returns the number of messages in the mailbox id on
   success or an appropriate error code on failure.
 */
SYSCALL_DEFINE1(count_msg_421, unsigned long, id) {
  
  long count = 0;
  struct list_head * currBox;
  mbox_t * pos;
  //check if given ID exists
  //Loop over mboxes list
  down_read(&lock);
  list_for_each(currBox, &mailBoxes) {
    pos = NULL;

    //Get the mbox_t struct that corresponds to the list_node 
    //that is currently pointed to by the currBox pointer in the mboxes list
    pos = list_entry(currBox, mbox_t, list_node);

    if (pos->boxId == id) {
      down_write(&lock);    
      //loop msgs
      msgNode_t* curr_msg;
      list_for_each_entry(curr_msg, &pos->msgs, list_node) {
        count++;
      }
      up_write(&lock);
      up_read(&lock);
      return count;
    }
  }
  printk("message box %lu does not exist\n", id);
  up_read(&lock);
  return -ENOENT;
}


/* 
  returns the length of the next message that would be returned
   by calling recv_msg_421() with the same id value (that is the
   number of bytes in the next message in the mailbox). If there
   are no messages in the mailbox, this shall return an appropriate
   error value.
 */
SYSCALL_DEFINE1(len_msg_421, unsigned long, id) {
  
  struct list_head * currBox;
  mbox_t * pos;
  //check if given ID exists
  //Loop over mboxes list
  down_read(&lock);
  list_for_each(currBox, &mailBoxes) {
    pos = NULL;

    //Get the mbox_t struct that corresponds to the list_node 
    //that is currently pointed to by the currBox pointer in the mboxes list
    pos = list_entry(currBox, mbox_t, list_node);

    if (pos != NULL) {
      if (pos -> boxId == id) {
        down_write(&lock);
        msgNode_t* firstMsg;
        if (list_empty(&pos->msgs)) { //check if empty
          printk("No msg in ID %lu\n", id);
          up_write(&lock);
          up_read(&lock);
          return -ENOENT; //return error if no messages
        }
        //find first message
        firstMsg = list_first_entry(&pos->msgs, msgNode_t, list_node);      
        up_write(&lock);
        up_read(&lock);
        return firstMsg->msgLen;//return byte count
      }
    }
  }
  up_read(&lock);
  printk("Mailbox of ID: %lu does not exist\n", id);
  return -ENOENT;
}


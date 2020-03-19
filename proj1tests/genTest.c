#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <linux/kernel.h>
#include <sys/syscall.h>

#define __NR_create_mbox_421 436
#define __NR_remove_mbox_421 437
#define __NR_count_mbox_421 438
#define __NR_list_mbox_421 439
#define __NR_send_msg_421 440
#define __NR_recv_msg_421 441
#define __NR_peek_msg_421 442
#define __NR_count_msg_421 443
#define __NR_len_msg_421 444

long create_box(unsigned long id, int crypt_alg) {
    return syscall(__NR_create_mbox_421, id, crypt_alg);
}

long remove_box(unsigned long id) {
    return syscall(__NR_remove_mbox_421, id);
}

long count_box(void) {
    return syscall(__NR_count_mbox_421);
}

long list_box(unsigned long *mbxes, long k) {
    return syscall(__NR_list_mbox_421, mbxes, k);
}

long send_msg(unsigned long id, unsigned char *msg, long n, uint32_t *key) {
    return syscall(__NR_send_msg_421, id, msg, n, key);
}

long recv_msg(unsigned long id, unsigned char *msg, long n, uint32_t *key) {
    return syscall(__NR_recv_msg_421, id, msg, n, key);
}

long peek_msg(unsigned long id, unsigned char *msg, long n, uint32_t *key) {
    return syscall(__NR_peek_msg_421, id, msg, n, key);
}

long count_msg(unsigned long id) {
    return syscall(__NR_count_msg_421, id);
}

long len_msg(unsigned long id){
  return syscall(__NR_len_msg_421, id);
}

int main(void) {
    long rv;
    unsigned long i, num;
    long k = 5;
    //unsigned long * mbxes = (unsigned long * ) kmalloc(sizeof(unsigned long) * k);;
    num = 50;
    rv = create_box(num, 1);
    if (rv < 0){
      printf("Error occured in creating box with ID: %ld\n", num+i);
    }
    else {
      printf("Box with ID: %ld created successfully, check logs (dmseg)\n", num+i);
    }
    
    for (i = 1; i < 5; i++){
      rv = create_box(num+i, 0);
      if (rv < 0){
        printf("Error occured in creating box with ID: %ld\n", num+i);
      }
      else {
        printf("Box with ID: %ld created successfully, check logs (dmseg)\n", num+i);
      }
    }

    printf("Number of mailboxes: %lu\n", count_box());


    uint32_t keyarr[] = {0x0000, 0x0000, 0x1BAD, 0xC0DE};

    unsigned char msg0[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34, 0xBE, 0xEF, 0x12};
    unsigned char msg1[] = {'A', 'B', 'C', 'D', 'E', 'F'};

    unsigned char * usrmsg = (unsigned char * ) malloc(9 * sizeof(unsigned char));

    send_msg(50, msg1, 6, keyarr);

    send_msg(50, msg1, 6, keyarr);

    send_msg(51, msg0, 6, keyarr);

    printf("Number of messages in mbox with ID 50: %lu\n", count_msg(50));

    printf("Length of next message in mbox with ID 50: %lu\n", len_msg(50));

    printf("Number of messages in mbox with ID 51: %lu\n", count_msg(51));

    printf("Length of next message in mbox with ID 50: %lu\n", len_msg(51));

    unsigned long * mbxes = (unsigned long * ) malloc(sizeof(unsigned long) * 5);;
    list_box(mbxes, 10);

    i = 0;
    while (i < 5){
      printf("ID: %lu\n", mbxes[i]);   // unsigned long
      i++;
    }

    printf("Lets peek into the message for ID 50\n");

    peek_msg(50, usrmsg, 6, keyarr);

    for (i = 0 ; i < 6 ; i++ ){
      printf("%d\n", usrmsg[i]);
    }

    printf("Now lets receive the message for ID 50\n");

    recv_msg(50, usrmsg, 6, keyarr);

    for (i = 0 ; i < 6 ; i++ ){
      printf("%d\n", usrmsg[i]);
    }

    recv_msg(50, usrmsg, 6, keyarr);

    printf("Lets peek into the message for ID 51\n");

    peek_msg(51, usrmsg, 9, keyarr);

    for (i = 0 ; i < 9 ; i++ ){
      printf("%d\n", usrmsg[i]);
    }

    printf("Now lets receive the message for ID 51\n");

    recv_msg(51, usrmsg, 9, keyarr);

    for (i = 0 ; i < 9 ; i++ ){
      printf("%d\n", usrmsg[i]);
    }

    for (i = 0; i < 5; i++){
      rv = remove_box(num+i);
      if (rv < 0){
        printf("Error occured in removing box with ID: %ld\n", num+i);
      }
      else {
        printf("Box with ID: %ld removed successfully, check logs (dmseg)\n", num + i);
      }
    }

    free(usrmsg);
    free(mbxes);

    return 0;
}

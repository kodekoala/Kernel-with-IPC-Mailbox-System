#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <linux/kernel.h>
#include <sys/syscall.h>

#define __NR_create_mbox_421 436

long create_box(unsigned long id, int crypt_alg) {
    return syscall(__NR_create_mbox_421(id, crypt_alg));
}

int main(int argc, char *argv[]) {
    long rv;
    unsigned long i, num;
  	long k = 5;
  	//unsigned long * mbxes = (unsigned long * ) kmalloc(sizeof(unsigned long) * k);;
  	num = 50;
  	for (i = 0; i < 5; i++){
  		rv = create_box(num+i, 0);
  		if (rv != 0){
  			printf("Error occured in creating box with ID: %ld\n", num+i);
  		}
  		else {
        printf("Box with ID: %ld created successfully, check logs (dmseg)\n");
    	}
  	}

    // rv = hello_syscall();

    // if(rv != 0) {
    //     perror("Box not created");
    // }
    // else {
    //     printf("Box created successfully, check logs (dmseg)\n");
    // }

    return 0;
}



// int main(void) {
//   unsigned long i, num;
//   long result;
//   long k = 5;
//   unsigned long * mbxes = (unsigned long * ) kmalloc(sizeof(unsigned long) * k);;
//   num = 50;
//   for (i = 0; i < 5; i++){
//   	result = create_mbox_421(num+i, 0);
//   	if (result != 0){
//   		printf("Error occured in creating box: %d\n", num+i);
//   	}
//   }
//   create_mbox_421(50, 0);
//   create_mbox_421(51, 0);
//   create_mbox_421(52, 0);
//   create_mbox_421(53, 0);
//   create_mbox_421(54, 0);
//   printk("=============================\n");
//   printk("Number of mailboxes: %lu\n", count_mbox_421());   // unsigned long

//   //uint32_t keyarr[] = {0x0000, 0x0000, 0x1BAD, 0xC0DE};
//   uint32_t keyarr = 0x1BADC0DE;
//   uint32_t * key = &keyarr;

//   unsigned char theMsg[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34, 0xBE, 0xEF, 0x12};
//   //unsigned char theMsg[] = {'A', 'B', 'C', 'D', 'E', 'F'};

//   //unsigned char theMsg[] = {0x12, 0x34};

//   unsigned char * msg = theMsg;

//   unsigned char * usrmsg = (unsigned char * ) kmalloc(9 * sizeof(unsigned char));

//   send_msg_421(50, msg, 9, key);
//   printk("=============================\n");
//   printk("There are currently %lu messages in box with ID 50\n", count_msg_421(50));
//   printk("=============================\n");
//   peek_msg_421(50, usrmsg, 9, key);
//   for (int i = 0 ; i < 9 ; i++ ){
//     printk("%d\n", usrmsg[i]);
//   }
//   printk("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");

//   recv_msg_421(50, usrmsg, 9, key);
//   printk("-------------------------------------\n");

//   // for (int i = 0; i < 6; i++){
//   //   printk("%d\n", usrmsg[i]);   // unsigned long
//   //   i++;
//   // }

//   for (int i = 0 ; i < 9 ; i++ ){
//     printk("%d\n", usrmsg[i]);
//   }

//   kfree(usrmsg);
//   printk("=============================\n");
//   printk("Number of messages in box with ID 50: %lu\n", count_msg_421(50));   // unsigned long

//   list_mbox_421(mbxes, k);
//   remove_mbox_421(50);
//   remove_mbox_421(51);
//   remove_mbox_421(52);
//   remove_mbox_421(53);
//   remove_mbox_421(54);
//   printk("=============================\n");

//   printk("Number of mailboxes: %lu\n", count_mbox_421());   // unsigned long

//   printk("=============================\n");

//   long i = 0;
//   while (i < k){
//     printk("ID: %lu\n", mbxes[i]);   // unsigned long
//     i++;
//   }

//   kfree(mbxes);

//   return 0;
// }

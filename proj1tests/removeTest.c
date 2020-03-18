#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <linux/kernel.h>
#include <sys/syscall.h>

#define __NR_remove_mbox_421 437

long remove_box(unsigned long id) {
    return syscall(__NR_remove_mbox_421, id);
}

int main(int argc, char *argv[]) {
    long rv;
    unsigned long i, num;
  	long k = 5;
  	//unsigned long * mbxes = (unsigned long * ) kmalloc(sizeof(unsigned long) * k);;
  	num = 50;
  	for (i = 0; i < 5; i++){
  		rv = remove_box(num+i);
  		if (rv < 0){
  			printf("Error occured in creating box with ID: %ld\n", num+i);
  		}
  		else {
        printf("Box with ID: %ld removed successfully, check logs (dmseg)\n");
    	}
  	}

    return 0;
}
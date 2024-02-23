#include <bits/types/struct_timeval.h>
#include <cstdlib>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/select.h>
#include <unistd.h>
#include <sys/time.h>

int funcc4(int val) {
    char* ptr;
    printf("zql funcc4 value=%d\n", val);
    ptr = (char *)malloc(val*1024*1024);
    for (int i = 0; i < val*1024*1024; i++) {
        ptr[i] = (char) (i & 0xff); // pagefault
    }
    free(ptr);
    return 0;
}

int funcc3(int val) {
    printf("zql funcc3 value=%d\n", val);
    char* ptr;
    ptr = (char *)malloc(val*1024*1024);
    for (int i = 0; i < val*1024*1024; i++) {
        ptr[i] = (char) (i & 0xff); // pagefault
    }
    funcc4(4);
    free(ptr);
    return 1;
}

int funcc(int val) {
    printf("zql funcc value=%d\n", val);
    char* ptr;
    ptr = (char *)malloc(val*1024*1024);
    for (int i = 0; i < val*1024*1024; i++) {
        ptr[i] = (char) (i & 0xff); // pagefault
    }
    funcc3(3);
    free(ptr);
    return 0;
}

int funcc2(int val);

int main() {
    struct timeval start, end;
    while(1) {
        sleep(1);
        gettimeofday(&start, NULL);
        printf("[%ld.%ld] funcc start\n", end.tv_sec, end.tv_usec);
	    funcc(2);
        gettimeofday(&end, NULL);
        printf("[%ld.%ld] funcc spend %ld us\n", end.tv_sec, end.tv_usec, 1000000 * (end.tv_sec-start.tv_sec)+ end.tv_usec-start.tv_usec);
        printf("###############\n");
        funcc2(3);
    }
}
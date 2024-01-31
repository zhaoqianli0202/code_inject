#include <bits/types/struct_timeval.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/select.h>
#include <unistd.h>
#include <sys/time.h>

__attribute__((noinline))
int funcc(int val) {
    printf("zql funcc value=%d\n", val);
    return 1;
}
int funcc2(int val);

int main() {
    struct timeval start, end;
    while(1) {
        sleep(1);
        gettimeofday(&start, NULL);
	    funcc(2);
        funcc2(3);
        gettimeofday(&end, NULL);
        printf("func spend %ld us\n", ((end.tv_sec - start.tv_sec)*1000*1000) + (end.tv_usec - start.tv_usec));
    }
}
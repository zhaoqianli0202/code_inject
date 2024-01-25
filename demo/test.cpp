#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((noinline))
int funcc(int val) {
    printf("zql funcc value=%d\n", val);
    return 1;
}

int main() {
    while(1) {
        sleep(1);
	    funcc(2); 
    }
}

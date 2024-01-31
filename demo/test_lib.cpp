#include <stdio.h>
#include <stdlib.h>
#include <sys/select.h>
#include <unistd.h>
#include <sys/time.h>

int funcc22(int val) {
    printf("zql funcc22 value=%d\n", val);
    return 3;
}

__attribute__((noinline))
int funcc2(int val) {
    printf("zql funcc2 value=%d\n", val);
    funcc22(val);
    return 3;
}
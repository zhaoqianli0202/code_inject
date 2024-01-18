
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef APP
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
#else
#include "log.h"

#define   A64_LOGE(fmt, ...)	ALOGE(fmt, ##__VA_ARGS__)
void *callback = nullptr;

__attribute__((noinline))
int funcc_hook_return(int ret) {
    ALOGE("zql funcc_hook_return value=%d\n", ret);
    return ret;
}
/*下一步不同类型的参数*/
__attribute__((noinline))
int funcc_hook(int val) {
    int ret = -1;
    ALOGE("zql funcc_hook value=%d\n", val);
    if (callback) {
        int (*cb)(int) = (int(*)(int))callback;
        ret = cb(val);
    }
    funcc_hook_return(ret);

    return -2;
}

#endif
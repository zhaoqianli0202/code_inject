#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define   A64_LOGE(fmt, ...)	ALOGE(fmt, ##__VA_ARGS__)
void *callback = nullptr;

__attribute__((noinline))
int funcc_hook_return(int ret) {
    ALOGE("zql funcc_hook_return value=%d\n", ret);
    return ret;
}

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

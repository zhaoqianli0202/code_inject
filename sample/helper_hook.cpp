#include "../hook_helper/hook_helper.h"
#include <cstdint>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

extern "C"
__attribute__((noinline))
uint64_t helper_hook_func(struct hooker_regs *regs, char *hook_func_name) {
    printf("helper_hook_func hook_func_name:%s\n", hook_func_name);
    /*c++ x0 is 'this'*/
    // printf("parm0=0x%lx, param1=0x%lx, param2=0x%lx, param3=0x%lx\n", regs->x0, regs->x1, regs->x2, regs->x3);
    return 1024;
}

extern "C"
__attribute__((noinline))
uint64_t helper_hook_func_return(struct hooker_regs *regs, char *hook_func_name) {
    printf("helper_hook_func_return hook_func_name:%s\n", hook_func_name);
    // printf("helper_hook_func_return parm0=0x%lx, param1=0x%lx, param2=0x%lx, param3=0x%lx\n", regs->x0, regs->x1, regs->x2, regs->x3);
    return 2048;
}
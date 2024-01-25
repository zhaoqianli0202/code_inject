#pragma once

#include <cstdint>

struct hooker_regs {
        uint64_t x0;
        uint64_t x1;
        uint64_t x2;
        uint64_t x3;
        uint64_t x4;
        uint64_t x5;
        uint64_t x6;
        uint64_t x7;
};

typedef uint64_t (*HOOK_FUNC)(struct hooker_regs *, char *);
typedef void (*HOOK_FUNC_RET)(struct hooker_regs *, char *);

extern "C" {
    uint64_t inline_func_entry(unsigned long *parent_loc, struct hooker_regs *regs, uint64_t hook_addr);
    uint64_t inline_func_exit(struct hooker_regs *regs);
    void injector_register(uint64_t hook_addr, uint64_t **ptarget_addr, void *hook_func, void *hook_func_ret, char *hook_func_name);
    void *find_org_code(uint64_t hook_addr);
}
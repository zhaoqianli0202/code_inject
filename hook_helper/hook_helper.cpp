#include <cstddef>
#include <cstdint>
#include <cstring>
#include <pthread.h>
#include <sys/cdefs.h>
#include <unordered_map>
#include "hook_helper.h"
#define MAX_STACK_DEPTH (512)
#define CODE_INJ_ALIGN (0x10)

#define HOOK_HELPER_ERR(fmt, ...) printf("[ERR]" fmt, ##__VA_ARGS__)
#define HOOK_HELPER_INFO(fmt, ...) printf("[INFO]" fmt, ##__VA_ARGS__)
#define HOOK_HELPER_WARN(fmt, ...) printf("[WARN]" fmt, ##__VA_ARGS__)

// #define DEGBUG
#ifdef DEGBUG
#define HOOK_HELPER_DBG(fmt, ...) printf("[DBG]" fmt, ##__VA_ARGS__)
#else
#define HOOK_HELPER_DBG(fmt, ...)
#endif

void *helper_callback;
extern "C" void inject_return(void);
struct ret_info_t {
    char *hook_func_name;
    uint64_t ret_addr;
    HOOK_FUNC_RET hook_ret_addr;
};
struct hook_stack {
    uint32_t depth;
    struct ret_info_t ret_info[MAX_STACK_DEPTH];
};

struct hook_map {
    void *orig_addr;
    uint64_t hook_addr;
    char hook_func_name[32];
    HOOK_FUNC hook_func;
    HOOK_FUNC_RET hook_func_ret;
};
static std::unordered_map<uint64_t, struct hook_map> hook_map;
static pthread_key_t hook_key = -1;

extern "C"
void free_stack(void* stack) {
    free(stack);
}

extern "C"
__attribute__((constructor))
void init() {
    pthread_key_create(&hook_key, &free_stack);
}

static uint64_t up_align_address(uint64_t addr, uint8_t align) {
    uintptr_t offset = addr % align;

    if (offset != 0) {
        size_t align_bytes = align - offset;
        addr += align_bytes;
    } else {
        addr += align;
    }

    return addr;
}

extern "C"
__attribute__((noinline))
uint64_t inline_func_entry(uint64_t *parent_loc, struct hooker_regs *regs, uint64_t hook_addr) {
    uint64_t ret = 0;
    HOOK_HELPER_DBG("inline_func_entry begin hook_addr_orgi=%lx\n", hook_addr);
    hook_addr = up_align_address(hook_addr, CODE_INJ_ALIGN);
    HOOK_HELPER_DBG("inline_func_entry begin hook_addr=%lx\n", hook_addr);
    /*addr correction*/
    if (hook_map.count(hook_addr) <= 0) {
        if (hook_map.count(hook_addr - CODE_INJ_ALIGN) > 0) {
            hook_addr -= CODE_INJ_ALIGN;
            HOOK_HELPER_DBG("inline_func_entry fixed hook_addr=%lx\n", hook_addr);
        }
    }
    if (hook_map.count(hook_addr) > 0) {
        if (hook_map[hook_addr].hook_func) {
            HOOK_HELPER_DBG("hook_map[hook_addr].hook_func %p, *parent_loc=%lx\n", hook_map[hook_addr].hook_func, *parent_loc);
            ret = hook_map[hook_addr].hook_func(regs, hook_map[hook_addr].hook_func_name);
        }
    }
    struct hook_stack *stack = (struct hook_stack *)pthread_getspecific(hook_key);
    if (!stack) {
        stack = (struct hook_stack *)malloc(sizeof(*stack));
        if (!stack) {
            HOOK_HELPER_ERR("inline_func_entry malloc failed\n");
            return 0;
        }
        memset(stack, 0, sizeof(*stack));
        pthread_setspecific(hook_key, stack);
    }
    if (stack->depth >= MAX_STACK_DEPTH) {
        HOOK_HELPER_ERR("stack depth exceeded the limit %d\n", MAX_STACK_DEPTH);
        abort();
        return 0;
    }
    if (hook_map[hook_addr].hook_func_ret) {
        stack->ret_info[stack->depth].hook_ret_addr = hook_map[hook_addr].hook_func_ret;
        stack->ret_info[stack->depth].ret_addr = *parent_loc;
        stack->ret_info[stack->depth].hook_func_name = hook_map[hook_addr].hook_func_name;
        stack->depth++;
        *parent_loc = (unsigned long)inject_return;
    }
    HOOK_HELPER_DBG("inline_func_entry end\n");
    return ret;
}

extern "C"
__attribute__((noinline))
uint64_t inline_func_exit(struct hooker_regs *regs) {
    struct hook_stack *stack = (struct hook_stack *)pthread_getspecific(hook_key);
    stack->depth--;
    HOOK_HELPER_DBG("inline_func_exit begin, hook_ret_addr=%p, ret_addr=%lx,depth=%d\n", stack->ret_info[stack->depth].hook_ret_addr, stack->ret_info[stack->depth].ret_addr, stack->depth);
    if (stack->ret_info[stack->depth].hook_ret_addr)
        stack->ret_info[stack->depth].hook_ret_addr(regs, stack->ret_info[stack->depth].hook_func_name);
    return stack->ret_info[stack->depth].ret_addr;
}

extern "C"
__attribute__((noinline))
void injector_register(uint64_t hook_addr, uint64_t **p_orig_addr, void *hook_func, void *hook_func_ret, char *hook_func_name) {
    uint64_t orig_hook_addr = hook_addr;
    hook_addr = up_align_address(hook_addr, CODE_INJ_ALIGN);

    if (!p_orig_addr)
        hook_map[hook_addr].orig_addr = nullptr;
    else
        hook_map[hook_addr].orig_addr = *p_orig_addr;
    hook_map[hook_addr].hook_addr = orig_hook_addr;
    hook_map[hook_addr].hook_func = (HOOK_FUNC)hook_func;
    hook_map[hook_addr].hook_func_ret = (HOOK_FUNC_RET)hook_func_ret;
    strncpy(hook_map[hook_addr].hook_func_name, hook_func_name, sizeof(hook_map[hook_addr].hook_func_name) - 1);
    HOOK_HELPER_DBG("hook_addr=%lx, orig_hook_addr=%lx, orig_addr=%p, p_orig_addr=%lx, helper_callback=%lx, hook_func=%p, hook_func_ret=%p\n", hook_addr, orig_hook_addr,
        hook_map[hook_addr].orig_addr, (unsigned long)p_orig_addr, (unsigned long)helper_callback, hook_map[hook_addr].hook_func, hook_map[hook_addr].hook_func_ret);
}

extern "C"
__attribute__((noinline))
void *find_org_code(uint64_t hook_addr) {
    hook_addr = up_align_address(hook_addr, CODE_INJ_ALIGN);
    HOOK_HELPER_DBG("find_org_code begin hook_addr=%lx\n", hook_addr);
    /*addr correction*/
    if (hook_map.count(hook_addr) <= 0) {
        if (hook_map.count(hook_addr - CODE_INJ_ALIGN) > 0) {
            hook_addr -= CODE_INJ_ALIGN;
            HOOK_HELPER_DBG("inline_func_entry fixed hook_addr=%lx\n", hook_addr);
        }
    }
    if (hook_map.count(hook_addr) > 0) {
        HOOK_HELPER_DBG("find_org_code orgi addr:0x%p\n", hook_map[hook_addr].orig_addr);
        return hook_map[hook_addr].orig_addr;
    }
    HOOK_HELPER_DBG("Find address 0x%lx org_code failed\n", hook_addr);
    return nullptr;
}
#pragma once
#include "common.h"
#include "inject_info.h"
#include "arm64_inlinehook.h"

#define CPSR_T_MASK     ( 1u << 5 )
#define lr regs[30]

class injector {
private:
    struct pt_regs {
        uint64_t regs[31];
        uint64_t sp;
        uint64_t pc;
        uint64_t pstate;
    };
    const std::string lbc_path = "/lib/libc-2.31.so";
    pid_t target_tid;
    struct pt_regs ori_regs;
    uintptr_t dlopen_addr, dlsym_addr, dlclose_addr;
    inject_info *callback;
    int ptrace_attach(pid_t tid);
    int ptrace_getregs(struct pt_regs * regs);
    int wait_for_sigstop();
    uintptr_t get_remote_addr(pid_t target_pid, const std::string &module_name, uintptr_t local_addr);
    int ptrace_call_wrapper(pid_t pid, const char * func_name, uintptr_t func_addr, uintptr_t * parameters, int param_num, struct pt_regs * regs);
    uintptr_t ptrace_retval(struct pt_regs * regs);
    int ptrace_call(pid_t pid, uintptr_t addr, uintptr_t *params, int num_params, struct pt_regs* regs);
    int ptrace_continue(pid_t pid);
    int ptrace_setregs(pid_t pid, struct pt_regs * regs);
    uintptr_t ptrace_push(int pid, struct pt_regs *regs, const void* paddr, size_t size);
    int ptrace_writedata(pid_t pid, uint8_t *dest, uint8_t *data, size_t size);
    int dl_remote_func_addr(inject_info &target);
    int exec_target_inlinehook(inject_info &where, inject_info &code, inject_info &callback, bool helper_mode);
    int inline_code_inject(inject_info &where, inject_info &code, bool callback_orgi, bool hook_return, bool helper_mode);
    int load_inject_function(inject_info &target);
    int injector_set_hooker(inject_info &target);
    int injector_set_helper(inject_info &target);
    void set_target_pid(pid_t tid);
    int attach_thread();
    int detach_thread();
    void* trampoline;

public:
    inject_info *hooker;
    inject_info *helper;
    injector(pid_t tid);
    int injector_prepare(pid_t tid, inject_info &inject, inject_info &hooker, bool helper_mode,inject_info &hook_helper);
    int injector_register(inject_info &inject, inject_info &target, bool callback_orgi, bool hook_return, bool helper_mode);
    int injector_finish();
    int injector_register_full(pid_t tid, inject_info &inject, inject_info &target, bool callback_orgi, bool hook_return, bool helper_mode);
};
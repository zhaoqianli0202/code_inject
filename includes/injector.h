#pragma once
#include <string>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <asm/ptrace.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <cstring>
#include <elf.h>
#include <dlfcn.h>
#include <sys/mman.h>
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
    int ptrace_attach();
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
    void* trampoline;

public:
    injector(pid_t tid);
    int attach_thread();
    int detach_thread();
    int load_inject_function(inject_info &target);
    int exec_target_inlinehook(inject_info &where, inject_info &code, inject_info &hooker, inject_info &callback);
};
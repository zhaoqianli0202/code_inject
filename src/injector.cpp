#include "injector.h"
#include "inject_info.h"
#include <cstddef>
#include <cstdint>
#include <memory>
#include <unistd.h>

injector::injector(pid_t tid) : target_tid(tid), hooker(nullptr), helper(nullptr) {
    dlopen_addr = get_remote_addr(target_tid, lbc_path, (uintptr_t)dlsym(NULL, "__libc_dlopen_mode"));
    dlsym_addr = get_remote_addr(target_tid, lbc_path, (uintptr_t)dlsym(NULL, "__libc_dlsym"));
    dlclose_addr = get_remote_addr(target_tid, lbc_path, (uintptr_t)dlsym(NULL, "__libc_dlclose"));
}

int injector::wait_for_sigstop() {
	bool allow_dead_tid = false;
	struct timeval start, end;

	gettimeofday(&start, NULL);
	while (1) {
		int status;
		gettimeofday(&end, NULL);
		if ((end.tv_sec - start.tv_sec) > 1) {
			CODE_INJECT_ERR("Wait for sigstop timeout %d", target_tid);
			break;
		}

		pid_t p = TEMP_FAILURE_RETRY(waitpid(target_tid, &status, __WALL | WNOHANG));
		if (p == -1) {
			CODE_INJECT_ERR("Waitpid failed: tid %d, %s", target_tid, strerror(errno));
			break;
		} else if (p == target_tid) {
			if (WIFSTOPPED(status)) {
				return WSTOPSIG(status);
			} else {
				CODE_INJECT_ERR("Unexpected waitpid response: pid=%d, status=%08x\n", p,
										status);
				// This is the only circumstance under which we can allow a detach
				// to fail with ESRCH, which indicates the tid has exited.
				allow_dead_tid = true;
				continue;
			}
		}
	}

	if (ptrace(PTRACE_DETACH, target_tid, 0, 0) != 0) {
		if (allow_dead_tid && errno == ESRCH) {
			CODE_INJECT_ERR("Tid exited before attach completed: tid %d", target_tid);
		} else {
			CODE_INJECT_ERR("Detach failed: tid %d, %s", target_tid, strerror(errno));
		}
	}
	return -1;
}

int injector::ptrace_attach(pid_t tid) {
    if (ptrace(PTRACE_ATTACH, tid, NULL, 0) < 0) {
        CODE_INJECT_ERR("ptrace_attach failed\n");
        return -1;
    }

    if (wait_for_sigstop() < 0) {
        CODE_INJECT_ERR("wait_for_sigstop failed\n");
        return -2;
    }
    return 0;
}

int injector::ptrace_getregs(struct pt_regs * regs) {
    uintptr_t regset = NT_PRSTATUS;
    struct iovec io_vec;

    io_vec.iov_base = regs;
    io_vec.iov_len = sizeof(*regs);

    if (ptrace(PTRACE_GETREGSET, target_tid, regset, &io_vec) < 0) {
        CODE_INJECT_ERR("ptrace_getregs: failed to get register values\n");
        return -1;
    }
    return 0;
}

int injector::attach_thread() {
    if (ptrace_attach(target_tid) < -1) {
        CODE_INJECT_ERR("attatch failed\n");
        return -1;
    }

    if (ptrace_getregs(&ori_regs) < -1) {
        CODE_INJECT_ERR("getregs failed\n");
        return -1;
    }
    return 0;
}

int injector::detach_thread() {
    if (ptrace_setregs(target_tid, &ori_regs) == -1) {
        CODE_INJECT_ERR("recover org regs failed\n");
        return -1;
    }
    if (ptrace(PTRACE_DETACH, target_tid, NULL, 0) < 0) {
        CODE_INJECT_ERR("ptrace_detach failed\n");
        return -2;
    }
    return 0;
}

uintptr_t injector::get_remote_addr(pid_t target_pid, const std::string &module_name, uintptr_t local_addr) {
    uintptr_t local_handle, remote_handle;

    local_handle = inject_info::get_module_base(-1, module_name);
    remote_handle = inject_info::get_module_base(target_pid, module_name);

    return (local_addr - local_handle + remote_handle);
}

__attribute__((noinline))
int injector::ptrace_writedata(pid_t pid, uint8_t *dest, uint8_t *data, size_t size) {
    long i, j, remain;
    uint8_t *laddr;

    union u {
        uintptr_t val;
        char chars[sizeof(uintptr_t)];
    } d;

    j = size / sizeof(uintptr_t);
    remain = size % sizeof(uintptr_t);

    laddr = data;

    for (i = 0; i < j; i ++) {
        memcpy(d.chars, laddr, sizeof(uintptr_t));
        ptrace(PTRACE_POKETEXT, pid, dest, d.val);

        dest  += sizeof(uintptr_t);
        laddr += sizeof(uintptr_t);
    }

    if (remain > 0) {
        d.val = ptrace(PTRACE_PEEKTEXT, pid, dest, 0);
        for (i = 0; i < remain; i ++) {
            d.chars[i] = *laddr ++;
        }

        ptrace(PTRACE_POKETEXT, pid, dest, d.val);
    }

    return 0;
}

uintptr_t injector::ptrace_push(int pid, struct pt_regs *regs, const void* paddr, size_t size) {
    uintptr_t new_sp;
    new_sp = regs->sp;
    new_sp -= size;
    new_sp -= new_sp % 0x10;
    regs->sp = new_sp;
    ptrace_writedata(pid, (uint8_t *)new_sp, (uint8_t *)paddr, size);
    return new_sp;
}

int injector::ptrace_setregs(pid_t pid, struct pt_regs * regs) {
	int regset = NT_PRSTATUS;
	struct iovec ioVec;

	ioVec.iov_base = regs;
	ioVec.iov_len = sizeof(*regs);
    if (ptrace(PTRACE_SETREGSET, pid, regset, &ioVec) < 0) {
        CODE_INJECT_ERR("ptrace_setregs: Can not set register values\n");
        return -1;
    }
    return 0;
}

int injector::ptrace_continue(pid_t pid) {
    if (ptrace(PTRACE_CONT, pid, NULL, 0) < 0) {
        CODE_INJECT_ERR("ptrace_cont\n");
        return -1;
    }
    return 0;
}

int injector::ptrace_call(pid_t pid, uintptr_t addr, uintptr_t *params, int num_params, struct pt_regs* regs) {
    int i;
    int num_param_registers = 8;

    for (i = 0; i < num_params && i < num_param_registers; i ++) {
        regs->regs[i] = params[i];
    }

    if (i < num_params) {
        regs->sp -= (num_params - i) * sizeof(uintptr_t) ;
        ptrace_writedata(pid, (uint8_t *)regs->sp, (uint8_t *)&params[i], (num_params - i) * sizeof(uintptr_t));
    }

    regs->pc = addr;
    if (regs->pc & 1) {
        /* thumb */
        regs->pc &= (~1u);
        regs->pstate |= CPSR_T_MASK;
    } else {
        /* arm */
        regs->pstate &= ~CPSR_T_MASK;
    }

    regs->lr = 0x0;

    if (ptrace_setregs(pid, regs) == -1 || ptrace_continue(pid) == -1) {
        CODE_INJECT_ERR("ptrace continue error\n");
        return -1;
    }

    int sig = wait_for_sigstop();
    if ((sig < 0) || (sig != SIGSEGV)) {
        CODE_INJECT_ERR("wait_for_sigstop failed sig:%d\n", sig);
        return -2;
    }

    return 0;
}

uintptr_t injector::ptrace_retval(struct pt_regs * regs) {
    return regs->regs[0];
}

int injector::ptrace_call_wrapper(pid_t pid, const char * func_name, uintptr_t func_addr, uintptr_t * parameters, int param_num, struct pt_regs * regs) { 
    if (ptrace_call(pid, func_addr, parameters, param_num, regs) == -1) {
        CODE_INJECT_ERR("Calling %s faild!\n", func_name);
        return -1;
    }
    if (ptrace_getregs(regs) == -1) {
        CODE_INJECT_ERR("getregs faild after Calling %s!\n", func_name);
        return -2;
    }
    CODE_INJECT_INFO("Target process returned from %s, return value=%p\n",
            func_name, (void*)ptrace_retval(regs));
    return 0;
}

int injector::dl_remote_func_addr(inject_info &target) {
    int ret;
    struct pt_regs regs;
    uintptr_t parameters[10];
    memcpy(&regs, &ori_regs, sizeof(regs));
    parameters[0] = ptrace_push(target_tid, &regs, target.elf_path.c_str(), target.elf_path.length() + 1);
    parameters[1] = RTLD_NOW | RTLD_GLOBAL;
    CODE_INJECT_INFO("calling dlopen(0x%lx) %s in remote\n", dlopen_addr, target.elf_path.c_str());
    if ((ret = ptrace_call_wrapper(target_tid, "dlopen", dlopen_addr, parameters, 2, &regs))) {
        CODE_INJECT_ERR("ptrace call dlopen failed ret:%d\n", ret);
        return -1;
    }

    void * sohandle = (void *)ptrace_retval(&regs);
    if(!sohandle) {
        CODE_INJECT_ERR("dlopen %s returned NULL!\n", target.elf_path.c_str());
        return -2;
    }

    memcpy(&regs,&ori_regs,sizeof(regs));
    parameters[0] = (uintptr_t)sohandle;
    parameters[1] = (uintptr_t)ptrace_push(target_tid,&regs, target.sym_name.c_str(), target.sym_name.length() + 1);
    CODE_INJECT_INFO("calling dlsym(0x%lx) %s in remote\n", dlsym_addr, target.sym_name.c_str());
    if ((ret = ptrace_call_wrapper(target_tid, "dlsym", dlsym_addr, parameters, 2, &regs))) {
        CODE_INJECT_ERR("ptrace call dlsym %s failed ret:%d\n", target.sym_name.c_str(), ret);
        return -3;
    }

    target.sym_addr = ptrace_retval(&regs);
    CODE_INJECT_INFO("hook_func_addr %s = %p\n", target.sym_name.c_str(), (void*)target.sym_addr);
    return 0;
}

int injector::load_inject_function(inject_info &target) {
    if (!(dlopen_addr && dlsym_addr && dlclose_addr)) {
        CODE_INJECT_ERR("dlopen_addr, dlsym_addr, dlclose_addr must be initialized\n");
        return -1;
    }

    return dl_remote_func_addr(target);
}

int injector::exec_target_inlinehook(inject_info &where, inject_info &code, inject_info &callback, bool helper_mode) {
    int ret;
    struct pt_regs regs;
    uintptr_t parameters[10];
    if (!hooker) {
        CODE_INJECT_ERR("hooker not be initialization\n");
        return -1;
    }
    memcpy(&regs, &ori_regs, sizeof(regs));
    parameters[0] = where.sym_addr;
    if (helper_mode) {
        if (helper)
            parameters[1] = helper->sym_addr;
        else {
            CODE_INJECT_ERR("helper must initialization in helper_mode\n");
            return -2;
        }
    }
    else {
        parameters[1] = code.sym_addr;
    }
    parameters[2] = callback.sym_addr;
    parameters[3] = helper_mode;
    CODE_INJECT_INFO("para: 0x%lx, 0x%lx, 0x%lx, 0x%lx\n", parameters[0], parameters[1], parameters[2], parameters[3]);
    CODE_INJECT_INFO("calling %s in remote\n", hooker->sym_name.c_str());
    if ((ret = ptrace_call_wrapper(target_tid, hooker->sym_name.c_str(), hooker->sym_addr, parameters, 4, &regs))) {
        CODE_INJECT_ERR("ptrace call %s failed ret:%d\n", hooker->sym_name.c_str(), ret);
        return -3;
    }

    return 0;
}

int injector::injector_set_hooker(inject_info &target) {
    if (load_inject_function(target) < 0) {
        CODE_INJECT_ERR("injector inject hooker failed\n");
        return -1;
    }
    hooker = &target;
    return 0;
}

int injector::injector_set_helper(inject_info &target) {
    if (load_inject_function(target) < 0) {
        CODE_INJECT_ERR("injector inject hooker failed\n");
        return -1;
    }
    helper = &target;
    return 0;
}

void injector::set_target_pid(pid_t tid) {
    target_tid = tid;
}

int injector::inline_code_inject(inject_info &where, inject_info &code, bool callback_orgi, bool hook_return, bool helper_mode) {
    int ret;
    struct pt_regs regs;
    uintptr_t parameters[10];
    inject_info cb;

    /*callback original function*/
    if (callback_orgi) {
        if (helper_mode && helper) {
            if (!helper_callback) {
                helper_callback = std::make_shared<inject_info>(helper->elf_path, "helper_callback");
                if (load_inject_function(*helper_callback) < 0) {
                    CODE_INJECT_ERR("injector load target helper_callback failed\n");
                    return -1;
                }
            }
            cb = *helper_callback;
        } else {
            if (!callback) {
                callback = std::make_shared<inject_info>(code.elf_path, "callback");
                if (load_inject_function(*callback) < 0) {
                    CODE_INJECT_ERR("injector load target callback failed\n");
                    return -1;
                }
            }
            cb = *callback;
        }
    } else {
        cb.sym_addr = 0;
    }

    if (exec_target_inlinehook(where, code, cb, helper_mode) < 0) {
        CODE_INJECT_ERR("helper exec_target_inlinehook failed\n");
        return -2;
    }
    if (helper_mode) {
        if (helper) {
            inject_info code_ret(code.elf_path, code.sym_name + "_return");
            if (hook_return) {
                if (load_inject_function(code_ret) < 0) {
                    CODE_INJECT_ERR("load %s_return failed\n", code.sym_name.c_str());
                    return -1;
                }
            } else {
                code_ret.sym_addr = 0;
            }
            /*injector_register*/
            if (!reg.sym_addr) {
                reg.elf_path = helper->elf_path;
                reg.sym_name = "injector_register";
                if (load_inject_function(reg) < 0) {
                    CODE_INJECT_ERR("load %s failed\n", reg.sym_name.c_str());
                    return -2;
                }
            }
            memcpy(&regs, &ori_regs, sizeof(regs));
            parameters[0] = where.sym_addr;
            parameters[1] = cb.sym_addr;
            parameters[2] = code.sym_addr;
            parameters[3] = code_ret.sym_addr;
            parameters[4] = (uintptr_t)ptrace_push(target_tid,&regs, where.sym_name.c_str(), where.sym_name.length() + 1);
            CODE_INJECT_INFO("calling %s in remote\n", reg.sym_name.c_str());
            if ((ret = ptrace_call_wrapper(target_tid, reg.sym_name.c_str(), reg.sym_addr, parameters, 5, &regs))) {
                CODE_INJECT_ERR("ptrace call %s failed ret:%d\n", reg.sym_name.c_str(), ret);
                return -3;
            }
        } else {
            CODE_INJECT_ERR("helper must initialization in helper_mode\n");
            return -4;
        }
    }
    return 0;
}

int injector::injector_prepare(pid_t tid, inject_info &hooker, bool helper_mode, inject_info &hook_helper) {
    set_target_pid(tid);
    if (attach_thread()) {
        CODE_INJECT_ERR("attach thread %d failed\n", tid);
        return 1;
    }
    if (injector_set_hooker(hooker) < 0) {
        CODE_INJECT_ERR("injector_set_hooker failed\n");
        return -2;
    }
    if (helper_mode) {
        if (injector_set_helper(hook_helper) < 0) {
            CODE_INJECT_ERR("injector_set_helper failed\n");
            return -3;
        }
    }

    return 0;
}

int injector::injector_register(inject_info &inject, inject_info &target, bool callback_orgi, bool hook_return, bool helper_mode) {
    if (load_inject_function(target) < 0) {
        CODE_INJECT_ERR("injector inject target failed\n");
        return -1;
    }

    if (inline_code_inject(inject, target, callback_orgi, hook_return, helper_mode) < 0) {
        CODE_INJECT_ERR("inline_code_inject failed\n");
        return -2;
    }
    return 0;
}

int injector::injector_finish() {
    if (detach_thread()) {
        CODE_INJECT_ERR("detach thread %d failed\n", target_tid);
        return -1;
    }
    return 0;
}

int injector::injector_register_full(pid_t tid, inject_info &inject, inject_info &target, bool callback_orgi, bool hook_return, bool helper_mode) {
    if (!inject.get_reloc_addr(tid)) {
        CODE_INJECT_ERR("injector get runtime inject address failed\n");
        return -1;
    }
    set_target_pid(tid);
    if (attach_thread()) {
        CODE_INJECT_ERR("attach thread %d failed\n", tid);
        return -2;
    }
    if (injector_register(inject, target, callback_orgi, hook_return, helper_mode) < 0) {
        CODE_INJECT_ERR("injector_register %d failed\n", tid);
    }

    if (detach_thread()) {
        CODE_INJECT_ERR("detach thread %d failed\n", tid);
        return -3;
    }

    return 0;
}
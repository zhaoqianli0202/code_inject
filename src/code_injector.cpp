#include <bits/types/struct_timeval.h>
#include <bits/types/time_t.h>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <sstream>
#include <sys/select.h>
#include "arm64_inlinehook.h"
#include "inject_info.h"
#include "injector.h"
extern "C" {
#include <stdlib.h>
#include <stdio.h>
#include <string>
#include <unistd.h>
#include <fcntl.h>
}

void show_help() {

}

int set_fifo_policy() {
    int policy = SCHED_FIFO;
    struct sched_param param;
    if (sched_getparam(0, &param) == -1) {
        CODE_INJECT_ERR("sched_getparam failed\n");
        return -1;
    }

    param.sched_priority = 99;

    if (sched_setscheduler(0, policy, &param) == -1) {
        CODE_INJECT_ERR("sched_setscheduler failed\n");
        return -2;
    }
    return 0;
}

int main(int argc, char *argv[]) {
    int opt;
    pid_t pid = -1;
    char *sub_command = nullptr;
    bool helper_mode = false;
    bool callback_orgi = false;
    bool hook_return = false;
    inject_info inject;
    inject_info target;
    inject_info hooker("/map/inject/libcode_inject.so", "A64HookFunction");
    inject_info hook_helper("/map/inject/libhook_helper.so", "inject_entry");

    while ((opt = getopt(argc, argv, "rop:i:t:sc:e:")) != -1) {
        switch(opt) {
            case 'p':
                pid = strtoul(optarg, nullptr, 10);
            break;
            case 'i':
                if (inject.parse_inject_info(optarg)) {
                    show_help();
                    return -1;
                }
                CODE_INJECT_INFO("Inject code to 0x%lx in %s\n", inject.sym_addr, inject.elf_path.c_str());
            break;
            case 't':
                if (target.parse_inject_info(optarg)) {
                    show_help();
                    return -2;
                }
                CODE_INJECT_INFO("Code 0x%lx in %s will injected\n", target.sym_addr, target.elf_path.c_str());
            break;
            case 'k':
                if (hooker.parse_inject_info(optarg)) {
                    show_help();
                    return -3;
                }
                CODE_INJECT_INFO("Injector 0x%s function %s is parsed\n", hooker.elf_path.c_str(), hooker.sym_name.c_str());
            break;
            case 's':
                helper_mode = true;
            break;
            case 'c':
                sub_command = optarg;
            break;
            case 'e':
                if (hook_helper.parse_inject_info(optarg)) {
                    show_help();
                    return -4;
                }
                CODE_INJECT_INFO("Hook helper 0x%s function %s is parsed\n", hooker.elf_path.c_str(), hooker.sym_name.c_str());
            break;
            case 'o':
                callback_orgi = true;
            break;
            case 'r':
                hook_return = true;
            break;
            case 'h':
            default:
                show_help();
            break;
        }
    }
    if (!sub_command) {
        if (set_fifo_policy() < 0) {
            CODE_INJECT_ERR("set hooker policy failed\n");
            return -1;
        }
    }

    if (!inject.get_reloc_addr(pid)) {
        CODE_INJECT_ERR("injector get runtime inject address failed\n");
        return -4;
    }
    struct timeval start, end;
    gettimeofday(&start, NULL);
    injector inj(pid);
    if (inj.attach_thread()) {
        CODE_INJECT_ERR("attach thread %d failed\n", pid);
        return -5;
    }

    if (inj.load_inject_function(hooker) < 0) {
        CODE_INJECT_ERR("injector inject hooker failed\n");
        goto detach;
    }
    inj.hooker = &hooker;
    if (helper_mode) {
        if (inj.load_inject_function(hook_helper) < 0) {
            CODE_INJECT_ERR("injector inject hooker failed\n");
            goto detach;
        }
        inj.helper = &hook_helper;
    }
    if (inj.load_inject_function(target) < 0) {
        CODE_INJECT_ERR("injector inject target failed\n");
        goto detach;
    }

    if (inj.injector_register(inject, target, callback_orgi, hook_return, helper_mode) < 0) {
        CODE_INJECT_ERR("injector_register failed\n");
        goto detach;
    }

detach:
    if (inj.detach_thread()) {
        CODE_INJECT_ERR("detach thread %d failed\n", pid);
        return -6;
    }
    gettimeofday(&end, NULL);
    CODE_INJECT_INFO("Code inject spend %ld us\n", ((end.tv_sec - start.tv_sec)*1000*1000) + (end.tv_usec - start.tv_usec));
    return 0;
}

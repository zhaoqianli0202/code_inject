#include <bits/types/struct_timeval.h>
#include <bits/types/time_t.h>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <pthread.h>
#include <sstream>
#include <sys/select.h>
#include <sys/wait.h>
#include <iostream>
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
    std::cout << "Code_injector for runtime code inject" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "\t-p $TARGET_PID, target process pid for runtime inject" << std::endl;
    std::cout << "\t-i elf_file_path:func_name/hex_addr, code injection point, e.g. /home/inject/test.elf(.so):_Z5funcci" << std::endl;
    std::cout << "\t-t elf_file_path:func_name/hex_addr, the code to be injected, e.g. /home/inject/sample_patch.so:_Z10funcc_hooki" << std::endl;
    std::cout << "\t-k elf_file_path:func_name/hex_addr, injector location, default: /home/inject/libcode_inject.so:A64HookFunction" << std::endl;
    std::cout << "\t-s, Enable helper mode, use hook_helper to inject code" << std::endl;
    std::cout << "\t-e elf_file_path:func_name/hex_addr, helper library location, e.g. /home/inject/libhook_helper.so:inject_entry" << std::endl;
    std::cout << "\t-c, command mode, Starting a program through code_injector, code will be injected before program startup, e.g. code_injector -c \"./test.elf\"" << std::endl;
    std::cout << "\t-o, Callback original function, original code will be executed before the function returns" << std::endl;
    std::cout << "\t-r, hook_return mode, in helper mode, helper will inject a return function after injection function return" << std::endl;
    std::cout << "\t-j, json config mode, code_injector will parser json to translate into injection instructions for batch injection" << std::endl;
    std::cout << "\t-h, show help" << std::endl;
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
    pid_t pid = 0;
    struct timeval start, end;
    char *sub_command = nullptr;
    bool helper_mode = false;
    bool orgi_callback = false;
    bool hook_return = false;
    char *config_json = nullptr;
    subcmd_control subc;
    inject_info inject;
    inject_info target;
    inject_info hooker("/map/inject/libcode_inject.so", "A64HookFunction");
    inject_info hook_helper("/map/inject/libhook_helper.so", "inject_entry");

    while ((opt = getopt(argc, argv, "j:rop:i:t:sc:e:")) != -1) {
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
                CODE_INJECT_INFO("Sub command mode: %s\n", sub_command);
            break;
            case 'e':
                if (hook_helper.parse_inject_info(optarg)) {
                    show_help();
                    return -4;
                }
                CODE_INJECT_INFO("Hook helper 0x%s function %s is parsed\n", hooker.elf_path.c_str(), hooker.sym_name.c_str());
            break;
            case 'o':
                orgi_callback = true;
            break;
            case 'r':
                hook_return = true;
            break;
            case 'j':
                config_json = optarg;
            break;
            case 'h':
            default:
                show_help();
            return -1;
        }
    }

    if (!sub_command) {
        if (set_fifo_policy() < 0) {
            CODE_INJECT_ERR("set hooker policy failed\n");
            return -1;
        }
    } else {
        pid = subc.exec_child_cmd(sub_command, hook_helper.elf_path.c_str());
        if (pid <= 0) {
            CODE_INJECT_ERR("exec_child_cmd failed\n");
            return -2;
        }
        if (subc.wait_child_ready() < 0) {
            CODE_INJECT_ERR("wait_child_ready failed\n");
            goto waitchild;
        }
    }

    if (config_json) {
        try {
            inject_parser parser(config_json);
            if (!parser.parse_inject_config()) {
                CODE_INJECT_ERR("parse inject config file:%s failed\n", config_json);
                return -2;
            }
            if (sub_command)
                parser.pid = subc.child_pid;
            injector inj(parser.pid);
            if (inj.injector_prepare(parser.pid, inject, hooker, true, hook_helper) > 0) {
                CODE_INJECT_ERR("injector_prepare failed\n");
                return -3;
            }
            if (inj.injector_finish() < 0) {
                CODE_INJECT_ERR("injector_finish failed\n");
                return -4;
            }
            for (auto t : parser.targets) {
                gettimeofday(&start, NULL);
                if (t->inject.parse_inject_info(t->inject.elf_path + ":" + t->inject.sym_name)) {
                    CODE_INJECT_ERR("parse inejct info failed\n");
                    return -5;
                }
                if (inj.injector_register_full(sub_command ? subc.child_pid : t->tid,
                                                t->inject, t->target, t->orgi_callback, t->hook_return, t->helper_mode) < 0) {
                    CODE_INJECT_ERR("injector_register inject:%s:%s, target:%s:%s failed\n", t->inject.elf_path.c_str(), t->inject.sym_name.c_str(), t->target.elf_path.c_str(), t->target.sym_name.c_str());
                    return -6;
                }
                gettimeofday(&end, NULL);
                CODE_INJECT_INFO("Code %s:%s inject %s:%s spend %ld us\n", t->inject.elf_path.c_str(), t->inject.sym_name.c_str(),
                                    t->target.elf_path.c_str(), t->target.sym_name.c_str(), ((end.tv_sec - start.tv_sec)*1000*1000) + (end.tv_usec - start.tv_usec));
            }
        } catch (const std::exception& e) {
            CODE_INJECT_ERR("json file %s format wrong\n", config_json);
            return -1;
        }
    } else {
        if (!pid) {
            CODE_INJECT_ERR("Injector must set pid in online mode\n");
            show_help();
            return -7;
        }
        injector inj(pid);
        gettimeofday(&start, NULL);
        if (!inject.get_reloc_addr(pid)) {
            CODE_INJECT_ERR("injector get runtime inject address failed\n");
            return -8;
        }
        if (!inj.injector_prepare(pid, inject, hooker, helper_mode, hook_helper)) {
            inj.injector_register(inject, target, orgi_callback, hook_return, helper_mode);
        }
        inj.injector_finish();
        gettimeofday(&end, NULL);
        CODE_INJECT_INFO("Code %s:%s inject %s:%s spend %ld us\n", inject.elf_path.c_str(), inject.sym_name.c_str(),
                            target.elf_path.c_str(), target.sym_name.c_str(), ((end.tv_sec - start.tv_sec)*1000*1000) + (end.tv_usec - start.tv_usec));
    }

    if (sub_command) {
        if (subc.finish_inject() < 0)
            CODE_INJECT_ERR("finish_inject failed\n");
    }

waitchild:
    if (sub_command && pid) {
        if (waitpid(pid, NULL, 0) < 0) {
            CODE_INJECT_ERR("Wait child:%d failed\n", pid);
            return -1;
        }
    }

    return 0;
}

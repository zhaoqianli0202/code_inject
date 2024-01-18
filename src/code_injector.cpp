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
        printf("sched_getparam failed\n");
        return -1;
    }

    param.sched_priority = 99;

    if (sched_setscheduler(0, policy, &param) == -1) {
        perror("sched_setscheduler failed\n");
        return -2;
    }
    return 0;
}

int main(int argc, char *argv[]) {
    int opt;
    inject_info inject, target, callback;
    pid_t pid = -1;
    char *sub_command = nullptr;
    bool callback_mode = true;
    inject_info hooker = {
        .elf_path = "/map/inject/libcode_inject.so",
        .sym_name = "A64HookFunction",
    };

    while ((opt = getopt(argc, argv, "p:i:t:jc:")) != -1) {
        switch(opt) {
            case 'p':
                pid = strtoul(optarg, nullptr, 10);
            break;
            case 'i':
                if (inject.parse_inject_info(optarg)) {
                    show_help();
                    return -1;
                }
                printf("Inject code to 0x%lx in %s\n", inject.sym_addr, inject.elf_path.c_str());
            break;
            case 't':
                if (target.parse_inject_info(optarg)) {
                    show_help();
                    return -2;
                }
                printf("Code 0x%lx in %s will injected\n", target.sym_addr, target.elf_path.c_str());
            break;
            case 'k':
                if (hooker.parse_inject_info(optarg)) {
                    show_help();
                    return -3;
                }
                printf("Injector 0x%s function %s is parsed\n", hooker.elf_path.c_str(), hooker.sym_name.c_str());
            break;
            case 'j':
                callback_mode = false;
            break;
            case 'c':
                sub_command = optarg;
            break;
            case 'h':
            default:
                show_help();
            break;
        }
    }
    if (!sub_command) {
        if (set_fifo_policy() < 0) {
            printf("set hooker policy failed\n");
            return -1;
        }
    }

    if (!inject.get_reloc_addr(pid)) {
        printf("injector get runtime inject address failed\n");
        return -4;
    }
    struct timeval start, end;
    gettimeofday(&start, NULL);
    injector inj(pid);
    if (inj.attach_thread()) {
        printf("attach thread %d failed\n", pid);
        return -5;
    }
    if (inj.load_inject_function(hooker) < 0) {
        printf("injector inject hooker failed\n");
        goto detach;
    }
    if (inj.load_inject_function(target) < 0) {
        printf("injector load_target_function failed\n");
        goto detach;
    }
    if (callback_mode) {
        callback.elf_path = target.elf_path;
        callback.sym_name = "callback";
        if (inj.load_inject_function(callback) < 0) {
            printf("injector load target callback failed\n");
            goto detach;
        }
    } else {
        callback.sym_addr = 0;
    }
    if (inj.exec_target_inlinehook(inject, target, hooker, callback) < 0) {
        printf("exec_target_inlinehook failed\n");
        goto detach;
    }

detach:
    if (inj.detach_thread()) {
        printf("detach thread %d failed\n", pid);
        return -6;
    }
    gettimeofday(&end, NULL);
    printf("Code inject spend %ld us\n", ((end.tv_sec - start.tv_sec)*1000*1000) + (end.tv_usec - start.tv_usec));
    return 0;
}

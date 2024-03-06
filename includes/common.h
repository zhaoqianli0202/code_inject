#pragma once
#include <cstdint>
#include <libelf.h>
#include <gelf.h>
#include <sstream>
#include <fstream>
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

#define INJECT_TIMEOUT_SECOND (5)

#define INJ_IPC_PATH_SER(pid)    ((("/tmp/inject_ipc_ser_" + std::to_string(pid))).c_str())
#define INJ_IPC_PATH_CLIENT(pid) ((("/tmp/inject_ipc_client_" + std::to_string(pid))).c_str())

#define CODE_INJECT_ERR(fmt, ...) printf("[INJECTOR]-[ERR]" fmt, ##__VA_ARGS__)
#define CODE_INJECT_INFO(fmt, ...) printf("[INJECTOR]-[INFO]" fmt, ##__VA_ARGS__)
#define CODE_INJECT_WARN(fmt, ...) printf("[INJECTOR]-[WARN]" fmt, ##__VA_ARGS__)

// #define DEBUG
#ifdef DEBUG
    #define CODE_INJECT_DBG(fmt, ...) printf("[DBG]" fmt, ##__VA_ARGS__)
#else
    #define CODE_INJECT_DBG(fmt, ...)
#endif

#include "log.h"
// #define DEBUG_HELPER
#define HOOK_HELPER_ERR(fmt, ...) ALOGE(fmt, ##__VA_ARGS__)
#define HOOK_HELPER_INFO(fmt, ...) ALOGI(fmt, ##__VA_ARGS__)
#define HOOK_HELPER_WARN(fmt, ...) ALOGW(fmt, ##__VA_ARGS__)

#ifdef DEBUG_HELPER
    #define HOOK_HELPER_DBG(fmt, ...) ALOGD("[HELPER]" fmt, ##__VA_ARGS__)
#else
    #define HOOK_HELPER_DBG(fmt, ...)
#endif
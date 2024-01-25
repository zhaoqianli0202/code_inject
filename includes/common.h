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

#define CODE_INJECT_ERR(fmt, ...) printf("[ERR]" fmt, ##__VA_ARGS__)
#define CODE_INJECT_INFO(fmt, ...) printf("[INFO]" fmt, ##__VA_ARGS__)
#define CODE_INJECT_WARN(fmt, ...) printf("[WARN]" fmt, ##__VA_ARGS__)

#ifdef DEGBUG
#define CODE_INJECT_DBG(fmt, ...) printf("[DBG]" fmt, ##__VA_ARGS__)
#else
#define CODE_INJECT_DBG(fmt, ...)
#endif
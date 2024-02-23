#pragma once
#include "../hook_helper/hook_helper.h"
#include <atomic>
#include <bits/types/struct_timeval.h>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <sched.h>
#include <unordered_map>

/*
PERF_GROUP_MODE: three functions spend 1.5ms+, about 500us+ every function
Not PERF_GROUP_MODE: three functions spend 2.7ms+, about 900us+ every function
*/
#define PERF_GROUP_MODE
// #define DEBUG
#define PERF_LOG_ERR(fmt, ...) printf("[PROFILE]-[ERR]" fmt, ##__VA_ARGS__)
#define PERF_LOG_INFO(fmt, ...) printf("[PROFILE]-[INFO]" fmt, ##__VA_ARGS__)
#ifdef DEBUG
  #define PERF_LOG_DBG(fmt, ...) printf("[PROFILE]-[DBG]" fmt, ##__VA_ARGS__)
#else
  #define PERF_LOG_DBG(fmt, ...)
#endif

#define OUT_FILE_NAME "/tmp/perf_profile_tid_"
#define PERF_PROFILE_HEADER "PROFILE_HEADER"
#define PERF_PROFILE_TEXT "PROFILE_TEXT"
#define NAME_MAX_LEN (32)

#define PERF_GROUP_LEADER (0)
#define DEF_HW_CACHE_ACCESS (PERF_COUNT_HW_CACHE_OP_READ << 8 | PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16)
#define DEF_HW_CACHE_MISS (PERF_COUNT_HW_CACHE_OP_READ << 8 | PERF_COUNT_HW_CACHE_RESULT_MISS << 16)
#define PERF_VENDOR_TYPE (0x8)
#define PERF_L2D_LOAD (0x16)
#define PERF_L2D_REFILL (0x17)
#define PERF_L3D_LOAD (0x2b)
#define PERF_L3D_REFILL (0x2a)

struct perf_events {
    char event_name[NAME_MAX_LEN];
    int fd;
    uint64_t perf_id;
    struct perf_event_attr attr;
};

/*group mode only support 6 hardware events(a53 6*pmu)*/
struct perf_events def_attrs[] = {
#ifndef PERF_GROUP_MODE
    { "instructions", .fd = 0,  .attr{.type = PERF_TYPE_HARDWARE, .config = PERF_COUNT_HW_INSTRUCTIONS}},
    { "l2d_cache", .fd = 0,  .attr{.type = PERF_VENDOR_TYPE, .config = PERF_L2D_LOAD}},
    { "l2d_cache_refill", .fd = 0,  .attr{.type = PERF_VENDOR_TYPE, .config = PERF_L2D_REFILL}},
    { "l3d_cache", .fd = 0, .attr{.type = PERF_VENDOR_TYPE, .config = PERF_L3D_LOAD}},
    { "l3d_cache_refill", .fd = 0, .attr{.type = PERF_VENDOR_TYPE, .config = PERF_L3D_REFILL}},
    { "LLC-load-misses", .fd = 0,  .attr{.type = PERF_TYPE_HW_CACHE, .config = PERF_COUNT_HW_CACHE_LL | DEF_HW_CACHE_MISS}},
    { "LLC-loads", .fd = 0, .attr{.type = PERF_TYPE_HW_CACHE, .config = PERF_COUNT_HW_CACHE_LL | DEF_HW_CACHE_ACCESS}},
    { "iTLB-load-misses", .fd = 0, .attr{.type = PERF_TYPE_HW_CACHE, .config = PERF_COUNT_HW_CACHE_ITLB | DEF_HW_CACHE_MISS}},
    { "iTLB-loads", .fd = 0, .attr{.type = PERF_TYPE_HW_CACHE, .config = PERF_COUNT_HW_CACHE_ITLB | DEF_HW_CACHE_ACCESS}},
    { "dTLB-load-misses", .fd = 0, .attr{.type = PERF_TYPE_HW_CACHE, .config = PERF_COUNT_HW_CACHE_DTLB | DEF_HW_CACHE_MISS}},
    { "dTLB-loads", .fd = 0, .attr{.type = PERF_TYPE_HW_CACHE, .config = PERF_COUNT_HW_CACHE_DTLB | DEF_HW_CACHE_ACCESS}},
#endif
    { "context-switches", .fd = 0, .attr{.type = PERF_TYPE_SOFTWARE, .config = PERF_COUNT_SW_CONTEXT_SWITCHES}},
    { "migrations", .fd = 0, .attr{.type = PERF_TYPE_SOFTWARE, .config = PERF_COUNT_SW_CPU_MIGRATIONS}},
    { "page-faults", .fd = 0, .attr{.type = PERF_TYPE_SOFTWARE, .config = PERF_COUNT_SW_PAGE_FAULTS}},
    { "cycles", .fd = 0, .attr{.type = PERF_TYPE_HARDWARE, .config = PERF_COUNT_HW_CPU_CYCLES}},/*not pmu event*/
    { "L1-dcache-load-misses", .fd = 0,  .attr{.type = PERF_TYPE_HW_CACHE, .config = PERF_COUNT_HW_CACHE_L1D | DEF_HW_CACHE_MISS}},
    { "L1-dcache-loads", .fd = 0,  .attr{.type = PERF_TYPE_HW_CACHE, .config = PERF_COUNT_HW_CACHE_L1D | DEF_HW_CACHE_ACCESS}},
    { "L1-icache-load-misses", .fd = 0,  .attr{.type = PERF_TYPE_HW_CACHE, .config = PERF_COUNT_HW_CACHE_L1I | DEF_HW_CACHE_MISS}},
    { "L1-icache-loads", .fd = 0,  .attr{.type = PERF_TYPE_HW_CACHE, .config = PERF_COUNT_HW_CACHE_L1I | DEF_HW_CACHE_ACCESS}},
    { "branch-misses", .fd = 0, .attr{.type = PERF_TYPE_HARDWARE, .config = PERF_COUNT_HW_BRANCH_MISSES}},
    { "branches", .fd = 0, .attr{.type = PERF_TYPE_HARDWARE, .config = PERF_COUNT_HW_BRANCH_INSTRUCTIONS}}
};

#ifdef PERF_GROUP_MODE
struct read_format {
  uint64_t nr;
  struct {
    uint64_t value;
    uint64_t id;
  } values[sizeof(def_attrs)/sizeof(struct perf_events)];
  struct timeval time;
};
#else
struct read_format {
    struct {
      uint64_t  value;
      uint64_t id;
    } values[sizeof(def_attrs)/sizeof(struct perf_events)];
    uint64_t nr;
    struct timeval time;
};
#endif
struct output_format {
  char func_name[32];
  int depth;
  struct read_format rf;
  uint64_t during_us;
};

class perf_profile {
public:
    perf_profile();
    int idx;
    pid_t tid;
    struct perf_events *evts;
    struct read_format rf_stack[MAX_STACK_DEPTH];
    std::unordered_map<uint64_t, struct perf_events *> perf_id_map;/*<perf_id, perf_events>*/
    std::ofstream outfile;
};
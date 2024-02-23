#include "perf_profile.h"
#include <bits/types/struct_timeval.h>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <sys/select.h>
#include <unistd.h>
#include <syscall.h>
#include <sys/ioctl.h>
#include <sys/time.h>
perf_profile perf;
perf_profile::perf_profile() : idx(0), tid(-1), evts(def_attrs) {
    memset(rf_stack, 0, sizeof(rf_stack));
}

static int enable_perf_profile() {
    int ret;
    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(struct perf_event_attr));
    attr.size = sizeof(struct perf_event_attr);
    attr.disabled = 1;
#ifdef PERF_GROUP_MODE
    attr.read_format = PERF_FORMAT_GROUP | PERF_FORMAT_ID;
#else
    attr.read_format = PERF_FORMAT_ID;
#endif
    for (uint64_t i = 0; i < sizeof(def_attrs)/sizeof(struct perf_events); i++) {
        PERF_LOG_INFO("enable_perf_profile event:%s, type=%d, config=%lld\n", def_attrs[i].event_name, attr.type, attr.config);
        attr.type = def_attrs[i].attr.type;
        attr.config = def_attrs[i].attr.config;
        // perf.evts[i].event_name = def_attrs[i].event_name;
        memcpy(perf.evts[i].event_name, def_attrs[i].event_name, sizeof(def_attrs[i].event_name));
#ifdef PERF_GROUP_MODE
        perf.evts[i].fd = syscall(__NR_perf_event_open, &attr, 0, -1, (i == PERF_GROUP_LEADER) ? -1 : perf.evts[PERF_GROUP_LEADER].fd, PERF_FLAG_FD_CLOEXEC);
#else
        perf.evts[i].fd = syscall(__NR_perf_event_open, &attr, 0, -1, -1, PERF_FLAG_FD_CLOEXEC);
#endif
        if (perf.evts[i].fd < 0) {
            PERF_LOG_ERR("Error opening event \"%s\", ret:%d\n", perf.evts[i].event_name, perf.evts[i].fd);
            ret = perf.evts[i].fd;
            goto err;
        }
        ioctl(perf.evts[i].fd, PERF_EVENT_IOC_ID, &perf.evts[i].perf_id);
#ifndef PERF_GROUP_MODE
        ioctl(perf.evts[i].fd, PERF_EVENT_IOC_RESET, 0);
#endif
        perf.perf_id_map[perf.evts[i].perf_id] = &perf.evts[i];
        PERF_LOG_DBG("event_name:%s, fd:%d, perf_id:%lu\n", def_attrs[i].event_name, perf.evts[i].fd, perf.evts[i].perf_id);
    }
#ifdef PERF_GROUP_MODE
    ioctl(perf.evts[PERF_GROUP_LEADER].fd, PERF_EVENT_IOC_RESET, PERF_IOC_FLAG_GROUP);
#endif
    perf.tid = (pid_t)syscall(SYS_gettid);

    return 0;

err:
#ifdef PERF_GROUP_MODE
    if (perf.evts[PERF_GROUP_LEADER].fd > 0)
        ioctl(perf.evts[PERF_GROUP_LEADER].fd, PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP);
#endif
    for (uint64_t i = 0; i < sizeof(def_attrs)/sizeof(struct perf_events); i++) {
        if (perf.evts[i].fd > 0) {
#ifndef PERF_GROUP_MODE
            ioctl(perf.evts[i].fd, PERF_EVENT_IOC_DISABLE, 0);
#endif
            close(perf.evts[i].fd);
        }
    }

    return ret;
}

extern "C"
uint64_t perf_profile(struct hooker_regs *regs, char *hook_func_name) {
    if (perf.evts[PERF_GROUP_LEADER].fd < 0) {
        PERF_LOG_ERR("perf_profile fd not available\n");
        return -1;
    }
    pid_t tid = (pid_t)syscall(SYS_gettid);
    if (perf.tid == -1) {
        if (enable_perf_profile() < 0) {
            PERF_LOG_ERR("enable_perf_profile failed\n");
            return -2;
        }
        std::string file_name = OUT_FILE_NAME + std::to_string(tid);
        perf.outfile.rdbuf()->pubsetbuf(0, 0);
        perf.outfile.open(file_name.c_str(), std::ios::trunc | std::ios::out | std::ios::binary);
        if (!perf.outfile.is_open()) {
            PERF_LOG_ERR("Open %s file failed\n", file_name.c_str());
            return -3;
        }
        perf.outfile.write(PERF_PROFILE_HEADER, strlen(PERF_PROFILE_HEADER) + 1);
        for (auto evts : perf.perf_id_map) {
            perf.outfile.write(evts.second->event_name, sizeof(evts.second->event_name));
            perf.outfile.write(reinterpret_cast<char *>(&evts.second->perf_id), sizeof(uint64_t));
        }
        char text[NAME_MAX_LEN] = PERF_PROFILE_TEXT;
        perf.outfile.write(text, NAME_MAX_LEN);
        perf.outfile.write((char *)&tid, sizeof(uint64_t));
    }
    struct read_format* rf = (struct read_format*)&perf.rf_stack[perf.idx++];
    if (perf.tid != tid) {
        PERF_LOG_ERR("current:%d, but profile is %d\n", perf.tid, tid);
        return -4;
    }
#ifdef PERF_GROUP_MODE
    ioctl(perf.evts[PERF_GROUP_LEADER].fd, PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP);
    if (read(perf.evts[PERF_GROUP_LEADER].fd, rf, sizeof(struct read_format)) <= 0) {
        PERF_LOG_ERR("perf_profile read failed\n");
        ioctl(perf.evts[PERF_GROUP_LEADER].fd, PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP);
        return -5;
    }
    ioctl(perf.evts[PERF_GROUP_LEADER].fd, PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP);
#else
    rf->nr = sizeof(def_attrs)/sizeof(struct perf_events);
    for (uint64_t i = 0; i < sizeof(def_attrs)/sizeof(struct perf_events); i++) {
        ioctl(perf.evts[i].fd, PERF_EVENT_IOC_DISABLE, 0);
    }
    for (uint64_t i = 0; i < rf->nr; i++) {
        if (read(perf.evts[i].fd, &rf->values[i], sizeof(rf->values[i])) <= 0) {
            PERF_LOG_ERR("perf_profile read failed\n");
            continue;
        }
    }
    for (uint64_t i = 0; i < sizeof(def_attrs)/sizeof(struct perf_events); i++) {
        ioctl(perf.evts[i].fd, PERF_EVENT_IOC_ENABLE, 0);
    }
#endif
#ifdef DEBUG
    PERF_LOG_DBG("==========function %s start:%ld==========rf->nr=%lu\n", hook_func_name, (rf->time.tv_sec * 1000000) + rf->time.tv_usec, rf->nr);
    for (uint64_t i = 0 ; i < rf->nr; i++) {
        PERF_LOG_DBG("%s entry perf id:%ld, event:%s, value:%ld\n", hook_func_name, rf->values[i].id, perf.perf_id_map[rf->values[i].id]->event_name, rf->values[i].value);
    }
#endif
    gettimeofday(&rf->time, NULL);

    return 0;
}

extern "C"
uint64_t perf_profile_return(struct hooker_regs *regs, char *hook_func_name) {
    struct read_format rf;
    struct output_format output;
    struct timeval current;

    gettimeofday(&current, NULL);
    if (perf.evts[PERF_GROUP_LEADER].fd < 0) {
        PERF_LOG_ERR("perf_profile_return fd not available\n");
        return -1;
    }
    if (perf.tid != (pid_t)syscall(SYS_gettid)) {
        PERF_LOG_ERR("perf_profile_return current:%d, but profile is %d\n", perf.tid, (pid_t)syscall(SYS_gettid));
        return -2;
    }
#ifdef PERF_GROUP_MODE
    ioctl(perf.evts[PERF_GROUP_LEADER].fd, PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP);
    if (read(perf.evts[PERF_GROUP_LEADER].fd, &rf, sizeof(struct read_format)) <= 0) {
        PERF_LOG_ERR("perf_profile_return read failed\n");
        ioctl(perf.evts[PERF_GROUP_LEADER].fd, PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP);
        return -3;
    }
#else
    rf.nr = sizeof(def_attrs)/sizeof(struct perf_events);
    for (uint64_t i = 0; i < sizeof(def_attrs)/sizeof(struct perf_events); i++) {
        ioctl(perf.evts[i].fd, PERF_EVENT_IOC_DISABLE, 0);
    }
    for (uint64_t i = 0; i < rf.nr; i++) {
        if (read(perf.evts[i].fd, &rf.values[i], sizeof(rf.values[i])) <= 0) {
            PERF_LOG_ERR("perf_profile read failed\n");
            continue;
        }
    }
#endif
#ifdef DEBUG
        for (uint64_t i = 0 ; i < rf.nr; i++) {
            PERF_LOG_DBG("%s return perf id:%ld, event:%s, value:%ld\n", hook_func_name, rf.values[i].id, perf.perf_id_map[rf.values[i].id]->event_name, rf.values[i].value);
        }
#endif

    perf.idx--;
    for (uint64_t i = 0; i < rf.nr; i++) {
        if (i == perf.rf_stack[perf.idx].values[i].id) {
            output.rf.values[i].value = rf.values[i].value - perf.rf_stack[perf.idx].values[i].value;
        } else {
            for (uint64_t j = 0; j < rf.nr; j++) {
                if (rf.values[i].id == perf.rf_stack[perf.idx].values[j].id) {
                    output.rf.values[i].value = rf.values[i].value - perf.rf_stack[perf.idx].values[j].value;
                }
            }
        }
        output.rf.values[i].id = rf.values[i].id;
    }
    output.depth = perf.idx;
    output.rf.nr = rf.nr;
    output.rf.time = perf.rf_stack[perf.idx].time;
    strncpy(output.func_name, hook_func_name, sizeof(output.func_name) - 1);
    output.during_us = 1000000 * (current.tv_sec - perf.rf_stack[perf.idx].time.tv_sec) + current.tv_usec - perf.rf_stack[perf.idx].time.tv_usec;
    perf.outfile.write(reinterpret_cast<char *>(&output), sizeof(output));
#ifdef DEBUG
    PERF_LOG_DBG("==========function %s during:%ld us==========\n", hook_func_name, output.during_us);
    for (uint64_t i = 0 ; i < rf.nr; i++) {
        PERF_LOG_DBG("event:%s, value:%ld\n", perf.perf_id_map[output.rf.values[i].id]->event_name, output.rf.values[i].value);
    }
#endif
#ifdef PERF_GROUP_MODE
    ioctl(perf.evts[PERF_GROUP_LEADER].fd, PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP);
#else
    for (uint64_t i = 0; i < sizeof(def_attrs)/sizeof(struct perf_events); i++) {
        ioctl(perf.evts[i].fd, PERF_EVENT_IOC_ENABLE, 0);
    }
#endif
    return 0;
}
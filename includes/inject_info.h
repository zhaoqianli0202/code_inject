#pragma once
#include "common.h"
#include <json/json.h>
#include <memory>
#include <sched.h>
#include <string>
#include <vector>

class inject_info {
private:
    bool parse_symbol_addr();
    bool find_symbol_addr();

public:
    std::string elf_path;
    std::string sym_name;
    uintptr_t sym_addr;
    inject_info() {};
    inject_info(const std::string &path, const std::string &name, uintptr_t addr = 0) : elf_path(path), sym_name(name), sym_addr(addr) {}
    static uintptr_t get_module_base(pid_t pid, const std::string &module_name);
    int parse_inject_info(const std::string &info);
    uintptr_t get_reloc_addr(pid_t pid);
};

class inject_point {
public:
    inject_point() : helper_mode(false), orgi_callback(false), hook_return(false) {}
    inject_info target;
    inject_info inject;
    pid_t tid;
    bool helper_mode;
    bool orgi_callback;
    bool hook_return;
};

class inject_parser {
private:
    Json::Value search_key(Json::Value &root, const std::string &key);
    Json::Value root;
    std::string config_file;
public:
    pid_t pid;
    std::vector<std::shared_ptr<inject_point>> targets;
    inject_info hooker;
    inject_info helper;
    inject_parser(const std::string &json);
    ~inject_parser(){};
    bool parse_inject_config();
};
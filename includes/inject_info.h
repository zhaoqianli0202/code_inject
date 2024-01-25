#pragma once
#include "common.h"

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
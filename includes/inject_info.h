#pragma once
#include <string>
#include <libelf.h>
#include <gelf.h>
#include <sstream>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <fstream>

class inject_info {
private:
    bool parse_symbol_addr();
    bool find_symbol_addr();

public:
    std::string elf_path;
    std::string sym_name;
    uintptr_t sym_addr;
    static uintptr_t get_module_base(pid_t pid, const std::string &module_name);
    int parse_inject_info(const std::string &info);
    uintptr_t get_reloc_addr(pid_t pid);
};
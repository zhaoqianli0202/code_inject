#include "inject_info.h"

bool inject_info::parse_symbol_addr() {
    std::istringstream iss(sym_name);
    iss >> std::hex >> sym_addr;

    if (!iss.fail() && iss.eof()) {
        return true;
    }
    return find_symbol_addr();
}

bool inject_info::find_symbol_addr() {
    int fd = open(elf_path.c_str(), O_RDONLY, 0);
    if (fd < 0) {
        printf("open failed\n");
        return false;
    }

    if (elf_version(EV_CURRENT) == EV_NONE) {
        printf("elf_version failed\n");
        close(fd);
        return false;
    }

    Elf* elf = elf_begin(fd, ELF_C_READ, nullptr);
    if (elf == nullptr) {
        printf("elf_begin failed\n");
        close(fd);
        return false;
    }

    Elf_Kind ek = elf_kind(elf);
    if (ek != ELF_K_ELF) {
        printf("Not an ELF object.\n");
        elf_end(elf);
        close(fd);
        return false;
    }

    Elf_Scn* section = nullptr;
    Elf_Scn* symbolSection = nullptr;
    GElf_Shdr symbolHeader;
    while ((section = elf_nextscn(elf, section)) != nullptr) {
        gelf_getshdr(section, &symbolHeader);
        if (symbolHeader.sh_type == SHT_SYMTAB) {
            symbolSection = section;
            break;
        }
    }

    if (symbolSection == nullptr) {
        printf("No symbol table found.\n");
        elf_end(elf);
        close(fd);
        return false;
    }

    Elf_Data* symbolData = elf_getdata(symbolSection, nullptr);
    if (symbolData == nullptr) {
        printf("elf_getdata failed\n");
        elf_end(elf);
        close(fd);
        return false;
    }

    size_t numSymbols = symbolData->d_size / sizeof(GElf_Sym);

    for (size_t i = 0; i < numSymbols; ++i) {
        GElf_Sym symbol;
        gelf_getsym(symbolData, i, &symbol);

        const char* symbolNameInFile = elf_strptr(elf, symbolHeader.sh_link, symbol.st_name);

        if (symbolNameInFile != nullptr && strcmp(symbolNameInFile, sym_name.c_str()) == 0) {
            sym_addr = symbol.st_value;
            // printf("Symbol %s found at address 0x%llx\n", sym_name.c_str(), (long long)symbol.st_value);
            return true;
        }
    }

    elf_end(elf);
    close(fd);
    return false;
}

int inject_info::parse_inject_info(const std::string &info) {
    std::istringstream iss(info);
    if (!std::getline(iss, elf_path, ':')) {
        printf("Fail to parse_inject_info elf path %s\n", elf_path.c_str());
        return -1;
    }
    if (access(elf_path.c_str(), R_OK)) {
        printf("Not exist elf %s\n", elf_path.c_str());
        return -2;
    }
    if (!std::getline(iss, sym_name)) {
        printf("Fail to parse_inject_info symbol %s\n", sym_name.c_str());
        return -3;
    }
    if (iss >> std::ws &&!iss.eof()) {
        printf("Fail to parse_inject_info symbol %s\n", sym_name.c_str());
        return -4;
    }
    if (!parse_symbol_addr()) {
        printf("parse symbol %s in file %s failed\n", sym_name.c_str(), elf_path.c_str());
        return -5;
    }

    return 0;
}

uintptr_t inject_info::get_reloc_addr(pid_t pid) {
    uintptr_t base = get_module_base(pid, elf_path);
    if (!base) {
        printf("Get module %s base failed\n", elf_path.c_str());
        return 0;
    }
    sym_addr += base;
    return sym_addr;
}

uintptr_t inject_info::get_module_base(pid_t pid, const std::string &module_name) {
    std::string line;
    std::string map_file;
    const char *path_name;
    uint64_t region_base;
    if (pid < 0) {
        map_file = "/proc/self/maps";
    } else {
        map_file = "/proc/" + std::to_string(pid) + "/maps";
    }
    std::ifstream ifs(map_file);
    if (!ifs.is_open()) {
        printf("Open %s failed\n", map_file.c_str());
        return 0;
    }
    while (std::getline(ifs, line)) {
        path_name = strstr(line.c_str(), module_name.c_str());
        if (path_name) {
            std::istringstream iss(line);
            iss >> std::hex >> region_base;
            if (path_name == module_name) {
                return region_base;
            }
        }
    }
    printf("Not found %s in %s\n", module_name.c_str(), map_file.c_str());
    return 0;
}

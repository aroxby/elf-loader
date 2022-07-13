#ifndef __INC_ELF_IMAGE_H_
#define __INC_ELF_IMAGE_H_

#include <istream>
#include <string>
#include <memory>
#include <map>
#include "elf64.h"

class ElfSymbolTable {
public:
    ElfSymbolTable(size_t num_symbols, const Elf64_Sym *symbols, const char *strings);

    size_t num_symbols;
    const Elf64_Sym *symbols;
    const char *strings;
};

class ElfImage {
public:
    ElfImage(std::istream &is);

    void dump(std::ostream &os);

private:
    const char *loadSection(Elf64_Half index, std::istream &is);
    void loadSymbolTable(Elf64_Half symbol_index, std::istream &is);

    void allocateAddressSpace();
    void loadSegment(const Elf64_Phdr &header, std::istream &is);

    Elf64_Ehdr elf_header;
    std::unique_ptr<Elf64_Shdr[]> section_headers;
    std::unique_ptr<Elf64_Phdr[]> program_headers;
    const char *section_strings;
    std::unique_ptr<char[]> image_base;

    std::map<Elf64_Half, std::unique_ptr<char[]>> aux_sections;

    std::map<Elf64_Half, ElfSymbolTable> symbol_tables;
};

#endif//__INC_ELF_IMAGE_H_

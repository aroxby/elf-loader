#ifndef __INC_ELF_IMAGE_H_
#define __INC_ELF_IMAGE_H_

#include <istream>
#include <string>
#include <memory>
#include "elf64.h"

class ElfSymbolCollection {
public:
    size_t num_symbols;
    std::unique_ptr<Elf64_Sym[]> symbols;
    std::unique_ptr<char[]> strings;
};

class ElfImage {
public:
    ElfImage(std::istream &is);

    void dump(std::ostream &os);

private:
    static std::unique_ptr<char[]> loadStringTable(const Elf64_Shdr &header, std::istream &is);
    static void loadSymbolTable(
        const Elf64_Shdr &symbol_header,
        const Elf64_Shdr &string_header,
        ElfSymbolCollection &symbols,
        std::istream &is
    );

    void allocateMemory();
    void loadSegment(const Elf64_Phdr &header, std::istream &is);

    Elf64_Ehdr elf_header;
    std::unique_ptr<Elf64_Shdr[]> section_headers;
    std::unique_ptr<Elf64_Phdr[]> program_headers;
    std::unique_ptr<char[]> section_strings;
    std::unique_ptr<char[]> image_base;

    ElfSymbolCollection symbols;
};

#endif//__INC_ELF_IMAGE_H_

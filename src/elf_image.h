#ifndef __INC_ELF_IMAGE_H_
#define __INC_ELF_IMAGE_H_

#include <istream>
#include <string>
#include <memory>
#include <map>
#include <vector>
#include "elf64.h"

typedef void (*ElfFunction)();

class ElfSymbolTable {
public:
    ElfSymbolTable(
        size_t num_symbols, std::shared_ptr<const Elf64_Sym[]> symbols, std::shared_ptr<const char[]> strings
    );

    const size_t num_symbols;
    std::shared_ptr<const Elf64_Sym[]> symbols;
    std::shared_ptr<const char[]> strings;
};

class ElfRelocation {
public:
    ElfRelocation(
        Elf64_Addr offset, Elf64_Xword type, Elf64_Sxword addend, Elf64_Addr symbol_value, const char *symbol_name
    );

    const Elf64_Addr offset;
    const Elf64_Xword type;
    const Elf64_Sxword addend;
    const Elf64_Addr symbol_value;
    const char *symbol_name;
};

class ElfImage {
public:
    ElfImage(std::istream &is);

    void dump(std::ostream &os) const;

private:
    void processRelocations(Elf64_Half section_index, std::istream &is);
    std::shared_ptr<const char[]> loadSection(Elf64_Half index, std::istream &is);
    // NB: Loose reference
    const ElfSymbolTable &loadSymbolTable(Elf64_Half symbol_index, std::istream &is);

    void allocateAddressSpace();
    void loadSegment(const Elf64_Phdr &header, std::istream &is);

    // FIXME: Copies data
    template <typename DataType>
    std::vector<DataType> loadArray(Elf64_Half section_index, std::istream &is);

    Elf64_Ehdr elf_header;
    std::unique_ptr<const Elf64_Shdr[]> section_headers;
    std::unique_ptr<const Elf64_Phdr[]> program_headers;
    std::shared_ptr<const char[]> section_strings;
    std::shared_ptr<char[]> image_base;

    std::map<Elf64_Half, std::shared_ptr<char[]>> aux_sections;

    std::map<Elf64_Half, const ElfSymbolTable> symbol_tables;

    std::vector<ElfRelocation> relocations;

    // TODO: Use an array class that keeps the unmanaged pointer and element count
    std::vector<ElfFunction> init_array;
    std::vector<ElfFunction> fini_array;
    std::vector<Elf64_Dyn> dynamic;
};

#endif//__INC_ELF_IMAGE_H_

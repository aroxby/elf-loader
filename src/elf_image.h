#ifndef __INC_ELF_IMAGE_H_
#define __INC_ELF_IMAGE_H_

#include <istream>
#include <string>
#include <memory>
#include <map>
#include <vector>
#include "elf64.h"
#include "dynamic_array.h"

typedef void (*ElfFunction)();

class ElfSymbolTable {
public:
    ElfSymbolTable(
        size_t num_symbols, std::shared_ptr<const Elf64_Sym[]> symbols, std::shared_ptr<const char[]> strings
    );

    // FIXME: Use DynamicArray
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

    template <typename DataType>
    DynamicArray<DataType> loadArray(Elf64_Half section_index, std::istream &is);

    Elf64_Ehdr elf_header;
    std::unique_ptr<const Elf64_Shdr[]> section_headers;
    std::unique_ptr<const Elf64_Phdr[]> program_headers;
    std::shared_ptr<const char[]> section_strings;
    std::shared_ptr<char[]> image_base;

    std::map<Elf64_Half, std::shared_ptr<char[]>> aux_sections;

    std::map<Elf64_Half, const ElfSymbolTable> symbol_tables;

    std::vector<ElfRelocation> relocations;

    DynamicArray<const ElfFunction> init_array;
    DynamicArray<const ElfFunction> fini_array;

    DynamicArray<const Elf64_Dyn> dynamic;
};

#endif//__INC_ELF_IMAGE_H_

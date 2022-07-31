#ifndef __INC_ELF_IMAGE_H_
#define __INC_ELF_IMAGE_H_

#include <istream>
#include <string>
#include <memory>
#include <map>
#include "elf64.h"
#include "dynamic_array.h"

typedef void (*ElfFunction)();

class ElfSymbolTable {
public:
    ElfSymbolTable(DynamicArray<const Elf64_Sym> symbols, std::shared_ptr<const char[]> strings);

    DynamicArray<const Elf64_Sym> symbols;
    std::shared_ptr<const char[]> strings;
};

class ElfRelocations {
public:
    ElfRelocations(const DynamicArray<const Elf64_Rela> relocations, const ElfSymbolTable symbols);

    void dump(std::ostream &os) const;

    const DynamicArray<const Elf64_Rela> relocations;
    const ElfSymbolTable symbols;
};

class ElfImage {
public:
    ElfImage(std::istream &is);

    void dump(std::ostream &os) const;

private:
    std::unique_ptr<const ElfRelocations> loadRelocations(Elf64_Half section_index, std::istream &is);
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

    std::map<Elf64_Half, std::unique_ptr<const ElfRelocations>> relocations;

    DynamicArray<const ElfFunction> init_array;
    DynamicArray<const ElfFunction> fini_array;

    DynamicArray<const Elf64_Dyn> dynamic;
};

#endif//__INC_ELF_IMAGE_H_

#ifndef __INC_ELF_IMAGE_H_
#define __INC_ELF_IMAGE_H_

#include <istream>
#include <string>
#include <memory>
#include <map>
#include "elf64.h"
#include "dynamic_array.h"

typedef void (*ElfFunction)();

class ElfImage;

class ElfSymbolTable {
public:
    ElfSymbolTable(DynamicArray<const Elf64_Sym> symbols, std::shared_ptr<const char[]> strings);

    void dump(const ElfImage &image, Elf64_Half section_index, std::ostream &os) const;

    const DynamicArray<const Elf64_Sym> symbols;
    const std::shared_ptr<const char[]> strings;
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

    // Having this method around really bothers me and I want to refactor ElfSymbolTable::dump so we don't need this
    std::shared_ptr<const char[]> getSectionName(Elf64_Half index) const;

    const std::map<Elf64_Half, std::unique_ptr<const ElfRelocations>> &getRelocations() const;

protected:
    void *getImageBase() const { return image_base.get(); }

private:
    void allocateAddressSpace();
    void loadSegment(const Elf64_Phdr &header, std::istream &is);

    std::shared_ptr<const char[]> loadSection(Elf64_Half index, std::istream &is);
    std::unique_ptr<const ElfRelocations> loadRelocations(Elf64_Half section_index, std::istream &is);
    const ElfSymbolTable loadSymbolTable(Elf64_Half symbol_index, std::istream &is);

    template <typename DataType>
    DynamicArray<DataType> loadArray(Elf64_Half section_index, std::istream &is);

    Elf64_Ehdr elf_header;
    DynamicArray<const Elf64_Shdr> section_headers;
    DynamicArray<const Elf64_Phdr> program_headers;
    std::shared_ptr<const char[]> section_strings;
    std::shared_ptr<char[]> image_base;

    std::map<Elf64_Half, std::shared_ptr<char[]>> aux_sections;

    std::map<Elf64_Half, const ElfSymbolTable> symbol_tables;

    std::map<Elf64_Half, std::unique_ptr<const ElfRelocations>> relocations;

    std::map<Elf64_Half, const DynamicArray<const ElfFunction>> init_array;
    std::map<Elf64_Half, const DynamicArray<const ElfFunction>> fini_array;

    std::map<Elf64_Half, const DynamicArray<const Elf64_Dyn>> dynamic;
};

void dumpElfHeader(const Elf64_Ehdr header, std::ostream &os);

void dumpSectionHeaders(
    DynamicArray<const Elf64_Shdr> headers, const char sectionStrings[], size_t sectionsOffset, std::ostream &os
);

void dumpProgramHeader(const Elf64_Phdr header, std::ostream &os);

void dumpFunctionArray(
    const std::string &name, const DynamicArray<const ElfFunction> array, std::ostream &os
);
void dumpDynamicEntry(const Elf64_Dyn entry, std::ostream &os);

#endif//__INC_ELF_IMAGE_H_

#include <istream>
#include <string>
#include <memory>
#include "exceptions.h"
#include "elf_decoding.h"
#include "elf_image.h"
using namespace std;

template <typename ValType, typename RangeType>
bool _inRange(ValType val, RangeType lower, RangeType upper) {
    if(val <= lower || val >= upper) {
        return false;
    } else {
        return true;
    }
}

ElfImage::ElfImage(istream &is) {
    // Read the header
    is.read((char*)&elf_header, sizeof(elf_header));

    if(!IS_ELF(elf_header)) {
        throw InvalidSignature();
    }

    if(elf_header.e_version != EV_CURRENT) {
        throw IncompatibleMachineType();
    }

    if(elf_header.e_machine != EM_X86_64) {
        throw IncompatibleVersion();
    }

    if(elf_header.e_shentsize != sizeof(Elf64_Shdr)) {
        throw UnsupportedSectionConfiguration();
    }

    // Load section headers
    is.seekg(elf_header.e_shoff);
    section_headers = unique_ptr<Elf64_Shdr[]>(new Elf64_Shdr[elf_header.e_shnum]);
    for(int i = 0; i < elf_header.e_shnum; i++) {
        is.read((char*)&section_headers[i], sizeof(Elf64_Shdr));
    }

    // Load program headers
    is.seekg(elf_header.e_phoff);
    program_headers = unique_ptr<Elf64_Phdr[]>(new Elf64_Phdr[elf_header.e_phnum]);
    for(int i = 0; i < elf_header.e_phnum; i++) {
        is.read((char*)&program_headers[i], sizeof(Elf64_Phdr));
    }

    // Load section header string table by known index
    section_strings = loadSection(elf_header.e_shstrndx, is);

    allocateAddressSpace();

    // Selectively load segments
    for(int i = 0; i < elf_header.e_phnum; i++) {
        switch(program_headers[i].p_type) {
        case PT_LOAD:
            loadSegment(program_headers[i], is);
        }
    }

    // Selectively load section data
    for(int i = 0; i < elf_header.e_shnum; i++) {
        switch(section_headers[i].sh_type) {
        case SHT_SYMTAB:
            loadSymbolTable(i, section_headers[i].sh_link, is);
            break;

        case SHT_DYNSYM:
            loadSymbolTable(i, section_headers[i].sh_link, is);
            break;

        }
    }
}

// TODO: These pointers die when the ElfImage is unloaded.  Can we use a shared_ptr?
const char *ElfImage::loadSection(Elf64_Half index, istream &is) {
    char *ptr;
    if(section_headers[index].sh_addr) {  // Resident Section
        ptr = &image_base[section_headers[index].sh_addr];
    } else {  // Non resident section
        auto &ptr_ref = aux_sections[index];
        ptr = ptr_ref.get();
        if(!ptr) {
            ptr_ref = unique_ptr<char[]>(new char[section_headers[index].sh_size]);
            ptr = ptr_ref.get();
            is.seekg(section_headers[index].sh_offset);
            is.read(ptr, section_headers[index].sh_size);
        }
    }
    return ptr;
}

void ElfImage::loadSymbolTable(
    Elf64_Half symbol_index,
    Elf64_Half string_index,
    istream &is
) {
    ElfSymbolTable symbols;

    if(section_headers[symbol_index].sh_size % sizeof(Elf64_Sym) != 0) {
        throw UnsupportedSymbolConfiguration();
    }

    symbols.num_symbols = section_headers[symbol_index].sh_size / sizeof(Elf64_Sym);
    symbols.symbols = (Elf64_Sym*)loadSection(symbol_index, is);
    symbols.strings = loadSection(string_index, is);

    symbol_tables[symbol_index] = symbols;
}

void ElfImage::allocateAddressSpace() {
    Elf64_Addr highestOffset = 0;
    Elf64_Xword size = 0;

    // Get the highest described virtual address
    for(int i = 0; i < elf_header.e_phnum; i++) {
        switch(program_headers[i].p_type) {
        case PT_LOAD:
            // These SHOULD already be sorted by address but just in case...
            if(program_headers[i].p_vaddr > highestOffset) {
                highestOffset = program_headers[i].p_vaddr;
                size = program_headers[i].p_memsz;
            }
        }
    }

    image_base = unique_ptr<char[]>(new char[highestOffset + size]);
}

void ElfImage::loadSegment(const Elf64_Phdr &header, istream &is) {
    is.seekg(header.p_offset);
    char *ptr = &image_base[header.p_vaddr];
    is.read(ptr, header.p_memsz);
}

void ElfImage::dump(ostream &os) {
    // Dump main header
    os << "Type: " << elf_header.e_type
        << " (" << elfTypeToString(elf_header.e_type) << ')' << endl;
    os << "Type Name: " << getElfTypeName(elf_header.e_type) << endl;
    os << "Machine: " << elf_header.e_machine << endl;
    os << "Version: " << elf_header.e_version << endl;
    os << "Entry point: " << (void*)elf_header.e_entry << endl;
    os << "Program Header Offset: " << (void*)elf_header.e_phoff << endl;
    os << "Section Header Offset: " << (void*)elf_header.e_shoff << endl;
    os << "Flags: " << (void*)((size_t)elf_header.e_flags) << endl;
    os << "ELF Header Size: " << elf_header.e_ehsize << endl;
    os << "Program Header Size: "<< elf_header.e_phentsize << endl;
    os << "Number of Program Header Entries: " << elf_header.e_phnum << endl;
    os << "Section Header Size: "<< elf_header.e_shentsize << endl;
    os << "Number of Section Header Entries: " << elf_header.e_shnum << endl;
    os << "Strings Section Index: " << elf_header.e_shstrndx << endl;

    // Dump sections
    for(int i = 0; i < elf_header.e_shnum; i++) {
        os << endl;
        os << "Section Name Offset: " << section_headers[i].sh_name << endl;
        os << "Section Name: " << &section_strings[section_headers[i].sh_name] << endl;
        os << "Section Type: " << (void*)((size_t)section_headers[i].sh_type)
            << " (" << sectionTypeToString(section_headers[i].sh_type) << ')' << endl;
        os << "Section Type Name: " << getSectionTypeName(section_headers[i].sh_type) << endl;
        os << "Section Flags: " << (void*)section_headers[i].sh_flags
            << " (" << sectionFlagsToString(section_headers[i].sh_flags) << ')' << endl;
        os << "Section Address: " << (void*)section_headers[i].sh_addr << endl;
        os << "Section Offset: " << (void*)section_headers[i].sh_offset << endl;
        os << "Section Size: " << section_headers[i].sh_size << endl;
        os << "Related Section: "
            << section_headers[i].sh_link << " ("
            << &section_strings[section_headers[section_headers[i].sh_link].sh_name]
            << ')' << endl;
        os << "Section Info: " << (void*)((size_t)section_headers[i].sh_info) << endl;
        os << "Section Alignment: " << (void*)section_headers[i].sh_addralign << endl;
        os << "Section Entry Size: " << (void*)section_headers[i].sh_entsize << endl;
    }

    // Dump program headers
    for(int i = 0; i < elf_header.e_phnum; i++) {
        os << endl;
        os << "Segment Type: " << (void*)((size_t)program_headers[i].p_type)
            << " (" << segmentTypeToString(program_headers[i].p_type) << ')' << endl;
        os << "Segment Type Name: " << getSegmentTypeName(program_headers[i].p_type) << endl;
        os << "Segment Flags: " << (void*)((size_t)program_headers[i].p_flags)
            << " (" << segmentFlagsToString(program_headers[i].p_flags) << ')' << endl;
        os << "Segment Offset: " << (void*)program_headers[i].p_offset << endl;
        os << "Segment Virtual Address: " << (void*)program_headers[i].p_vaddr << endl;
        os << "Segment Physical Address: " << (void*)program_headers[i].p_paddr << endl;
        os << "Segment File Size: " << program_headers[i].p_filesz << endl;
        os << "Segment Memory Size: " << program_headers[i].p_memsz << endl;
        os << "Segment Alignment: " << (void*)program_headers[i].p_align << endl;
    }

    // Dump symbols
    for(auto iterator : symbol_tables) {
        ElfSymbolTable symbols = iterator.second;
        os << endl;
        os << "Symbol Table: " << &section_strings[section_headers[iterator.first].sh_name] << endl;

        for(int i = 0; i < symbols.num_symbols; i++) {
            auto section_index_for_name = _inRange(
                symbols.symbols[i].st_shndx, SHN_LORESERVE, SHN_HIRESERVE
            ) ? 0 : symbols.symbols[i].st_shndx;
            os << endl;
            os << "Symbol Name Offset: " << symbols.symbols[i].st_name << endl;
            os << "Symbol Name: " << &symbols.strings[symbols.symbols[i].st_name] << endl;
            os << "Symbol Bind: " << ELF64_ST_BIND(symbols.symbols[i].st_info)
                << " (" << symbolBindToString(ELF64_ST_BIND(symbols.symbols[i].st_info)) << ')' << endl;
            os << "Symbol Type: " << ELF64_ST_TYPE(symbols.symbols[i].st_info)
                << " (" << symbolTypeToString(ELF64_ST_TYPE(symbols.symbols[i].st_info)) << ')' << endl;
            // Strangely, elf_common.h contains 7 constants for this despite it being 1 bit
            os << "Symbol Visibility: " << ELF64_ST_VISIBILITY(symbols.symbols[i].st_other) << endl;
            os << "Symbol Section Index: " << symbols.symbols[i].st_shndx << endl;
            os << "Symbol Section Name: "
                << &section_strings[section_headers[section_index_for_name].sh_name] << endl;
            os << "Symbol Value: " << (void*)symbols.symbols[i].st_value << endl;
            os << "Symbol Size: " << symbols.symbols[i].st_size << endl;
        }
    }
}

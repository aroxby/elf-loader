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
    section_headers = unique_ptr<const Elf64_Shdr[]>(new Elf64_Shdr[elf_header.e_shnum]);
    for(int i = 0; i < elf_header.e_shnum; i++) {
        is.read((char*)&section_headers[i], sizeof(Elf64_Shdr));
    }

    // Load program headers
    is.seekg(elf_header.e_phoff);
    program_headers = unique_ptr<const Elf64_Phdr[]>(new Elf64_Phdr[elf_header.e_phnum]);
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
        case SHT_DYNSYM:
            loadSymbolTable(i, is);
            break;

        case SHT_RELA:
            processRelocations(i, is);
            break;

        case SHT_INIT_ARRAY:
            init_array = loadArray<ElfFunction>(i, is);
            break;

        case SHT_FINI_ARRAY:
            fini_array = loadArray<ElfFunction>(i, is);
            break;

        case SHT_DYNAMIC:
            dynamic = loadArray<Elf64_Dyn>(i, is);
            break;

        case SHT_NOTE:  // There's very little information about this available
        case SHT_GNU_HASH:  // This isn't needed to run but it boosts performance
        case SHT_STRTAB:  // These are loaded by other sections
        case SHT_GNU_versym:  // I can't tell if this is required for dynamic linking
        case SHT_GNU_verneed:  // I can't tell if this is required for dynamic linking
        case SHT_NOBITS:  // These sections contain no data
        case SHT_PROGBITS:  // Most of these aren't processed but there may be exceptions
            // TODO: Figure out if we need to collect .init, .fini, or anything else
            break;
        }
    }
}

void ElfImage::processRelocations(Elf64_Half section_index, istream &is) {
    size_t num_entries = section_headers[section_index].sh_size / sizeof(Elf64_Rela);
    Elf64_Rela *entries = (Elf64_Rela*)loadSection(section_index, is);

    const ElfSymbolTable &table = loadSymbolTable(section_headers[section_index].sh_link, is);

    for(size_t i = 0; i < num_entries; i++) {
        Elf64_Xword symbol_index = ELF64_R_SYM(entries[i].r_info);
        Elf64_Xword relocation_type = ELF64_R_TYPE_ID(entries[i].r_info);
        // ELF64_R_TYPE_DATA(entries[i].r_info);  // Seems only used on SPARC

        // FIXME: Dynamic symbols (eg: R_X86_64_JMP_SLOT) are not loaded
        // Missed in a previous section or included in upcoming section?
        const Elf64_Sym &symbol = table.symbols[symbol_index];
        const char *symbol_name = &table.strings[symbol.st_name];

        /*
        Elf64_Xword A = entries[i].r_addend;
        Elf64_Xword B = (Elf64_Xword)&image_base[0];
        Elf64_Xword S = symbol.st_value;
        */
        /*
        Elf64_Xword P = entries[i].r_offset;
        Elf64_Xword G = 0;  // GOT offset?
        Elf64_Xword GOT = 0;  // GOT address?
        Elf64_Xword L = 0;  // PLT address?
        Elf64_Xword Z = symbol.st_size;
        */

        // I'm not ready to process this section yet so we'll just dump it for now
        relocations.emplace_back(
            entries[i].r_offset, relocation_type, entries[i].r_addend, symbol.st_value, symbol_name
        );
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

const ElfSymbolTable &ElfImage::loadSymbolTable(Elf64_Half section_index, istream &is) {
    if(section_headers[section_index].sh_size % sizeof(Elf64_Sym) != 0) {
        throw UnsupportedSymbolConfiguration();
    }

    auto iterator = symbol_tables.find(section_index);
    if(iterator == symbol_tables.end()) {
        size_t num_symbols = section_headers[section_index].sh_size / sizeof(Elf64_Sym);
        const Elf64_Sym *symbols = (Elf64_Sym*)loadSection(section_index, is);
        const char *strings = loadSection(section_headers[section_index].sh_link, is);

        auto emplace_result = symbol_tables.emplace(
            section_index, ElfSymbolTable(num_symbols, symbols, strings)
        );
        iterator = emplace_result.first;
    }
    return iterator->second;
}

template <typename DataType>
vector<DataType> ElfImage::loadArray(Elf64_Half section_index, istream &is) {
    size_t num_entries =  section_headers[section_index].sh_size / sizeof(DataType);
    DataType *ptrs = (DataType*)loadSection(section_index, is);
    vector<DataType> entries;
    entries.reserve(num_entries);
    for(size_t i = 0; i<num_entries; i++) {
        entries.push_back(ptrs[i]);
    }
    return entries;
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

void ElfImage::dump(ostream &os) const {
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
        const ElfSymbolTable &symbols = iterator.second;
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
            // Strangely, elf_common.h contains 7 constants for this despite it being 2 bits
            os << "Symbol Visibility: " << ELF64_ST_VISIBILITY(symbols.symbols[i].st_other) << endl;
            os << "Symbol Section Index: " << symbols.symbols[i].st_shndx << endl;
            os << "Symbol Section Name: "
                << &section_strings[section_headers[section_index_for_name].sh_name] << endl;
            os << "Symbol Value: " << (void*)symbols.symbols[i].st_value << endl;
            os << "Symbol Size: " << symbols.symbols[i].st_size << endl;
        }
    }

    // Dump relocations
    for(auto relocation : relocations) {
        os << endl;
        os << "Relocation Offset: " << (void*)relocation.offset << endl;
        os << "Relocation Type: " << relocation.type
            << " (" << relocationTypeToString(relocation.type) << ')' << endl;
        os << "Relocation Addend: " << (void*)relocation.addend << endl;
        os << "Relocation Symbol Value: " << (void*)relocation.symbol_value << endl;
        os << "Relocation Symbol Name: " << relocation.symbol_name << endl;
    }

    // Dump init array
    for(auto function : init_array) {
        os << endl;
        // Strangely, just printing function addresses was showing the wrong value
        os << "Init: " << (void*)function << endl;
    }

    // Dump fini array
    for(auto function : fini_array) {
        os << endl;
        os << "Fini: " << (void*)function << endl;
    }

    // Dump dynamic data
    for(auto entry : dynamic) {
        os << endl;
        const string &entryTypeName = dynamicEntryTypeToString(entry.d_tag);
        if(entry.d_tag < DT_LOOS) {
            os << "Dynamic Entry Type: " << entry.d_tag
                << " (" << entryTypeName << ')' << endl;
        } else {
            os << "Dynamic Entry Type: " << (void*)entry.d_tag
                << " (" << entryTypeName << ')' << endl;
        }
        os << "Dynamic Entry Address: " << (void*)entry.d_un.d_ptr << endl;
    }
}

ElfSymbolTable::ElfSymbolTable(size_t num_symbols, const Elf64_Sym *symbols, const char *strings) :
    num_symbols(num_symbols), symbols(symbols), strings(strings) { }


ElfRelocation::ElfRelocation(
    Elf64_Addr offset, Elf64_Xword type, Elf64_Sxword addend, Elf64_Addr symbol_value, const char *symbol_name
) : offset(offset), type(type), addend(addend), symbol_value(symbol_value), symbol_name(symbol_name) { }

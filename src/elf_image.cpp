#include <istream>
#include <string>
#include <memory>
#include "exceptions.h"
#include "elf_decoding.h"
#include "elf_image.h"
using namespace std;

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
    section_headers = DynamicArray(
        shared_ptr<const Elf64_Shdr[]>(new Elf64_Shdr[elf_header.e_shnum]), elf_header.e_shnum
    );
    for(const Elf64_Shdr &header : section_headers) {
        is.read((char*)&header, sizeof(Elf64_Shdr));
    }

    // Load program headers
    is.seekg(elf_header.e_phoff);
    program_headers = DynamicArray(
        shared_ptr<const Elf64_Phdr[]>(new Elf64_Phdr[elf_header.e_phnum]), elf_header.e_phnum
    );
    for(const Elf64_Phdr &header : program_headers) {
        is.read((char*)&header, sizeof(Elf64_Phdr));
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
            // Unlike other methods like `loadRelocations`
            // `loadSymbolTable` checks if the table has already been
            // loaded and thus manages the instance variable.
            // This is done because other sections sometimes also load
            // symbol tables
            loadSymbolTable(i, is);
            break;

        case SHT_RELA:
            relocations.emplace(i, loadRelocations(i, is));
            break;

        case SHT_INIT_ARRAY:
            init_array.emplace(i, loadArray<const ElfFunction>(i, is));
            break;

        case SHT_FINI_ARRAY:
            fini_array.emplace(i, loadArray<const ElfFunction>(i, is));
            break;

        case SHT_DYNAMIC:
            dynamic.emplace(i, loadArray<const Elf64_Dyn>(i, is));
            break;

        case SHT_NULL:  // This section is not used
        case SHT_NOTE:  // There's very little information about this available
        case SHT_GNU_HASH:  // This isn't needed to run but it boosts performance
        case SHT_STRTAB:  // These are loaded by other sections
        case SHT_GNU_verdef:  // These are only required if we need symbol versioning
        case SHT_GNU_verneed:  // These are only required if we need symbol versioning
        case SHT_GNU_versym:  // These are only required if we need symbol versioning
        case SHT_NOBITS:  // These sections contain no data
        case SHT_PROGBITS:  // Most of these aren't processed but there may be exceptions
            // TODO: Figure out if we need to collect .init, .fini, or anything else
            break;

        default:
            throw UnexpectedSectionType();
            break;
        }
    }
}

unique_ptr<const ElfRelocations> ElfImage::loadRelocations(Elf64_Half section_index, istream &is) {
    const DynamicArray<const Elf64_Rela> entries = loadArray<const Elf64_Rela>(section_index, is);
    const ElfSymbolTable table = loadSymbolTable(section_headers[section_index].sh_link, is);
    unique_ptr<const ElfRelocations> ptr =  unique_ptr<const ElfRelocations>(new ElfRelocations(entries, table));
    return ptr;
}

shared_ptr<const char[]> ElfImage::loadSection(Elf64_Half index, istream &is) {
    shared_ptr<char[]> ptr;
    if(section_headers[index].sh_addr) {  // Resident Section
        ptr = shared_ptr<char[]>(image_base, &image_base[section_headers[index].sh_addr]);
    } else {  // Non resident section
        shared_ptr<char[]> &ptr_ref = aux_sections[index];
        if(!ptr_ref) {
            ptr_ref.reset(new char[section_headers[index].sh_size]);
            is.seekg(section_headers[index].sh_offset);
            is.read(ptr_ref.get(), section_headers[index].sh_size);
        }
        ptr = ptr_ref;
    }
    return ptr;
}

const ElfSymbolTable ElfImage::loadSymbolTable(Elf64_Half section_index, istream &is) {
    if(section_headers[section_index].sh_size % sizeof(Elf64_Sym) != 0) {
        throw UnsupportedSymbolConfiguration();
    }

    auto iterator = symbol_tables.find(section_index);
    if(iterator == symbol_tables.end()) {
        DynamicArray<const Elf64_Sym> symbols = loadArray<const Elf64_Sym>(section_index, is);
        shared_ptr<const char[]> strings = loadSection(section_headers[section_index].sh_link, is);

        auto emplace_result = symbol_tables.emplace(
            section_index, ElfSymbolTable(symbols, strings)
        );
        iterator = emplace_result.first;
    }
    return iterator->second;
}

template <typename DataType>
DynamicArray<DataType> ElfImage::loadArray(Elf64_Half section_index, istream &is) {
    size_t num_entries =  section_headers[section_index].sh_size / sizeof(DataType);
    shared_ptr<const DataType[]> ptr = reinterpret_pointer_cast<const DataType[]>(
        loadSection(section_index, is)
    );
    return DynamicArray(ptr, num_entries);
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

    image_base = shared_ptr<char[]>(new char[highestOffset + size]);
}

void ElfImage::loadSegment(const Elf64_Phdr &header, istream &is) {
    is.seekg(header.p_offset);
    char *ptr = &image_base[header.p_vaddr];
    is.read(ptr, header.p_memsz);
}

void ElfImage::dump(ostream &os) const {
    // Dump main header
    dumpElfHeader(elf_header, os);

    // Dump sections
    dumpSectionHeaders(section_headers, section_strings.get(), elf_header.e_shoff, os);

    // Dump program headers
    for(Elf64_Phdr header : program_headers) {
        dumpProgramHeader(header, os);
    }

    // Dump symbols
    for(auto iterator : symbol_tables) {
        const ElfSymbolTable &symbols = iterator.second;
        iterator.second.dump(*this, iterator.first, os);
    }

    // Dump relocations
    for(auto &iterator : relocations) {
        iterator.second->dump(os);
    }

    // Dump init array
    for(auto iterator : init_array) {
        dumpFunctionArray("Init", iterator.second, os);
    }

    // Dump fini array
    for(auto iterator : fini_array) {
        dumpFunctionArray("Fini", iterator.second, os);
    }

    // Dump dynamic data
    for(auto iterator : dynamic) {
        for(const Elf64_Dyn entry : iterator.second) {
            dumpDynamicEntry(entry, os);
        }
    }
}

shared_ptr<const char[]> ElfImage::getSectionName(Elf64_Half index) const {
    shared_ptr<const char[]> ptr = shared_ptr<const char[]>(
        section_strings, &section_strings[section_headers[index].sh_name]
    );
    return ptr;
}

ElfSymbolTable::ElfSymbolTable(DynamicArray<const Elf64_Sym> symbols, shared_ptr<const char[]> strings)
    : symbols(symbols), strings(strings) { }

void ElfSymbolTable::dump(const ElfImage &image, Elf64_Half section_index, ostream &os) const {
    os << endl;
    os << "Symbol Table: " << image.getSectionName(section_index) << endl;

    for(int i = 0; i < symbols.getLength(); i++) {
        Elf64_Half section_index_for_name = (
            symbols[i].st_shndx >=SHN_LORESERVE && symbols[i].st_shndx <= SHN_HIRESERVE
        ) ? 0 : symbols[i].st_shndx;
        os << endl;
        os << "Symbol Name Offset: " << symbols[i].st_name << endl;
        os << "Symbol Name: " << &strings[symbols[i].st_name] << endl;
        os << "Symbol Bind: " << ELF64_ST_BIND(symbols[i].st_info)
            << " (" << symbolBindToString(ELF64_ST_BIND(symbols[i].st_info)) << ')' << endl;
        os << "Symbol Type: " << ELF64_ST_TYPE(symbols[i].st_info)
            << " (" << symbolTypeToString(ELF64_ST_TYPE(symbols[i].st_info)) << ')' << endl;
        // Strangely, elf_common.h contains 7 constants for this despite it being 2 bits
        os << "Symbol Visibility: " << ELF64_ST_VISIBILITY(symbols[i].st_other) << endl;
        os << "Symbol Section Index: " << symbols[i].st_shndx << endl;
        os << "Symbol Section Name: "
            << image.getSectionName(section_index_for_name) << endl;
        os << "Symbol Value: " << (void*)symbols[i].st_value << endl;
        os << "Symbol Size: " << symbols[i].st_size << endl;
    }
}

ElfRelocations::ElfRelocations(const DynamicArray<const Elf64_Rela> relocations, const ElfSymbolTable symbols)
    : relocations(relocations), symbols(symbols) { }

void dumpElfHeader(const Elf64_Ehdr header, ostream &os) {
    os << "Type: " << header.e_type
        << " (" << elfTypeToString(header.e_type) << ')' << endl;
    os << "Type Name: " << getElfTypeName(header.e_type) << endl;
    os << "Machine: " << header.e_machine << endl;
    os << "Version: " << header.e_version << endl;
    os << "Entry point: " << (void*)header.e_entry << endl;
    os << "Program Header Offset: " << (void*)header.e_phoff << endl;
    os << "Section Header Offset: " << (void*)header.e_shoff << endl;
    os << "Flags: " << (void*)((size_t)header.e_flags) << endl;
    os << "ELF Header Size: " << header.e_ehsize << endl;
    os << "Program Header Size: "<< header.e_phentsize << endl;
    os << "Number of Program Header Entries: " << header.e_phnum << endl;
    os << "Section Header Size: "<< header.e_shentsize << endl;
    os << "Number of Section Header Entries: " << header.e_shnum << endl;
    os << "Strings Section Index: " << header.e_shstrndx << endl;
}

void ElfRelocations::dump(ostream &os) const {
    for(const Elf64_Rela relocation : relocations) {
        Elf64_Xword relocation_type = ELF64_R_TYPE_ID(relocation.r_info);
        Elf64_Xword symbol_index = ELF64_R_SYM(relocation.r_info);
        const Elf64_Sym &symbol = symbols.symbols[symbol_index];
        const char *symbol_name = &symbols.strings[symbol.st_name];

        os << endl;  // TODO: Move these to the end of the block
        os << "Relocation Offset: " << (void*)relocation.r_offset << endl;
        os << "Relocation Type: " << relocation_type
            << " (" << relocationTypeToString(relocation_type) << ')' << endl;
        os << "Relocation Addend: " << (void*)relocation.r_addend << endl;
        os << "Relocation Symbol Value: " << (void*)symbol.st_value << endl;
        os << "Relocation Symbol Name: " << symbol_name << endl;
    }
}

void dumpSectionHeaders(
    DynamicArray<const Elf64_Shdr> headers, const char sectionStrings[], size_t sectionsOffset, ostream &os
) {
    for(size_t i = 0; i < headers.getLength(); i++) {
        size_t sectionOffset = i * sizeof(headers[i]) + sectionsOffset;
        os << endl;
        os << "Section Header Index: " << i << endl;
        os << "Section Header Offset: " << (void*)sectionOffset << endl;
        os << "Section Name Offset: " << headers[i].sh_name << endl;
        os << "Section Name: " << &sectionStrings[headers[i].sh_name] << endl;
        os << "Section Type: " << (void*)((size_t)headers[i].sh_type)
            << " (" << sectionTypeToString(headers[i].sh_type) << ')' << endl;
        os << "Section Type Name: " << getSectionTypeName(headers[i].sh_type) << endl;
        os << "Section Flags: " << (void*)headers[i].sh_flags
            << " (" << sectionFlagsToString(headers[i].sh_flags) << ')' << endl;
        os << "Section Address: " << (void*)headers[i].sh_addr << endl;
        os << "Section Offset: " << (void*)headers[i].sh_offset << endl;
        os << "Section Size: " << headers[i].sh_size << endl;
        os << "Related Section: "
            << headers[i].sh_link << " ("
            << &sectionStrings[headers[headers[i].sh_link].sh_name]
            << ')' << endl;
        os << "Section Info: " << (void*)((size_t)headers[i].sh_info) << endl;
        os << "Section Alignment: " << (void*)headers[i].sh_addralign << endl;
        os << "Section Entry Size: " << (void*)headers[i].sh_entsize << endl;
    }
}

void dumpProgramHeader(const Elf64_Phdr header, ostream &os) {
    os << endl;
    os << "Segment Type: " << (void*)((size_t)header.p_type)
        << " (" << segmentTypeToString(header.p_type) << ')' << endl;
    os << "Segment Type Name: " << getSegmentTypeName(header.p_type) << endl;
    os << "Segment Flags: " << (void*)((size_t)header.p_flags)
        << " (" << segmentFlagsToString(header.p_flags) << ')' << endl;
    os << "Segment Offset: " << (void*)header.p_offset << endl;
    os << "Segment Virtual Address: " << (void*)header.p_vaddr << endl;
    os << "Segment Physical Address: " << (void*)header.p_paddr << endl;
    os << "Segment File Size: " << header.p_filesz << endl;
    os << "Segment Memory Size: " << header.p_memsz << endl;
    os << "Segment Alignment: " << (void*)header.p_align << endl;
}

void dumpFunctionArray(const string &name, const DynamicArray<const ElfFunction> array, ostream &os) {
    if(array.getLength()) {
        os << endl;
        for(ElfFunction function : array) {
            os << name << ": " << (void*)function << endl;
        }
    }
}

void dumpDynamicEntry(const Elf64_Dyn entry, ostream &os) {
    os << endl;
    const string &entryTypeName = dynamicEntryTypeToString(entry.d_tag);
    // DT_LOOS and higher are specified using hex
    if(entry.d_tag < DT_LOOS) {
        os << "Dynamic Entry Type: " << entry.d_tag
            << " (" << entryTypeName << ')' << endl;
    } else {
        os << "Dynamic Entry Type: " << (void*)entry.d_tag
            << " (" << entryTypeName << ')' << endl;
    }
    os << "Dynamic Entry Value: " << (void*)entry.d_un.d_ptr << endl;
}

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
            relocations.emplace(i, loadRelocations(i, is));
            break;

        // TODO: Handle multiple instances of the following sections
        // Like was done above
        case SHT_INIT_ARRAY:
            init_array = loadArray<const ElfFunction>(i, is);
            break;

        case SHT_FINI_ARRAY:
            fini_array = loadArray<const ElfFunction>(i, is);
            break;

        case SHT_DYNAMIC:
            dynamic = loadArray<const Elf64_Dyn>(i, is);
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
        size_t section_offset = i * sizeof(section_headers[i]) + elf_header.e_shoff;
        os << endl;
        os << "Section Header Index: " << i << endl;
        os << "Section Header Offset: " << (void*)section_offset << endl;
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

        for(int i = 0; i < symbols.symbols.getLength(); i++) {
            auto section_index_for_name = (
                SHN_LORESERVE <= symbols.symbols[i].st_shndx <= SHN_HIRESERVE
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
    for(auto &iterator : relocations) {
        iterator.second->dump(os);
    }

    // Dump init array
    for(const ElfFunction function : init_array) {
        os << endl;
        // Strangely, just printing function addresses was showing the wrong value
        os << "Init: " << (void*)function << endl;
    }

    // Dump fini array
    for(const ElfFunction function : fini_array) {
        os << endl;
        os << "Fini: " << (void*)function << endl;
    }

    // Dump dynamic data
    for(const Elf64_Dyn &entry : dynamic) {
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
        os << "Dynamic Entry Address: " << (void*)entry.d_un.d_ptr << endl;
    }
}

ElfSymbolTable::ElfSymbolTable(DynamicArray<const Elf64_Sym> symbols, shared_ptr<const char[]> strings)
    : symbols(symbols), strings(strings) { }

ElfRelocation::ElfRelocation(
    Elf64_Addr offset, Elf64_Xword type, Elf64_Sxword addend, Elf64_Addr symbol_value, const char *symbol_name
) : offset(offset), type(type), addend(addend), symbol_value(symbol_value), symbol_name(symbol_name) { }


ElfRelocations::ElfRelocations(const DynamicArray<const Elf64_Rela> relocations, const ElfSymbolTable symbols)
    : relocations(relocations), symbols(symbols) { }

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

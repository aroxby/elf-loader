#include <iostream>  // For cout
#include <fstream>  // For ifstream
#include <memory>  // For unique_ptr
#include <vector>
#include "elf64.h"
#include "exceptions.h"
#include "elf_decoding.h"
#include "loader.h"
using namespace std;


ElfLoader::ElfLoader(const string &path) {
    // Enable exceptions
    ifstream ifs;
    ifs.exceptions(ifstream::eofbit | ifstream::failbit | ifstream::badbit);

    // Open the file
    ifs.open(path, ios_base::in | ios_base::binary);

    // Read the header
    Elf64_Ehdr header;
    ifs.read((char*)&header, sizeof(header));

    if(!IS_ELF(header)) {
        throw InvalidSignature();
    }

    if(header.e_version != EV_CURRENT) {
        cerr << "Machine type: " << header.e_machine << endl;
        throw IncompatibleMachineType();
    }

    if(header.e_machine != EM_X86_64) {
        cerr << "Machine type: " << header.e_machine << endl;
        throw IncompatibleVersion();
    }

    // Dump main header
    cout << "Type: " << header.e_type << endl;
    cout << "Type Name: " << getElfTypeName(header.e_type) << endl;
    cout << "Machine: " << header.e_machine << endl;
    cout << "Version: " << header.e_version << endl;
    cout << "Entry point: " << (void*)header.e_entry << endl;
    cout << "Program Header Offset: " << (void*)header.e_phoff << endl;
    cout << "Section Header Offset: " << (void*)header.e_shoff << endl;
    cout << "Flags: " << (void*)((size_t)header.e_flags) << endl;
    cout << "ELF Header Size: " << header.e_ehsize << endl;
    cout << "Program Header Size: "<< header.e_phentsize << endl;
    cout << "Number of Program Header Entries: " << header.e_phnum << endl;
    cout << "Section Header Size: "<< header.e_shentsize << endl;
    cout << "Number of Section Header Entries: " << header.e_shnum << endl;
    cout << "Strings Section Index: " << header.e_shstrndx << endl;

    if(header.e_shentsize != sizeof(Elf64_Shdr)) {
        throw UnsupportedFileConfiguration();
    }

    // Load section headers
    ifs.seekg(header.e_shoff);
    unique_ptr<Elf64_Shdr[]> sheaders(new Elf64_Shdr[header.e_shnum]);
    for(int i = 0; i < header.e_shnum; i++) {
        ifs.read((char*)&sheaders[i], sizeof(Elf64_Shdr));
    }

    // Load string section
    unique_ptr<char[]> strings(new char[sheaders[header.e_shstrndx].sh_size]);
    ifs.seekg(sheaders[header.e_shstrndx].sh_offset);
    ifs.read(&strings[0], sheaders[header.e_shstrndx].sh_size);

    // Dump sections
    for(int i = 0; i < header.e_shnum; i++) {
        cout << endl;
        cout << "Section Name Offset: " << sheaders[i].sh_name << endl;
        cout << "Section Name: " << &strings[sheaders[i].sh_name] << endl;
        cout << "Section Type: " << (void*)((size_t)sheaders[i].sh_type) << endl;
        cout << "Section Type Name: " << getSectionTypeName(sheaders[i].sh_type) << endl;
        cout << "Section Flags: "
            << (void*)sheaders[i].sh_flags
            << " (" << sectionFlagsToString(sheaders[i].sh_flags) << ')' << endl;
        cout << "Section Address: " << (void*)sheaders[i].sh_addr << endl;
        cout << "Section Offset: " << (void*)sheaders[i].sh_offset << endl;
        cout << "Section Size: " << sheaders[i].sh_size << endl;
        cout << "Related Section: " << sheaders[i].sh_link << endl;
        cout << "Section Info: " << (void*)((size_t)sheaders[i].sh_info) << endl;
        cout << "Section Alignment: " << (void*)sheaders[i].sh_addralign << endl;
        cout << "Section Entry Size: " << (void*)sheaders[i].sh_entsize << endl;
    }

    // Load program headers
    ifs.seekg(header.e_phoff);
    unique_ptr<Elf64_Phdr[]> pheaders(new Elf64_Phdr[header.e_phnum]);
    for(int i = 0; i < header.e_phnum; i++) {
        ifs.read((char*)&pheaders[i], sizeof(Elf64_Phdr));
    }

    // Dump program headers
    for(int i = 0; i < header.e_phnum; i++) {
        cout << endl;
        cout << "Segment Type: " << (void*)((size_t)pheaders[i].p_type) << endl;
        cout << "Segment Type Name: " << getSegmentTypeName(pheaders[i].p_type) << endl;
        cout << "Segment Flags: "
            << (void*)((size_t)pheaders[i].p_flags)
            << " (" << segmentFlagsToString(pheaders[i].p_flags) << ')' << endl;
        cout << "Segment Offset: " << (void*)pheaders[i].p_offset << endl;
        cout << "Segment Virtual Address: " << (void*)pheaders[i].p_vaddr << endl;
        cout << "Segment Physical Address: " << (void*)pheaders[i].p_paddr << endl;
        cout << "Segment File Size: " << pheaders[i].p_filesz << endl;
        cout << "Segment Memory Size: " << pheaders[i].p_memsz << endl;
        cout << "Segment Alignment: " << (void*)pheaders[i].p_align << endl;
    }
}

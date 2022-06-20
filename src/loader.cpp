#include <cstring>  // for memcmp
#include <iostream>  // For cout
#include <fstream>
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

    if(header.e_machine != EM_X86_64) {
        cerr << "Machine type: " << header.e_machine << endl;
        throw IncompatibleMachineType();
    }

    // Dump
    cout << "Type: " << header.e_type << endl;
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
}

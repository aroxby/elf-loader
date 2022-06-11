#include <iostream>  // For cout
#include <fstream>
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

    // Dump
    // This doesn't output the full ident as it contains nulls
    // But we don't plan on always printing the ident either so...
    cout << "Magic: " << header.e_ident << endl;
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

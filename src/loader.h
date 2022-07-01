#ifndef __INC_LOADER_H_
#define __INC_LOADER_H_

#include <string>
#include <memory>
#include "elf64.h"

class ElfImage {
public:
    ElfImage(std::ifstream &ifs);

    void dump(std::ostream &os);

private:
    Elf64_Ehdr elf_header;
    std::unique_ptr<Elf64_Shdr[]> section_headers;
    std::unique_ptr<char[]> strings;
    std::unique_ptr<Elf64_Phdr[]> program_headers;
};

#endif//__INC_LOADER_H_

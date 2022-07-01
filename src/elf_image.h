#ifndef __INC_ELF_IMAGE_H_
#define __INC_ELF_IMAGE_H_

#include <istream>
#include <string>
#include <memory>
#include "elf64.h"

class ElfImage {
public:
    ElfImage(std::istream &is);

    void dump(std::ostream &os);

private:
    void allocateMemory();
    void loadSegment(const Elf64_Phdr &header, std::istream &is);

    Elf64_Ehdr elf_header;
    std::unique_ptr<Elf64_Shdr[]> section_headers;
    std::unique_ptr<char[]> strings;
    std::unique_ptr<Elf64_Phdr[]> program_headers;

    std::unique_ptr<char[]> image_base;
};

#endif//__INC_ELF_IMAGE_H_

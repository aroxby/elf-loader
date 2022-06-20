#include <map>
#include <string>
#include "elf_common.h"
#include "elf_decoding.h"

const std::map<int, std::string> SECTION_TYPES = {
    {SHT_NULL, "inactive"},
    {SHT_PROGBITS, "program defined information"},
    {SHT_SYMTAB, "symbol table section"},
    {SHT_STRTAB, "string table section"},
    {SHT_RELA, "relocation section with addends"},
    {SHT_HASH, "symbol hash table section"},
    {SHT_DYNAMIC, "dynamic section"},
    {SHT_NOTE, "note section"},
    {SHT_NOBITS, "no space section"},
    {SHT_REL, "relocation section - no addends"},
    {SHT_SHLIB, "reserved - purpose unknown"},
    {SHT_DYNSYM, "dynamic symbol table section"},
    {SHT_INIT_ARRAY, "Initialization function pointers"},
    {SHT_FINI_ARRAY, "Termination function pointers"},
    {SHT_PREINIT_ARRAY, "Pre-initialization function pointers"},
    {SHT_GROUP, "Section group."},
    {SHT_SYMTAB_SHNDX, "Section indexes"},
    {SHT_GNU_HASH, "Hash"},
    {SHT_GNU_LIBLIST, "Library List"},
    {SHT_GNU_verdef, "Symbol versions provided"},
    {SHT_GNU_verneed, "Symbol versions required"},
    {SHT_GNU_versym, "Symbol version table"},
    {SHT_AMD64_UNWIND, "unwind information"},
};

const std::string UNKNOWN_SECTION_NAME = "Unknown";

const std::string &getSectionTypeName(int type) {
    auto iterator = SECTION_TYPES.find(type);
    if(iterator == SECTION_TYPES.end()) {
        return UNKNOWN_SECTION_NAME;
    } else {
        return iterator->second;
    }
}

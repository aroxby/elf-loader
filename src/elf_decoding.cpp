#include <map>
#include <string>
#include <sstream>
#include "elf_common.h"
#include "elf_decoding.h"

typedef std::map<int, std::string> Index;

const std::string &getNameOrUnknown(const Index &map, int type) {
    const static std::string unkown_name = "Unknown";
    auto iterator = map.find(type);
    if(iterator == map.end()) {
        return unkown_name;
    } else {
        return iterator->second;
    }
}

const std::string &getElfTypeName(int type) {
    const static Index elf_types = {
        {ET_REL, "Relocatable"},
        {ET_EXEC, "Executable"},
        {ET_DYN, "Shared object"},
        {ET_CORE, "Core file"},
    };
    return getNameOrUnknown(elf_types, type);
}

const std::string &getSectionTypeName(int type) {
    const static Index section_types = {
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
    return getNameOrUnknown(section_types, type);
}

const std::string &getSegmentTypeName(int type) {
    const static Index segment_types = {
        {PT_NULL, "Unused"},
        {PT_LOAD, "Loadable segment"},
        {PT_DYNAMIC, "Dynamic linking information segment"},
        {PT_INTERP, "Pathname of interpreter"},
        {PT_NOTE, "Auxiliary information"},
        {PT_SHLIB, "Reserved"},
        {PT_PHDR, "Location of program header itself"},
        {PT_TLS, "Thread local storage segment"},
        {PT_SUNW_UNWIND, "AMD64 UNWIND program header"},
        {PT_GNU_EH_FRAME, "Gnu EH Frame?"},
        {PT_GNU_STACK, "Gnu Stack?"},
        {PT_GNU_RELRO, "Gnu Relocate?"},
        {PT_GNU_PROPERTY, "Gnu Property?"},
        {PT_DUMP_DELTA, "Map for kernel Dumps"},
        {PT_SUNWBSS, "Sun Specific segment"},
        {PT_SUNWSTACK, "Describes the stack segment"},
        {PT_SUNWDTRACE, "Private"},
        {PT_SUNWCAP, "Hard/soft capabilities segment"},
    };
    return getNameOrUnknown(segment_types, type);
}

std::string flagsToString(const Index &map, int flags) {
    const static std::string sep(" | ");
    const static std::string extra("?");

    if(!flags) {
        return "";
    } else {
        std::stringstream sstream;
        for(auto iterator : map) {
            if(flags & iterator.first) {
                sstream << sep << iterator.second;
            }
            flags &= ~iterator.first;
        }
        if(flags) {
            sstream << sep << extra;
        }

        std::string flags_str = sstream.str();
        flags_str.erase(0, sep.length());
        return flags_str;
    }
}

std::string sectionFlagsToString(int flags) {
    const static Index section_flags = {
        {SHF_WRITE, "SHF_WRITE"},
        {SHF_ALLOC, "SHF_ALLOC"},
        {SHF_EXECINSTR, "SHF_EXECINSTR"},
        {SHF_MERGE, "SHF_MERGE"},
        {SHF_STRINGS, "SHF_STRINGS"},
        {SHF_INFO_LINK, "SHF_INFO_LINK"},
        {SHF_LINK_ORDER, "SHF_LINK_ORDER"},
        {SHF_OS_NONCONFORMING, "SHF_OS_NONCONFORMING"},
        {SHF_GROUP, "SHF_GROUP"},
        {SHF_TLS, "SHF_TLS"},
        {SHF_MASKOS, "SHF_MASKOS"},
        {SHF_MASKPROC, "SHF_MASKPROC"},
    };
    return flagsToString(section_flags, flags);
}

std::string segmentFlagsToString(int flags) {
    const static Index segment_flags = {
        {PF_X, "PF_X"},
        {PF_W, "PF_W"},
        {PF_R, "PF_R"},
        {PF_MASKOS, "PF_MASKOS"},
        {PF_MASKPROC, "PF_MASKPROC"},
    };
    return flagsToString(segment_flags, flags);
}

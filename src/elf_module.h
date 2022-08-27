#ifndef __INC_ELF_MODULE_H_
#define __INC_ELF_MODULE_H_

#include <map>
#include <string>
#include "elf_image.h"

class ElfModule : public ElfImage {
public:
    typedef std::map<const std::string, const void *> DynamicShims;

    ElfModule(const DynamicShims &shims, std::istream &is);

private:
    void processRelocations();
    void processRelocation(Elf64_Addr offset, Elf64_Xword type, Elf64_Sxword addend, const char *symbol_name);
    const void *getShim(const char *symbol_name) const;

    DynamicShims shims;
};

#endif//__INC_ELF_MODULE_H_

#include <cstring>
#include <string>
#include "exceptions.h"

UnexpectedRelocationType::UnexpectedRelocationType(const std::string &type) {
    static const char *prefix = "Unexpected relocation type: ";
    const char *type_str = type.c_str();
    msg = new char[strlen(prefix) + strlen(type_str) + 1];
    strcpy(msg, prefix);
    strcat(msg, type_str);
}

UnresolvedSymbol::UnresolvedSymbol(const std::string &name) {
    static const char *prefix = "Unresolved symbol: ";
    const char *name_str = name.c_str();
    msg = new char[strlen(prefix) + strlen(name_str) + 1];
    strcpy(msg, prefix);
    strcat(msg, name_str);
}

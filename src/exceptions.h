#ifndef __INC_EXCEPTIONS_H_
#define __INC_EXCEPTIONS_H_

#include <exception>
#include <string>

class ElfLoaderException : public std::exception {};

class InvalidSignature : public ElfLoaderException {
public:
    const char *what() const noexcept {
        return "File does not identify as ELF";
    }
};

class IncompatibleMachineType : public ElfLoaderException {
public:
    const char *what() const noexcept {
        return "Incompatible machine type";
    }
};

class IncompatibleVersion : public ElfLoaderException {
public:
    const char *what() const noexcept {
        return "Incompatible ELF version";
    }
};

class UnsupportedSectionConfiguration : public ElfLoaderException {
public:
    const char *what() const noexcept {
        return "File section size is not supported";
    }
};

class UnsupportedSymbolConfiguration : public ElfLoaderException {
public:
    const char *what() const noexcept {
        return "File symbol size is not supported";
    }
};

class UnexpectedSectionType : public ElfLoaderException {
public:
    const char *what() const noexcept {
        return "Encounter unknown section type";
    }
};

class UnexpectedRelocationType : public ElfLoaderException {
public:
    UnexpectedRelocationType(const std::string &type);

    const char *what() const noexcept {
        return msg;
    }

private:
    char *msg;
};

class UnresolvedSymbol : public ElfLoaderException {
public:
    UnresolvedSymbol(const std::string &name);

    const char *what() const noexcept {
        return msg;
    }

private:
    char *msg;
};

#endif//__INC_EXCEPTIONS_H_

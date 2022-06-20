#include <exception>

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

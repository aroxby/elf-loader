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
        return "Specified machine type not compatible";
    }
};

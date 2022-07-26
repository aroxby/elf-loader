#ifndef __INC_DYNAMIC_ARRAY_H_
#define __INC_DYNAMIC_ARRAY_H_

#include <memory>

template <typename DataType>
class DynamicArray {
public:
    DynamicArray() : ptr(), length() { }
    DynamicArray(std::shared_ptr<DataType[]> ptr, size_t length) : ptr(ptr), length(length) { }

    DataType &operator*() const { return ptr[0]; }
    DataType &operator[](size_t index) const { return ptr[index]; }

    size_t getLength() const { return length; }

    DataType *begin() const {
        return &ptr[0];
    }

    DataType *end() const {
        return &ptr[length];
    }

private:
    std::shared_ptr<DataType[]> ptr;
    size_t length;
};

#endif//__INC_DYNAMIC_ARRAY_H_

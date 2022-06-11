LIB_DIR=example-lib
LIB_SRCS=$(shell find $(LIB_DIR) -name *.cpp)
LIB_OBJS=$(subst .cpp,.o,$(LIB_SRCS))
LIB_TARGET=example-lib.so
LIB_LDFLAGS=-shared

SRC_DIR=src
SRCS=$(shell find $(SRC_DIR) -name *.cpp)
OBJS=$(subst .cpp,.o,$(SRCS))
TARGET=elf-loader

CPP=g++

.PHONY: all tidy tidy-all clean clean-all example-lib

all: $(TARGET)

example-lib: $(LIB_TARGET)

%.o: %.cpp
	$(CPP) $(CPPFLAGS) -c $< -o $@

$(LIB_TARGET): $(LIB_OBJS)
	$(CPP) $^ $(LIB_LDFLAGS) -o $@

$(TARGET): $(OBJS)
	$(CPP) $^ $(LDFLAGS) -o $@

tidy:
	rm -f $(OBJS)

tidy-all: tidy
	rm -f $(LIB_OBJS)

clean: tidy
	rm -f $(TARGET)

clean-all: clean tidy-all
	rm -f $(LIB_TARGET)

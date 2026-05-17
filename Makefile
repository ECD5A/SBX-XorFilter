CXX = g++
CC = gcc
AR = ar

CXXFLAGS ?= -O3 -std=c++11 -Wall -Wextra -Wno-unused-function
CFLAGS ?= -O3 -Wall -Wextra

ifeq ($(OS),Windows_NT)
RM_FILES = cmd /C del /Q
RM_REDIRECT = 2>NUL
else
RM_FILES = rm -f
RM_REDIRECT =
endif

TARGET = libsbx-xorfilter.a
OBJS = xorfilter.o sbx_hash64.o

default: $(TARGET)

$(TARGET): $(OBJS)
	$(AR) rcs $@ $(OBJS)

xorfilter.o: xorfilter.cpp xorfilter.h sbx_hash64.h
	$(CXX) $(CXXFLAGS) -c xorfilter.cpp -o $@

sbx_hash64.o: sbx_hash64.c sbx_hash64.h
	$(CC) $(CFLAGS) -c sbx_hash64.c -o $@

clean:
	$(RM_FILES) $(TARGET) $(OBJS) $(RM_REDIRECT)

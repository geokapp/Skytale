#
# Specify the compiler
#
CXX = g++

#
# Compiler options
#
CXXFLAGS = -Isrc -rdynamic
LIBS = -ldl -lcryptopp -liris $(OPTLIBS)

#
# Installation prefix
#
PREFIX?=/usr/local

SOURCES=$(wildcard src/**/*.cc src/*.cc)
OBJECTS=$(patsubst %.cc,%.o,$(SOURCES))

TEST_SOURCES=$(wildcard tests/*.cc)
TEST_OBJECTS=$(patsubst %.cc,%.o,$(TEST_SOURCES))

TARGET=build/libskytale.a
SO_TARGET=$(patsubst %.a,%.so,$(TARGET))

#
# Build the library
#
all: $(TARGET) $(SO_TARGET) tests

dev: CXXFLAGS=-g -Wall -Isrc -Wall -Wextra $(OPTFLAGS)
dev: all

$(TARGET): CXXFLAGS += -fPIC
$(TARGET): build $(OBJECTS)
	ar rcs $@ $(OBJECTS)
	ranlib $@

$(SO_TARGET): $(TARGET) $(OBJECTS)
	$(CXX) -shared -o $@ $(OBJECTS)

build:
	@mkdir -p build

#
# Build the unit tests
#
.PHONY: tests
tests: CXXFLAGS += $(TARGET)
tests: $(TEST_OBJECTS)

$(TEST_OBJECTS): %.o: %.cc
	$(CXX) -o $(patsubst %.o,%,$@) $< $(TARGET) $(LIBS)

#
# Cleaning
#
clean:
	rm -rf build $(OBJECTS) $(TEST_OBJECTS)
	find . -name "*.gc*" -exec rm {} \;
	rm -rf `find . -name "*dSYM" -print`

#
# Installing
#
install: all
	install -d $(DESTDIR)/$(PREFIX)/lib/
	install $(TARGET) $(DESTDIR)/$(PREFIX)/lib/
	@mkdir -p $(DESTDIR)/$(PREFIX)/include/skytale
	install src/*.h $(DESTDIR)/$(PREFIX)/include/skytale/.

#
# Removing
#
remove:
	rm -rf $(DESTDIR)/$(PREFIX)/lib/libskytale.*
	rm -rf $(DESTDIR)/$(PREFIX)/include/libskytale*

# Checker
BADFUNCS='[^_.>a-zA-Z0-9](str(n?cpy|n?cat|xfrm|n?dup|str|pbrk|tok|_)|stpn?cpy|a?sn?printf|byte_)'
check:
	@echo "Files with potentially dangerous functions."
	@egrep $(BADFUNCS) $(SOURCES) || true

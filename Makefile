OS=$(shell uname -s)

CC = gcc
CFLAGS = -std=c99 -DFH_USE_MAIN_FUNC=1
LDFLAGS =
LIBS = -lm -ldl

ifeq ($(OS), Darwin)
	LIBS := $(filter-out -ldl,$(LIBS))
endif
ifeq ($(OS), OpenBSD)
	CC = clang
	LIBS := $(filter-out -ldl,$(LIBS))
endif


ifeq ($(OS), Windows_NT)
	CC = x86_64-w64-mingw32-gcc
endif 

OBJS = src/main.o src/functions.o
OBJS += src/crypto/bcrypt.o src/crypto/mt19937.o src/crypto/mt19937-jump.o src/crypto/md5.o \
		src/tar/microtar.o src/regex/re.o src/vec/vec.o src/map/map.o src/util.o src/input.o src/buffer.o src/stack.o src/symtab.o \
		src/operator.o src/tokenizer.o src/parser.o src/ast.o src/dump_ast.o \
		src/compiler.o src/dump_bytecode.o src/vm.o src/gc.o \
		src/map.o src/value.o src/src_loc.o src/program.o src/c_funcs.o
SRCS=$(patsubst %.o,%.c,$(OBJS)) 

CHECK_SCRIPT = tests/test.fh

# Possible inputs: debug, debug2, release and asan.
# Note: leave no spaces behind or after the equal sign below
TARGETS =debug

#-Wundef: undefined macro variables used in #if.
#-Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations: make sure that functions are prototyped properly.
ifeq ($(TARGETS), debug)
	CFLAGS += -O0 -g3 -pedantic -Wall -Wextra -Wundef -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations
endif
ifeq ($(TARGETS), debug2) # Used for gprof
	CFLAGS += -O0 -g3 -pedantic-errors -pg -Wall -Wextra -Wundef -no-pie
endif
ifeq ($(TARGETS), release)
	CFLAGS += -O3
endif
ifeq ($(TARGETS), asan)
	CFLAGS += -fsanitize=address -fno-omit-frame-pointer -O -g -Wall -Wextra
endif

all: build

build: fh
	@echo
	@echo "Compilation successful!  Try these examples:"
	@echo
	@echo "  ./fh tests/test.fh"
	@echo "  ./fh tests/mandelbrot.fh"
	@echo "  ./fh tests/mandel_color.fh"
	@echo

fh: $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

.c.o:
	$(CC) $(CFLAGS) -o $@ -c $<

check: debug
	valgrind --track-origins=yes --leak-check=full --show-leak-kinds=all ./fh -d $(CHECK_SCRIPT) arg1 arg2

test: debug
	./fh tests/mandel_color.fh

install:
ifeq ($(OS), Linux)
	sudo mkdir -p /usr/local/include/fh /usr/local/include/fh/map /usr/local/include/fh/vec /usr/local/include/fh/regex /usr/local/include/fh/tar /usr/local/include/fh/crypto
	sudo cp src/*.h /usr/local/include/fh
	sudo cp src/map/*.h /usr/local/include/fh/map/
	sudo cp src/vec/*.h /usr/local/include/fh/vec/
	sudo cp src/tar/*.h /usr/local/include/fh/tar/
	sudo cp src/crypto/*.h /usr/local/include/fh/crypto/
	sudo cp src/regex/*.h /usr/local/include/fh/regex
	sudo cp fh /usr/local/bin
endif
ifeq ($(OS), OpenBSD)
	mkdir -p /usr/local/include/fh /usr/local/include/fh/map /usr/local/include/fh/vec /usr/local/include/fh/regex /usr/local/include/fh/tar /usr/local/include/fh/crypto
	cp src/*.h /usr/local/include/fh
	cp src/map/*.h /usr/local/include/fh/map/
	cp src/vec/*.h /usr/local/include/fh/vec/
	cp src/tar/*.h /usr/local/include/fh/tar/
	cp src/crypto/*.h /usr/local/include/fh/crypto/
	cp src/regex/*.h /usr/local/include/fh/regex
	cp fh /usr/local/bin
endif
ifeq ($(OS), Darwin)
	sudo mkdir -p /usr/local/include/fh /usr/local/include/fh/map /usr/local/include/fh/vec /usr/local/include/fh/regex /usr/local/include/fh/tar /usr/local/include/fh/crypto
	sudo cp src/*.h /usr/local/include/fh
	sudo cp src/map/*.h /usr/local/include/fh/map/
	sudo cp src/vec/*.h /usr/local/include/fh/vec/
	sudo cp src/tar/*.h /usr/local/include/fh/tar/
	sudo cp src/crypto/*.h /usr/local/include/fh/crypto/
	sudo cp src/regex/*.h /usr/local/include/fh/regex
	sudo cp fh /usr/local/bin
endif
#TODO: What about Windows?

uninstall:
ifeq ($(OS), Linux)
	sudo rm -rf /usr/local/bin/fh
	sudo rm -rf /usr/local/include/fh
endif
ifeq ($(OS), Darwin)
	sudo rm -rf /usr/local/bin/fh
	sudo rm -rf /usr/local/include/fh
endif
#TODO: What about Windows?

#----------Create custom dynamic library for testing purpose-------------#
ifeq ($(OS), Linux)
test_dynamic_lib:
	$(CC) -I/usr/local/include/fh -c $(CFLAGS) -fPIC tests/dynamic_libraries/*.c
	$(CC) -shared -fPIC $(SRCS) -o libcustom.so custom_library.o $(LIBS)
	mv libcustom.so tests/dynamic_libraries/
	rm -f custom_library.o
endif
ifeq ($(OS), OpenBSD)
test_dynamic_lib:
	$(CC) -I/usr/local/include/fh -c $(CFLAGS) -fPIC tests/dynamic_libraries/*.c
	$(CC) -shared -fPIC $(SRCS) -o libcustom.so custom_library.o $(LIBS)
	mv libcustom.so tests/dynamic_libraries/
	rm -f custom_library.o
endif
ifeq ($(OS), Darwin)
test_dynamic_lib:
	$(CC) -c $(CFLAGS) tests/dynamic_libraries/*.c
	$(CC) -dynamiclib $(SRCS) -o libcustom.dylib custom_library.o $(LIBS)
	mv libcustom.dylib tests/dynamic_libraries/
	rm -f custom_library.o
endif 
ifeq ($(OS), Windows_NT)
test_dynamic_lib:
	$(CC) -c $(CFLAGS) -fPIC tests/dynamic_libraries/*.c
	$(CC) -shared -fPIC $(SRCS) -o libcustom.dll custom_library.o $(LIBS)
	mv libcustom.so tests/dynamic_libraries/
	rm -f custom_library.o
endif
#----------END Create custom dynamic library for testing purpose-------------#

asan:
	$(MAKE) clean
	$(MAKE) CFLAGS="$(CFLAGS) -fsanitize=address -fno-omit-frame-pointer -g -O1" \
	        LDFLAGS="$(LDFLAGS) -fsanitize=address" \
	        fh

clean:
	find src -name "*.o" -type f -delete
	rm -f fh src/*.o *~ src/lib/*.o src/map/*.o tests/dynamic_libraries/*.so

.PHONY: $(TARGETS) build clean check test dump_exported_symbols dynamic_lib_test install uninstall

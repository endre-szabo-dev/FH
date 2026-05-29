/* program.h */

#ifndef PROGRAM_H_FILE
#define PROGRAM_H_FILE

#include "fh.h"
#include "ast.h"
#include "bytecode.h"
#include "vm.h"
#include "parser.h"
#include "compiler.h"
#include "value.h"

#include "map/map.h"
#include "vec/vec.h"

#ifdef FH_OS_UNIX
#include <dlfcn.h> /* used for dlopen */
#elif FH_OS_WINDOWS
#include <windows.h>
#endif

struct named_c_func {
    const char *name;
    fh_c_func func;
};

DECLARE_STACK(named_c_func_stack, struct named_c_func);
DECLARE_STACK(p_closure_stack, struct fh_closure *);
DECLARE_STACK(p_object_stack, union fh_object *);

struct fh_program {
    char last_error_msg[512];
    uint32_t gc_frequency;
    size_t gc_collect_at;
    bool gc_isPaused;
    int alive_objects;
    struct fh_value null_value;
    struct fh_parser parser;
    struct fh_compiler compiler;
    struct fh_symtab src_file_names;
    struct named_c_func_stack c_funcs;
    struct fh_vm vm; // GC roots (VM stack)
    //struct p_closure_stack global_funcs;   // GC roots (global functions)
    vec_void_t pinned_objs; //struct p_object_stack pinned_objs;     // GC roots (temporarily pinned objects)
    vec_void_t c_vals; // GC roots (values held by running C functions)
    union fh_object *objects; // all created objects
    map_t(struct fh_closure*) global_funcs_map;

    map_void_t c_funcs_map;
};

void *fh_load_dynamic_library(const char *path, struct fh_program *prog);

#endif /* PROGRAM_H_FILE */

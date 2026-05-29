/* functions.c */

#include <stdlib.h>
#include <stdio.h>
#include "fh.h"

#include "functions.h"

#if defined (__linux__)
#include <sys/ioctl.h>
#elif defined (_WIN32)
#include <windows.h>
#endif

int add_functions(struct fh_program *prog) {
#define ADD_FUNC(name) { #name, fn_##name }
    static const struct fh_named_c_func c_funcs[] = {};
    return fh_add_c_funcs(prog, c_funcs, sizeof(c_funcs) / sizeof(c_funcs[0]));
}

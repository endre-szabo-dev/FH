/* fh.c */

#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include "program.h"
#include "fh.h"

void fh_init() {
    fh_programs_vector = malloc(sizeof(vec_void_t));
    vec_init(fh_programs_vector);
    fh_is_packed = false;
    fh_main_file_packed = "main.fh";
    fh_started_pack = false;

    vec_init(&fh_dynamic_libraries);

    // see fh_internal.h
    fh_type_size[FH_VAL_NULL] = 0;
    fh_type_size[FH_VAL_BOOL] = sizeof(bool);
    fh_type_size[FH_VAL_FLOAT] = sizeof(double);
    fh_type_size[FH_VAL_C_FUNC] = sizeof(fh_c_func);
    fh_type_size[FH_VAL_ARRAY] = sizeof(struct fh_array);
    fh_type_size[FH_VAL_MAP] = sizeof(struct fh_map);
    fh_type_size[FH_VAL_UPVAL] = sizeof(struct fh_upval);
    fh_type_size[FH_VAL_CLOSURE] = sizeof(struct fh_closure);
    fh_type_size[FH_VAL_C_OBJ] = sizeof(struct fh_c_obj);
    fh_type_size[FH_VAL_FUNC_DEF] = sizeof(struct fh_func_def);

    bcrypt_init();

    mt19937_generator = malloc(sizeof(mt19937_state));
    mt19937_seed(mt19937_generator, time(NULL));
}

void fh_deinit(struct fh_program *prog) {
    free(mt19937_generator);

    if (fh_is_packed)
        mtar_close(&fh_tar);

    for (int i = 0; i < fh_dynamic_libraries.length; i++) {
        void *handle = fh_dynamic_libraries.data[i];
#ifdef FH_OS_UNIX
        dlclose(handle);
#elif defined(FH_OS_WINDOWS)
        FreeLibrary(handle);
#endif
    }
    vec_deinit(&fh_dynamic_libraries);

    if (fh_programs_vector) {
        for (size_t i = 0; i < fh_programs_vector->length; i++) {
            struct fh_program *p = fh_programs_vector->data[i];
            if (p && p != prog) {
                fh_free_program(p);
            }
        }
        vec_deinit(fh_programs_vector);
        free(fh_programs_vector);
        fh_programs_vector = NULL;
    }

    if (prog) {
        fh_free_program(prog);
    }
}

struct fh_program *fh_new_program(void) {
    struct fh_program *prog = malloc(sizeof(struct fh_program));
    if (!prog)
        return NULL;
    prog->gc_frequency = 0;
    prog->gc_collect_at = 1000000;
    prog->gc_isPaused = false;
    prog->alive_objects = 0;
    prog->objects = NULL;
    prog->null_value.type = FH_VAL_NULL;
    prog->last_error_msg[0] = '\0';
    fh_init_symtab(&prog->src_file_names);
    named_c_func_stack_init(&prog->c_funcs);

    fh_init_vm(&prog->vm, prog);
    fh_init_parser(&prog->parser, prog);
    fh_init_compiler(&prog->compiler, prog);
    // p_object_stack_init(&prog->pinned_objs);

    map_init(&prog->global_funcs_map);
    map_init(&prog->c_funcs_map);

    vec_init(&prog->c_vals);
    vec_init(&prog->pinned_objs);


    if (fh_add_c_funcs(prog, fh_std_c_funcs, fh_std_c_funcs_len) < 0)
        goto err;

    fh_running = true;
    return prog;

err:
    map_deinit(&prog->global_funcs_map);
    map_deinit(&prog->c_funcs_map);
    fh_destroy_symtab(&prog->src_file_names);
    // p_closure_stack_free(&prog->global_funcs);
    // p_object_stack_free(&prog->pinned_objs);
    named_c_func_stack_free(&prog->c_funcs);
    vec_deinit(&prog->c_vals);
    vec_deinit(&prog->pinned_objs);

    fh_destroy_compiler(&prog->compiler);
    fh_destroy_parser(&prog->parser);
    free(prog);
    return NULL;
}

void fh_free_program(struct fh_program *prog) {
    prog->gc_isPaused = false;
    // if (p_object_stack_size(&prog->pinned_objs) > 0)
    if (prog->pinned_objs.length > 0)
        fprintf(stderr, "*** WARNING: %d pinned object(s) on exit\n", prog->pinned_objs.length);
    //p_object_stack_size(&prog->pinned_objs));

    fh_destroy_symtab(&prog->src_file_names);
    // p_object_stack_free(&prog->pinned_objs);
    named_c_func_stack_free(&prog->c_funcs);

    fh_collect_garbage(prog);
    fh_free_program_objects(prog);

    fh_destroy_vm(&prog->vm);
    fh_destroy_compiler(&prog->compiler);
    fh_destroy_parser(&prog->parser);

    map_deinit(&prog->global_funcs_map);
    map_deinit(&prog->c_funcs_map);
    vec_deinit(&prog->c_vals);
    vec_deinit(&prog->pinned_objs);

    free(prog);
}

const char *fh_get_error(struct fh_program *prog) {
    int frame_index = call_frame_stack_size(&prog->vm.call_stack) - 1;
    if (frame_index >= 0) {
        struct fh_vm_call_frame *frame;
        printf("CALLSTACK BEGIN:\n");
        do {
            frame = call_frame_stack_item(&prog->vm.call_stack, frame_index);
            if (frame && frame->closure) {
                struct fh_func_def *func_def = frame->closure->func_def;
                int32_t addr = prog->vm.pc - func_def->code;

                char *closure_name = "?";
                if (frame->closure->func_def && frame->closure->func_def->name) {
                    closure_name = GET_OBJ_STRING_DATA(frame->closure->func_def->name);
                }

                printf(" %s - %s:%d:%d\n",
                       fh_get_symbol_name(&prog->src_file_names, func_def->code_creation_loc.file_id),
                       closure_name,
                       func_def->code_creation_loc.line,
                       func_def->code_creation_loc.col);
            }

            frame_index--;
        } while (frame && frame_index >= 0);
        printf("CALLSTACK END\n");
    }


    if (prog->vm.last_error_addr < 0)
        return prog->last_error_msg;

    char tmp[512];
    struct fh_src_loc *last_func = &prog->compiler.last_func_call;
    struct fh_src_loc *loc = &prog->vm.last_error_loc;

    /*
     *
     * The logic:
     * Whenever you call a function the PC will be modified in a lower value
     * because you first have to define the function for it to be callable.
     * Meaning the PC will become lower than the current value when the function
     * needs to be executed.
     *
     * Note: last_func will always be initialized because of the need of
     * having "function main". If that function is missing an error will be
     * issued not called from here.
     */
    if (loc->line > last_func->line) {
        snprintf(tmp, sizeof(tmp), "%s:%d:%d: %s",
                 fh_get_symbol_name(&prog->src_file_names, loc->file_id),
                 loc->line, loc->col, prog->last_error_msg);
    } else {
        snprintf(tmp, sizeof(tmp), "%s:%d:%d: %s\nlast called from: %s:%d:%d",
                 fh_get_symbol_name(&prog->src_file_names, loc->file_id),
                 loc->line, loc->col, prog->last_error_msg,
                 fh_get_symbol_name(&prog->src_file_names, last_func->file_id),
                 last_func->line, last_func->col);
    }

    size_t size = (sizeof(tmp) > sizeof(prog->last_error_msg))
                      ? sizeof(prog->last_error_msg)
                      : sizeof(tmp);
    memcpy(prog->last_error_msg, tmp, size);
    return prog->last_error_msg;
}

int fh_set_error(struct fh_program *prog, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(prog->last_error_msg, sizeof(prog->last_error_msg), fmt, ap);
    va_end(ap);
    prog->vm.last_error_addr = -1;
    fh_running = false;
    return -1;
}

int fh_set_verror(struct fh_program *prog, const char *fmt, va_list ap) {
    vsnprintf(prog->last_error_msg, sizeof(prog->last_error_msg), fmt, ap);
    prog->vm.last_error_addr = -1;
    return -1;
}

int fh_get_pin_state(struct fh_program *prog) {
    // return p_object_stack_size(&prog->pinned_objs);
    return prog->pinned_objs.length;
}

void fh_restore_pin_state(struct fh_program *prog, int state) {
    /* if (state > p_object_stack_size(&prog->pinned_objs)) {
        fprintf(stderr, "ERROR: invalid pin state\n");
        return;
    }
    p_object_stack_set_size(&prog->pinned_objs, state);
	*/
    if (state > prog->pinned_objs.length) {
        fprintf(stderr, "ERROR: invalid pin state\n");
        return;
    }
    prog->pinned_objs.length = state;
}

int fh_add_c_func(struct fh_program *prog, const char *name, fh_c_func func) {
    struct named_c_func **cfn
            = (struct named_c_func **) map_get(&prog->c_funcs_map, name);
    if (cfn) {
        fprintf(stderr, "Error: duplicating C function '%s'!\n", name);
        return -1;
    }
    struct named_c_func *cf = named_c_func_stack_push(&prog->c_funcs, NULL);
    if (!cf)
        return fh_set_error(prog, "out of memory");
    cf->name = name;
    cf->func = func;
    map_set(&prog->c_funcs_map, name, cf);
    return 0;
}

int fh_add_c_funcs(struct fh_program *prog, const struct fh_named_c_func *funcs,
                   int n_funcs) {
    for (int i = 0; i < n_funcs; i++)
        if (fh_add_c_func(prog, funcs[i].name, funcs[i].func) < 0)
            return -1;
    return 0;
}

const char *fh_get_c_func_name(struct fh_program *prog, fh_c_func func) {
    stack_foreach(struct named_c_func, *, c_func, &prog->c_funcs) {
        if (c_func->func == func)
            return c_func->name;
    }
    return NULL;
}

fh_c_func fh_get_c_func_by_name(struct fh_program *prog, const char *name) {
    struct named_c_func **func
            = (struct named_c_func **) map_get(&prog->c_funcs_map, name);
    if (func) {
        return (*func)->func;
    }
    return NULL;
}

int fh_add_global_func(struct fh_program *prog, struct fh_closure *closure) {
    struct fh_closure **val = (struct fh_closure **) map_get(
        &prog->global_funcs_map, GET_OBJ_STRING_DATA(closure->func_def->name));
    if (val) {
        if (closure->func_def->name != NULL) {
            *val = closure;
            return 0;
        }
    }
    map_set(&prog->global_funcs_map, GET_OBJ_STRING_DATA(closure->func_def->name), closure);
    return 0;
}

int fh_get_num_global_funcs(struct fh_program *prog) {
    int len = 0;
    const char *key;

    map_iter_t iter = map_iter(&prog->global_funcs_map);
    while ((/*key = */map_next(&prog->global_funcs_map, &iter))) {
        len++;
    }
    return len;
}

struct fh_closure *fh_get_global_func_by_index(struct fh_program *prog,
                                               int index) {
    int len = 0;
    const char *key;

    struct fh_closure **pc = NULL;
    map_iter_t iter = map_iter(&prog->global_funcs_map);
    while ((key = map_next(&prog->global_funcs_map, &iter))) {
        if (len == index) {
            pc = (struct fh_closure **) map_get(&prog->global_funcs_map, key);
            break;
        }
        len++;
    }
    return *pc;
}

struct fh_closure *fh_get_global_func_by_name(struct fh_program *prog, const char *name) {
    struct fh_closure **slot = map_get(&prog->global_funcs_map, name);
    return (slot && *slot) ? *slot : NULL;
}

int fh_compile_input(struct fh_program *prog, struct fh_input *in) {
    struct fh_ast *ast = fh_new_ast(&prog->src_file_names);
    if (!ast) {
        fh_close_input(in);
        fh_set_error(prog, "out of memory for AST");
        return -1;
    }
    if (fh_parse(&prog->parser, ast, in) < 0) {
        fh_set_error(prog, "can't parse '%s'", fh_get_input_filename(in));
        goto err;
    }

    // fh_dump_ast(ast);

    if (fh_compile(&prog->compiler, ast) < 0) {
        fh_set_error(prog, "can't compile AST");
        goto err;
    }

    fh_free_ast(ast);
    return 0;

err:
    fh_free_ast(ast);
    fh_close_input(in);
    return -1;
}

int fh_compile_pack(struct fh_program *prog, const char *path, bool is_mandatory) {
    struct fh_input *in = fh_open_input_pack(path);
    if (!in) {
        if (is_mandatory) {
            fh_set_error(prog, "can't open '%s' from pack", path);
        } else {
            fprintf(stderr, "warning: can't open '%s' from pack", path);
        }
        return -1;
    }
    return fh_compile_input(prog, in);
}

int fh_compile_file(struct fh_program *prog, const char *filename, bool is_mandatory) {
    struct fh_input *in = fh_open_input_file(filename);
    if (!in) {
        if (is_mandatory) {
            fh_set_error(prog, "can't open '%s'", filename);
        } else {
            fprintf(stderr, "warning: can't open '%s'", filename);
        }
        return -1;
    }
    return fh_compile_input(prog, in);
}

int fh_call_function(struct fh_program *prog, const char *func_name,
                     struct fh_value *args, int n_args, struct fh_value *ret) {
    struct fh_closure *closure = fh_get_global_func_by_name(prog, func_name);
    if (!closure)
        return fh_set_error(prog, "function '%s' doesn't exist", func_name);
    return fh_call_vm_function(&prog->vm, closure, args, n_args, ret);
}

void *fh_load_dynamic_library(const char *path, struct fh_program *prog) {
    int (*fh_register_library)(struct fh_program *);
    void *handle;

#ifdef FH_OS_UNIX
    // RTLD_LAZY: If specified, Linux is not concerned about unresolved symbols until they are referenced.
    // RTLD_NOW: All unresolved symbols resolved when dlopen() is called.
    handle = dlopen(path, RTLD_LAZY);
    if (!handle) {
        printf("ERROR: %s\n", dlerror());
        return NULL;
    }
    dlerror(); /* Clear any existing error */

    *(void **) (&fh_register_library) = dlsym(handle, "fh_register_library");
    if (!fh_register_library) {
        printf("Error loading 'fh_register_library' function from custom library. %s\n", dlerror());
        return NULL;
    }

    if (fh_register_library(prog) < 0) {
        printf("ERROR: Couldn't load library %s functions", path);
        return NULL;
    }
    vec_push(&fh_dynamic_libraries, handle);
#elif FH_OS_WINDOWS
    handle = LoadLibrary(path);
    if (!handle) {
        fprintf(stderr, "Failed to load: %s\n", path);
        return NULL;
    }
    *(void **) (&fh_register_library) = GetProcAddress(handle, "fh_register_library");
    if (!fh_register_library) {
        printf("ERROR: Couldn't load 'fh_register_library' function from custom library: %s\n", path);
        return NULL;
    }
    if (fh_register_library(prog) < 0) {
        printf("ERROR: Couldn't load library %s functions", path);
        return NULL;
    }
    vec_push(&fh_dynamic_libraries, handle);
#else
    perror("ERROR: Couldn't compile function 'fh_load_dynamic_library' on this OS, OS unsupported");
    exit(1);
    return NULL;
#endif
    return handle;
}


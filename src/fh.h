/* fh.h */

#ifndef FH_H_FILE
#define FH_H_FILE

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>

#include "tar/microtar.h"
#include "vec/vec.h"

// major, minor, release (month, day, year, minute)
#define FH_VERSION "1.0.rc6"

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32) || defined(__WIN32__)
#define FH_OS "windows"
#define FH_OS_WINDOWS
#endif
#if defined(__linux) || defined( __linux__)
#define FH_OS "linux"
#define FH_OS_LINUX
#endif
#if defined(__FreeBSD__) || defined(BSD) || defined(__OpenBSD__) || defined(__DragonFly__)
#define FH_OS "bsd"
#define FH_OS_BSD
#endif
#if defined(__APPLE__)
#define FH_OS "macOS"
#define FH_OS_MAC
#endif
#ifndef FH_OS
#define FH_OS "unknown"
#define FH_OS_UNKNOWN
#endif

#if defined(FH_OS_BSD) || defined(FH_OS_MAC) || defined(FH_OS_LINUX)
#define FH_OS_UNIX
#endif

#if defined(__GNUC__)
#define FH_PRINTF_FORMAT(x,y) __attribute__((format (printf, (x), (y))))
#else
#define FH_PRINTF_FORMAT(x,y)
#endif

#include "crypto/bcrypt.h"
/**
* Global instance for mt19937. Its seeds gets set once FH starts
*/
mt19937_state *mt19937_generator;

/* Used when you want to deconstruct a c-object */
typedef void (*fh_c_obj_gc_callback)(void *data);

struct fh_input;
struct fh_program;
struct fh_value;

struct fh_input_funcs {
    struct fh_input *(*open)(struct fh_input *in, const char *filename);

    int (*read)(struct fh_input *in, char *line, int max_len);

    int (*close)(struct fh_input *in);
};

enum fh_value_type {
    /* non-object values (completely contained inside struct fh_value)*/
    FH_VAL_NULL,
    FH_VAL_BOOL,
    FH_VAL_FLOAT,
    FH_VAL_C_FUNC,

#define FH_FIRST_OBJECT_VAL FH_VAL_STRING
    /* objects */
    FH_VAL_STRING,
    FH_VAL_ARRAY,
    FH_VAL_MAP,
    FH_VAL_UPVAL,
    FH_VAL_CLOSURE,
    FH_VAL_C_OBJ,
    FH_VAL_FUNC_DEF
};

typedef int (*fh_c_func)(struct fh_program *prog, struct fh_value *ret,
                         struct fh_value *args, int n_args);

struct fh_named_c_func {
    const char *name;
    fh_c_func func;
};

struct fh_value {
    union {
        void *obj;
        fh_c_func c_func;
        double num;
        bool b;
    } data;

    enum fh_value_type type;
};

/*
 * This vector is used for storing all the created
 * programs via eval() function (c_funcs.c).
 * We cannot release the created programs immediately
 * because we need to return the return value to the main program,
 * hence if we free the items we produce undefined behavior.
 * Solution: free every created program (with eval()) at the end of
 * running the main program struct.
 */
vec_void_t *fh_programs_vector;

void fh_init(void);

void fh_deinit(struct fh_program *prog);

struct fh_input *fh_open_input_file(const char *filename);

struct fh_input *fh_open_input_pack(const char *path);

struct fh_input *fh_open_input_string(const char *string);

struct fh_input *fh_new_input(const char *filename, void *user_data, struct fh_input_funcs *funcs);

void *fh_get_input_user_data(struct fh_input *in);

const char *fh_get_input_filename(struct fh_input *in);

struct fh_input *fh_open_input(struct fh_input *in, const char *filename);

int fh_close_input(struct fh_input *in);

int fh_read_input(struct fh_input *in, char *line, int max_len);

struct fh_program *fh_new_program(void);

void fh_free_program(struct fh_program *prog);

int fh_add_c_func(struct fh_program *prog, const char *name, fh_c_func func);

int fh_add_c_funcs(struct fh_program *prog, const struct fh_named_c_func *funcs, int n_funcs);

int fh_compile_input(struct fh_program *prog, struct fh_input *in);

/**
 * when @param is_mandatory is set to "false" then if opening the file fails the language won't stop from running
*/
int fh_compile_file(struct fh_program *prog, const char *filename, bool is_mandatory);

int fh_compile_pack(struct fh_program *prog, const char *path, bool is_mandatory);

void fh_dump_bytecode(struct fh_program *prog);

int fh_call_function(struct fh_program *prog, const char *func_name,
                     struct fh_value *args, int n_args, struct fh_value *ret);

const char *fh_get_error(struct fh_program *prog);

int fh_set_error(struct fh_program *prog, const char *fmt, ...) FH_PRINTF_FORMAT(2, 3);

int fh_set_verror(struct fh_program *prog, const char *fmt, va_list ap);

void fh_collect_garbage(struct fh_program *prog);

bool fh_val_is_true(struct fh_value *val);

bool fh_vals_are_equal(struct fh_value *v1, struct fh_value *v2);

#define fh_is_null(v)     ((v)->type == FH_VAL_NULL)
#define fh_is_bool(v)     ((v)->type == FH_VAL_BOOL)
#define fh_is_number(v)   ((v)->type == FH_VAL_FLOAT)
#define fh_is_c_obj(v)    ((v)->type == FH_VAL_C_OBJ)
#define fh_is_c_func(v)   ((v)->type == FH_VAL_C_FUNC)
#define fh_is_string(v)   ((v)->type == FH_VAL_STRING)
#define fh_is_closure(v)  ((v)->type == FH_VAL_CLOSURE)
#define fh_is_array(v)    ((v)->type == FH_VAL_ARRAY)
#define fh_is_map(v)      ((v)->type == FH_VAL_MAP)

#define fh_new_null()     ((struct fh_value) { .type = FH_VAL_NULL })

#define fh_new_bool(bv)   ((struct fh_value) { .type = FH_VAL_BOOL, .data = { .b = !!(bv) }})
#define fh_get_bool(v)    ((v)->data.b)

#define fh_new_c_func(f)  ((struct fh_value) { .type = FH_VAL_C_FUNC, .data = { .c_func = (f) }})
#define fh_get_c_func(v)  ((v)->data.c_func)

#define fh_new_number(n)  ((struct fh_value) { .type = FH_VAL_FLOAT, .data = { .num = (n) }})
#define fh_get_number(v)  ((v)->data.num)

struct fh_value fh_new_c_obj(struct fh_program *prog, void *ptr, fh_c_obj_gc_callback callback, int type);

#define fh_get_c_obj(v) ((struct fh_c_obj*) GET_VAL_OBJ(v))
#define fh_get_c_obj_value(v) ((struct fh_c_obj*)((v)->data.obj))->ptr

struct fh_c_obj *fh_make_c_obj(struct fh_program *prog, bool pinned, void *ptr, fh_c_obj_gc_callback callback);

struct fh_value fh_new_string(struct fh_program *prog, const char *str);

struct fh_value fh_new_string_n(struct fh_program *prog, const char *str, size_t str_len);

const char *fh_get_string(const struct fh_value *str);

struct fh_value fh_new_array(struct fh_program *prog);

int fh_get_array_len(const struct fh_value *arr);

struct fh_value *fh_get_array_item(struct fh_value *arr, uint32_t index);

struct fh_value *fh_grow_array(struct fh_program *prog, struct fh_value *val, uint32_t num_items);

struct fh_value fh_new_map(struct fh_program *prog);

int fh_alloc_map_len(struct fh_value *map, uint32_t len);

int fh_next_map_key(struct fh_value *map, struct fh_value *key, struct fh_value *next_key);

int fh_get_map_value(struct fh_value *map, struct fh_value *key, struct fh_value *val);

int fh_add_map_entry(struct fh_program *prog, struct fh_value *map, struct fh_value *key, struct fh_value *val);

int fh_delete_map_entry(struct fh_value *map, struct fh_value *key);

int fh_run_string(struct fh_program *prog, bool dump_bytecode, const char *string, const char *main_function_name);

/**
 * when @param is_mandatory is set to "false" then if opening the file fails the language won't stop from running
*/
int fh_run_script_file(struct fh_program *prog, bool dump_bytecode, const char *filename,
                       const char *main_function_name, char **args, int n_args, bool is_mandatory);

/**
 * when @param is_mandatory is set to "false" then if opening the file fails the language won't stop from running
*/
int fh_run_pack(struct fh_program *prog, bool dump_bytecode, const char *pack_name, const char *filename,
                const char *main_function_name, char **args, int n_args, bool is_mandatory);


bool fh_dump_doc;
/**
 * Automatically set to 'true' when program.c starts and set to 'false' when
 * fh_set_error() is called.
 *
 * Useful when needing the running state of FH
 */
bool fh_running;

/**
 * When this flag is set to 'true' via ./fh -p <PATH_TO_PACK> <main_file>.fh.
 * Default set to 'false'
*/
bool fh_is_packed;
bool fh_started_pack;
/**
 * Tells the name of the main file to run from a .fhpack
 */
char *fh_main_file_packed;
mtar_t fh_tar;
mtar_header_t fh_tar_header;

#define FH_IO_TAR_STRUCT_ID (-102)
#define FH_IO_STRUCT_ID (-101)
#define FH_TIME_STRUCT_ID (-100)

/*
 Holds a reference to all handlers for dynamic libraries loaded
 with -l.
*/
vec_void_t fh_dynamic_libraries;

#endif /* FH_H_FILE */

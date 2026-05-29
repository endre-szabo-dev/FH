/* value.h */

#ifndef VALUE_H_FILE
#define VALUE_H_FILE

#include "fh_internal.h"
#include "stack.h"

#define GC_BIT_MARK  1
#define GC_BIT_PIN   2

#define GC_SET_BIT(o,b)      ((o)->header.gc_bits |= (b))
#define GC_CLEAR_BIT(o,b)    ((o)->header.gc_bits &= ~(b))
#define GC_HAS_BIT(o,b)      (((o)->header.gc_bits & (b)) != 0)

#define GC_PIN_OBJ(o)        GC_SET_BIT((o), GC_BIT_PIN)
#define GC_UNPIN_OBJ(o)      GC_CLEAR_BIT((o), GC_BIT_PIN)

struct fh_object_header {
    union fh_object *next;
    uint8_t gc_bits;
    enum fh_value_type type;
};

struct fh_string {
    struct fh_object_header header;
    uint32_t size;
    uint32_t hash;
};

struct fh_array {
    struct fh_object_header header;
    union fh_object *gc_next_container;
    struct fh_value *items;
    uint32_t len;
    uint32_t cap;
};

struct fh_map_entry {
    struct fh_value key;
    struct fh_value val;
};

struct fh_map {
    struct fh_object_header header;
    union fh_object *gc_next_container;
    struct fh_map_entry *entries;
    uint32_t len;
    uint32_t cap;
};

struct fh_func_def {
    struct fh_object_header header;
    union fh_object *gc_next_container;
    struct fh_string *name;
    int n_params;
    int n_regs;
    uint32_t *code;
    int code_size;
    struct fh_value *consts;
    int n_consts;
    struct fh_upval_def *upvals;
    int n_upvals;
    int code_src_loc_size;
    void *code_src_loc;
    struct fh_src_loc code_creation_loc;
};

struct fh_upval {
    struct fh_object_header header;
    union fh_object *gc_next_container;
    struct fh_value *val;

    union {
        struct fh_value storage;
        struct fh_upval *next;
    } data;
};

struct fh_closure {
    struct fh_object_header header;
    union fh_object *gc_next_container;
    struct fh_func_def *func_def;
    int n_upvals;
    struct fh_string *doc_string;
    struct fh_upval *upvals[];
};

struct fh_c_obj {
    struct fh_object_header header;
    union fh_object *gc_next_container;
    void *ptr;
    fh_c_obj_gc_callback free_callback;
    /* *Not* used by the language.
     * It may be used by the C user API to
     * identify more easily the object */
    int type;
};

union fh_object {
    struct fh_object_header header;
    struct fh_c_obj c_obj;
    struct fh_string str;
    struct fh_func_def func_def;
    struct fh_upval upval;
    struct fh_closure closure;
    struct fh_array array;
    struct fh_map map;
};

enum fh_upval_def_type {
    FH_UPVAL_TYPE_REG,
    FH_UPVAL_TYPE_UPVAL
};

struct fh_upval_def {
    enum fh_upval_def_type type;
    int num;
};

#define VAL_IS_OBJECT(v)  ((v)->type >= FH_FIRST_OBJECT_VAL)

#define GET_OBJ_C_OBJ(o)       ((struct fh_c_obj     *) (o))
#define GET_OBJ_CLOSURE(o)     ((struct fh_closure   *) (o))
#define GET_OBJ_UPVAL(o)       ((struct fh_upval     *) (o))
#define GET_OBJ_FUNC_DEF(o)    ((struct fh_func_def  *) (o))
#define GET_OBJ_ARRAY(o)       ((struct fh_array     *) (o))
#define GET_OBJ_MAP(o)         ((struct fh_map       *) (o))
#define GET_OBJ_STRING(o)      ((struct fh_string    *) (o))
#define GET_OBJ_STRING_DATA(o) (((char *) (o)) + sizeof(struct fh_string))

#define GET_VAL_OBJ(v)         ((union fh_object *) ((v)->data.obj))
#define GET_VAL_CLOSURE(v)     (((v)->type == FH_VAL_CLOSURE ) ? ((struct fh_closure  *) ((v)->data.obj)) : NULL)
#define GET_VAL_FUNC_DEF(v)    (((v)->type == FH_VAL_FUNC_DEF) ? ((struct fh_func_def *) ((v)->data.obj)) : NULL)
#define GET_VAL_ARRAY(v)       (((v)->type == FH_VAL_ARRAY   ) ? ((struct fh_array    *) ((v)->data.obj)) : NULL)
#define GET_VAL_MAP(v)         (((v)->type == FH_VAL_MAP     ) ? ((struct fh_map      *) ((v)->data.obj)) : NULL)
#define GET_VAL_STRING(v)      (((v)->type == FH_VAL_STRING  ) ? ((struct fh_string   *) ((v)->data.obj)) : NULL)
#define GET_VAL_STRING_DATA(v) (((v)->type == FH_VAL_STRING  ) ? GET_OBJ_STRING_DATA((v)->data.obj) : NULL)

#define UPVAL_IS_OPEN(uv)    ((uv)->val != &(uv)->data.storage)

// non-object types
#define fh_make_null    fh_new_null
#define fh_make_bool    fh_new_bool
#define fh_make_float   fh_new_float
#define fh_make_integer fh_new_integer
#define fh_make_c_func  fh_new_c_func

int fh_arg_int32(struct fh_program *prog, const struct fh_value *v, const char *fn, int arg_index_0_based,
                 int32_t *out);

int fh_arg_double(struct fh_program *prog, const struct fh_value *v, const char *fn, int arg_index_0_based,
                  double *out);


double fh_optnumber(struct fh_value *args, int n_args, int check, double opt);

int64_t fh_optinteger(struct fh_value *args, int n_args, int check, int64_t opt);


bool fh_optboolean(struct fh_value *args, int n_args, int check, bool opt);

const char *fh_optstring(struct fh_value *args, int n_args, int check, const char *opt);

void *fh_optcobj(struct fh_value *args, int n_args, int check, short ctype, void *opt);

/**
 * @brief fh_is_c_obj_of_type Checks if given fh_value is
 * of type "c object" and has a given user type
 */
bool fh_is_c_obj_of_type(struct fh_value *v, int usr_type);


// object types
struct fh_func_def *fh_make_func_def(struct fh_program *prog, bool pinned);

struct fh_closure *fh_make_closure(struct fh_program *prog, bool pinned, struct fh_func_def *func_def);

struct fh_upval *fh_make_upval(struct fh_program *prog, bool pinned);

struct fh_array *fh_make_array(struct fh_program *prog, bool pinned);

struct fh_map *fh_make_map(struct fh_program *prog, bool pinned);

struct fh_string *fh_make_string(struct fh_program *prog, bool pinned, const char *str);

struct fh_string *fh_make_string_n(struct fh_program *prog, bool pinned, const char *str, size_t str_len);

// object functions
void fh_free_object(struct fh_program *prog, union fh_object *obj);

bool fh_vals_are_equal(struct fh_value *v1, struct fh_value *v2);

struct fh_value *fh_grow_array_object(struct fh_program *prog, struct fh_array *arr, uint32_t num_items);

struct fh_value *fh_grow_array_object_uninit(struct fh_program *prog, struct fh_array *arr, uint32_t num_items);

int fh_reserve_array_capacity(struct fh_program *prog, struct fh_array *arr, uint32_t min_cap);

void fh_reset_array(struct fh_array *arr);

const char *fh_get_func_def_name(struct fh_func_def *func_def);

int fh_alloc_map_object_len(struct fh_map *map, uint32_t len);

int fh_next_map_object_key(struct fh_map *map, struct fh_value *key, struct fh_value *next_key);

int fh_get_map_object_value(struct fh_map *map, struct fh_value *key, struct fh_value *val);

int fh_add_map_object_entry(struct fh_program *prog, struct fh_map *map, struct fh_value *key,
                            const struct fh_value *val);

int fh_delete_map_object_entry(struct fh_map *map, struct fh_value *key);

void fh_reset_map(struct fh_map *map);

DECLARE_STACK(value_stack, struct fh_value);

const char *fh_type_to_str(struct fh_program *prog, enum fh_value_type type);

#endif /* VALUE_H_FILE */

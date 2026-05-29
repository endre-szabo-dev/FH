/* vm.c */

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <math.h>

#include "vm.h"
#include "program.h"
#include "bytecode.h"
#include "value.h"
#include <stdint.h>

#ifndef FH_MAXSHORTLEN
#define FH_MAXSHORTLEN 64
#endif

static int vm_error(struct fh_vm *vm, char *fmt, ...);

static inline int64_t fh_java_shl_i64(const int64_t a, const int64_t s) {
    const uint32_t dist = (uint32_t) s & 63u; // Java: n & 0x3f
    return (int64_t) ((uint64_t) a << dist);
}

static inline int64_t fh_java_sar_i64(const int64_t a, const int64_t s) {
    const uint32_t dist = (uint32_t) s & 63u;
    if (dist == 0) return a;

    const uint64_t ua = (uint64_t) a;
    uint64_t r = ua >> dist;

    if (a < 0) {
        r |= (~0ULL) << (64u - dist); // fill with 1s
    }
    return (int64_t) r;
}

static inline struct fh_value fh_add_string_integer(struct fh_program *prog, struct fh_string *s, const int64_t num) {
    char buf[FH_MAXSHORTLEN];
    int n = snprintf(buf, sizeof(buf), "%s%lld", GET_OBJ_STRING_DATA(s), (long long) num);

    if (n >= 0 && n < (int) sizeof(buf)) {
        return fh_new_string(prog, buf);
    }

    /* fallback heap */
    if (n < 0) {
        fh_set_error(prog, "string formatting failed");
        return fh_new_null();
    }

    char *heap = malloc((size_t) n + 1);
    if (!heap) {
        fh_set_error(prog, "out of memory");
        return fh_new_null();
    }

    snprintf(heap, (size_t)n + 1, "%s%lld", GET_OBJ_STRING_DATA(s), (long long) num);

    const struct fh_value v = fh_new_string(prog, heap);
    free(heap);
    return v;
}

static inline struct fh_value fh_add_string_float(struct fh_program *prog, struct fh_string *s, const double num) {
    char buf[FH_MAXSHORTLEN];
    int n = snprintf(buf, sizeof(buf), "%s%g", GET_OBJ_STRING_DATA(s), num);

    if (n >= 0 && n < (int) sizeof(buf)) {
        return fh_new_string(prog, buf);
    }

    /* fallback heap */
    if (n < 0) {
        fh_set_error(prog, "string formatting failed");
        return fh_new_null();
    }

    char *heap = malloc((size_t) n + 1);
    if (!heap) {
        fh_set_error(prog, "out of memory");
        return fh_new_null();
    }

    snprintf(heap, (size_t)n + 1, "%s%g", GET_OBJ_STRING_DATA(s), num);

    const struct fh_value v = fh_new_string(prog, heap);
    free(heap);
    return v;
}

static inline struct fh_value fh_add_integer_string(struct fh_program *prog, const int64_t num, struct fh_string *s) {
    char buf[FH_MAXSHORTLEN];
    int n = snprintf(buf, sizeof(buf), "%lld%s", (long long) num, GET_OBJ_STRING_DATA(s));

    if (n >= 0 && n < (int) sizeof(buf)) {
        return fh_new_string(prog, buf);
    }

    if (n < 0) {
        fh_set_error(prog, "string formatting failed");
        return fh_new_null();
    }

    char *heap = malloc((size_t) n + 1);
    if (!heap) {
        fh_set_error(prog, "out of memory");
        return fh_new_null();
    }

    snprintf(heap, (size_t)n + 1, "%lld%s",
             (long long) num, GET_OBJ_STRING_DATA(s));

    struct fh_value v = fh_new_string(prog, heap);
    free(heap);
    return v;
}

static inline struct fh_value fh_add_float_string(struct fh_program *prog, const double num, struct fh_string *s) {
    char buf[FH_MAXSHORTLEN];
    int n = snprintf(buf, sizeof(buf), "%g%s", num, GET_OBJ_STRING_DATA(s));

    if (n >= 0 && n < (int) sizeof(buf)) {
        return fh_new_string(prog, buf);
    }

    if (n < 0) {
        fh_set_error(prog, "string formatting failed");
        return fh_new_null();
    }

    char *heap = malloc((size_t) n + 1);
    if (!heap) {
        fh_set_error(prog, "out of memory");
        return fh_new_null();
    }

    snprintf(heap, (size_t)n + 1, "%g%s",
             num, GET_OBJ_STRING_DATA(s));

    struct fh_value v = fh_new_string(prog, heap);
    free(heap);
    return v;
}

static inline struct fh_value fh_add_string_string(struct fh_program *prog, const char *sa, const char *sb) {
    const size_t la = strlen(sa);
    const size_t lb = strlen(sb);
    const size_t len = la + lb + 1;

    if (len <= FH_MAXSHORTLEN) {
        char buf[FH_MAXSHORTLEN];
        memcpy(buf, sa, la);
        memcpy(buf + la, sb, lb + 1);
        return fh_new_string(prog, buf);
    }

    char *heap = malloc(len);
    if (!heap) {
        fh_set_error(prog, "out of memory");
        return fh_new_null();
    }

    memcpy(heap, sa, la);
    memcpy(heap + la, sb, lb + 1);

    const struct fh_value v = fh_new_string(prog, heap);
    free(heap);
    return v;
}

static void fh_init_char_cache(struct fh_vm *vm) {
    for (int i = 0; i < 256; i++) {
        const char s[2] = {(char) i, '\0'};

        struct fh_string *str = fh_make_string_n(vm->prog, true, s, 2);
        if (!str) {
            vm->char_cache[i] = vm->prog->null_value;
            continue;
        }

        vm->char_cache[i].type = FH_VAL_STRING;
        vm->char_cache[i].data.obj = str;
    }
}

void fh_init_vm(struct fh_vm *vm, struct fh_program *prog) {
    vm->prog = prog;
    vm->stack = NULL;
    vm->stack_size = 0;
    vm->open_upvals = NULL;
    vm->last_error_loc = fh_make_src_loc(0, 0, 0);
    vm->last_error_addr = -1;
    vm->last_error_frame_index = -1;
    call_frame_stack_init_cap(&vm->call_stack, 8192);
    fh_init_char_cache(vm);
}

void fh_destroy_vm(struct fh_vm *vm) {
    if (vm->stack)
        free(vm->stack);
    call_frame_stack_free(&vm->call_stack);
}

void fh_destroy_char_cache(struct fh_vm *vm) {
    for (int i = 0; i < 256; i++) {
        const struct fh_value *v = &vm->char_cache[i];
        if (v->type == FH_VAL_STRING && v->data.obj != NULL) {
            GC_UNPIN_OBJ((union fh_object*)v->data.obj);
        }
    }
}

static int vm_error(struct fh_vm *vm, char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fh_set_verror(vm->prog, fmt, ap);
    va_end(ap);
    return -1;
}

static int vm_error_oom(struct fh_vm *vm) {
    return vm_error(vm, "out of memory");
}

static int ensure_stack_size(struct fh_vm *vm, const size_t size) {
    if (vm->stack_size >= size)
        return 0;
    const size_t new_size = (size + 1023u) & ~(size_t) 1023u;

    void *new_stack = realloc(vm->stack, new_size * sizeof(struct fh_value));
    if (!new_stack)
        return vm_error_oom(vm);
    vm->stack = new_stack;
    vm->stack_size = new_size;
    return 0;
}

static struct fh_vm_call_frame *prepare_call(struct fh_vm *vm, struct fh_closure *closure, const int ret_reg,
                                             const int n_args) {
    const struct fh_func_def *func_def = closure->func_def;

    if (ensure_stack_size(vm, (size_t) ret_reg + 1u + (size_t) func_def->n_regs) < 0)
        return NULL;

    const int base = ret_reg + 1;

    // Args are already copied into [base .. base+n_args)
    // Only mark remaining regs as NULL (cheaper than memset full structs)
    if (n_args < func_def->n_regs) {
        struct fh_value *p = vm->stack + base + n_args;
        const int count = func_def->n_regs - n_args;
        for (int i = 0; i < count; i++) {
            p[i].type = FH_VAL_NULL;
            p[i].data.obj = NULL;
        }
    }

    struct fh_vm_call_frame *frame = call_frame_stack_push_uninit(&vm->call_stack);
    if (!frame) {
        vm_error_oom(vm);
        return NULL;
    }

    frame->closure = closure;
    frame->base = base;
    frame->ret_addr = NULL;
    frame->stack_top = base + func_def->n_regs;
    return frame;
}

static struct fh_vm_call_frame *prepare_c_call(struct fh_vm *vm, int ret_reg, int n_args) {
    if (ensure_stack_size(vm, ret_reg + 1 + n_args) < 0)
        return NULL;

    struct fh_vm_call_frame *frame = call_frame_stack_push_uninit(&vm->call_stack);
    if (!frame) {
        vm_error_oom(vm);
        return NULL;
    }
    frame->closure = NULL;
    frame->base = ret_reg + 1;
    frame->ret_addr = NULL;
    frame->stack_top = frame->base + n_args;

    return frame;
}

static void dump_val(char *label, struct fh_value *val) {
    printf("%s", label);
    fh_dump_value(val);
    printf("\n");
}

static void dump_regs(struct fh_vm *vm) {
    struct fh_vm_call_frame *frame = call_frame_stack_top(&vm->call_stack);
    if (!frame || !frame->closure) {
        printf("--- base=%d (C-call frame)\n", frame ? frame->base : -1);
        return;
    }
    struct fh_value *reg_base = vm->stack + frame->base;
    printf("--- base=%d, n_regs=%d\n", frame->base, frame->closure->func_def->n_regs);
    for (int i = 0; i < frame->closure->func_def->n_regs; i++) {
        printf("[%-3d] r%-2d = ", i + frame->base, i);
        dump_val("", &reg_base[i]);
    }
    printf("----------------------------\n");
}

int fh_call_vm_function(struct fh_vm *vm, struct fh_closure *closure,
                        struct fh_value *args, int n_args, struct fh_value *ret) {
    const struct fh_func_def *fh_func_def = closure->func_def;
    if (n_args > fh_func_def->n_params)
        n_args = fh_func_def->n_params;

    struct fh_vm_call_frame *prev_frame = call_frame_stack_top(&vm->call_stack);
    int ret_reg = 0;
    if (prev_frame && prev_frame->closure) {
        ret_reg = prev_frame->base + prev_frame->closure->func_def->n_regs;
    }

    ensure_stack_size(vm, ret_reg + n_args + 1);

    // memset(&vm->stack[ret_reg], 0, sizeof(struct fh_value));
    vm->stack[ret_reg].type = FH_VAL_NULL;

    if (args)
        memcpy(&vm->stack[ret_reg+1], args, n_args*sizeof(struct fh_value));

    // if (n_args < closure->func_def->n_regs)
    // memset(&vm->stack[ret_reg+1+n_args], 0,
    // (closure->func_def->n_regs-n_args)*sizeof(struct fh_value));

    if (!prepare_call(vm, closure, ret_reg, n_args))
        return -1;
    vm->pc = fh_func_def->code;
    if (fh_run_vm(vm) < 0)
        return -2;
    if (ret)
        *ret = vm->stack[ret_reg];
    return 0;
}

static bool fh_val_is_true(struct fh_value *val) {
    if (val->type == FH_VAL_UPVAL)
        val = GET_OBJ_UPVAL(val)->val;
    switch (val->type) {
        case FH_VAL_ARRAY:
        case FH_VAL_MAP:
        case FH_VAL_CLOSURE:
        case FH_VAL_FUNC_DEF:
        case FH_VAL_C_FUNC:
        case FH_VAL_C_OBJ:
            return true;
        case FH_VAL_NULL:
        case FH_VAL_UPVAL:
            return false;
        case FH_VAL_BOOL: return val->data.b;
        case FH_VAL_FLOAT: return val->data.num != 0.0;
        case FH_VAL_INTEGER: return val->data.i != 0;
        case FH_VAL_STRING: return GET_VAL_STRING(val)->size > 1;
    }
    return false;
}

static inline bool fh_double_is_finite(const double d) {
    const union {
        double d;
        uint64_t u;
    } x = {d};

    // IEEE-754: exponent = bits 52..62
    // If exponent == 0x7FF → NaN or Inf
    return (x.u & 0x7ff0000000000000ULL) != 0x7ff0000000000000ULL;
}

static bool fh_num_equals_int64(const double d, const int64_t i) {
    if (!fh_double_is_finite(d)) return false;

    const double id = (double) i;
    if (id != d) return false;

    return (int64_t) d == i;
}

static bool vals_are_equali(struct fh_value *v1, struct fh_value *v2) {
    if (v1->type == FH_VAL_UPVAL)
        v1 = GET_OBJ_UPVAL(v1)->val;
    if (v2->type == FH_VAL_UPVAL)
        v2 = GET_OBJ_UPVAL(v2)->val;

    if (!fh_is_integer(v1) || !fh_is_integer(v2)) {
        return false;
    }
    return fh_get_integer(v1) == fh_get_integer(v2);
}

static bool vals_are_equalf(struct fh_value *v1, struct fh_value *v2) {
    if (v1->type == FH_VAL_UPVAL)
        v1 = GET_OBJ_UPVAL(v1)->val;
    if (v2->type == FH_VAL_UPVAL)
        v2 = GET_OBJ_UPVAL(v2)->val;

    if (!fh_is_float(v1) || !fh_is_float(v2)) {
        return false;
    }

    return fh_get_float(v1) == fh_get_float(v2);
}

bool fh_vals_are_equal(struct fh_value *v1, struct fh_value *v2) {
    if (v1->type == FH_VAL_UPVAL)
        v1 = GET_OBJ_UPVAL(v1)->val;
    if (v2->type == FH_VAL_UPVAL)
        v2 = GET_OBJ_UPVAL(v2)->val;

    if (v1->type != v2->type) {
        if (fh_is_float(v1) && fh_is_integer(v2)) {
            return fh_num_equals_int64(v1->data.num, v2->data.i);
        }
        if (fh_is_integer(v1) && fh_is_float(v2)) {
            return fh_num_equals_int64(v2->data.num, v1->data.i);
        }
        return false;
    }

    switch (v1->type) {
        case FH_VAL_NULL: return true;
        case FH_VAL_BOOL: return v1->data.b == v2->data.b;
        case FH_VAL_FLOAT: return v1->data.num == v2->data.num;
        case FH_VAL_INTEGER: return v1->data.i == v2->data.i;
        case FH_VAL_C_FUNC: return v1->data.c_func == v2->data.c_func;
        case FH_VAL_UPVAL: return false;
        case FH_VAL_C_OBJ:
        case FH_VAL_ARRAY:
        case FH_VAL_MAP:
        case FH_VAL_CLOSURE:
        case FH_VAL_FUNC_DEF:
            return v1->data.obj == v2->data.obj;

        case FH_VAL_STRING: {
            const struct fh_string *s1 = GET_VAL_STRING(v1);
            const struct fh_string *s2 = GET_VAL_STRING(v2);

            if (v1->data.obj == v2->data.obj) return true;

            if (s1->hash != s2->hash || s1->size != s2->size)
                return false;

            const char *p1 = GET_OBJ_STRING_DATA(v1->data.obj);
            const char *p2 = GET_OBJ_STRING_DATA(v2->data.obj);

            return memcmp(p1, p2, (size_t) s1->size) == 0;
        }
    }
    return false;
}

static inline int vm_assert_index(struct fh_vm *vm, const struct fh_value *idx_val, int64_t *out,
                                  const char *what) {
    if (idx_val->type != FH_VAL_INTEGER) {
        vm_error(vm, "invalid %s access (non-integer index)", what);
        return -1;
    }

    const int64_t n = idx_val->data.i;

    if (n < 0) {
        vm_error(vm, "invalid %s access (index is negative)", what);
        return -1;
    }

    *out = n;
    return 0;
}


static struct fh_upval *find_or_add_upval(struct fh_vm *vm, struct fh_value *val) {
    struct fh_upval **cur = &vm->open_upvals;
    while (*cur != NULL && (*cur)->val >= val) {
        if ((*cur)->val == val)
            return *cur;
        cur = &(*cur)->data.next;
    }
    struct fh_upval *uv = fh_make_upval(vm->prog, false);
    uv->val = val;
    uv->data.next = *cur;
    *cur = uv;
    return uv;
}

static void close_upval(struct fh_vm *vm) {
    struct fh_upval *uv = vm->open_upvals;
    //printf("CLOSING UPVAL %p (", (void *) uv); fh_dump_value(uv->val); printf(")\n");
    vm->open_upvals = uv->data.next;
    uv->data.storage = *uv->val;
    uv->val = &uv->data.storage;
}

static void dump_state(struct fh_vm *vm) {
    const struct fh_vm_call_frame *frame = call_frame_stack_top(&vm->call_stack);
    printf("\n");
    printf("****************************\n");
    printf("***** HALTING ON ERROR *****\n");
    printf("****************************\n");
    printf("** current stack frame: ");
    if (frame) {
        if (frame->closure->func_def->name)
            printf("closure %p of %s\n", (void *) frame->closure,
                   GET_OBJ_STRING_DATA(frame->closure->func_def->name));
        else
            printf("closure %p of function %p\n",
                   (void *) frame->closure, (void *) frame->closure->func_def);
    } else
        printf("no stack frame!\n");
    dump_regs(vm);
    printf("** instruction that caused error:\n");
    int addr = (frame) ? vm->pc - 1 - frame->closure->func_def->code : -1;
    fh_dump_bc_instr(vm->prog, addr, vm->pc[-1]);
    printf("----------------------------\n");
}

static void save_error_loc(struct fh_vm *vm) {
    const int n = call_frame_stack_size(&vm->call_stack);

    for (int i = n - 1; i >= 0; --i) {
        struct fh_vm_call_frame *frame = call_frame_stack_item(&vm->call_stack, i);
        if (!frame) { break; }
        if (!frame->closure) {
            // skip C-call frames (closure == NULL)
            continue;
        }

        struct fh_func_def *func_def = frame->closure->func_def;

        vm->last_error_frame_index = i;
        vm->last_error_addr = (int) ((vm->pc - 1) - func_def->code);
        vm->last_error_loc = fh_get_addr_src_loc(func_def, vm->last_error_addr);
        return;
    }

    vm->last_error_frame_index = -1;
    vm->last_error_addr = -1;
    vm->last_error_loc = fh_make_src_loc(0, 0, 0);
}

#define handle_op(op) case op:
#define RK_IS_REG(i)        ((i) < MAX_FUNC_REGS)
#define RK_IS_CONST(i)      ((i) >= (MAX_FUNC_REGS + 1))
#define RK_CONST_INDEX(i)   ((i) - (MAX_FUNC_REGS + 1))

#define LOAD_REG(i)         (&reg_base[(i)])
#define LOAD_CONST(i)       (&const_base[RK_CONST_INDEX(i)])

#define LOAD_REG_OR_CONST(i) (RK_IS_REG(i) ? LOAD_REG(i) : (RK_IS_CONST(i) ? LOAD_CONST(i) : NULL))

#define do_simple_arithmetic(op, ra, rb_i, rc_i)  { \
    struct fh_value *rb = LOAD_REG_OR_CONST(rb_i); \
    struct fh_value *rc = LOAD_REG_OR_CONST(rc_i); \
    if (!fh_is_number(rb) || !fh_is_number(rc)) { \
        vm_error(vm, "arithmetic on non-numeric values"); \
        goto user_err; \
    } \
    if (fh_is_float(rb) && fh_is_float(rc)) { \
        ra->type = FH_VAL_FLOAT; \
        ra->data.num = rb->data.num op rc->data.num; \
    } else if (fh_is_integer(rb) && fh_is_integer(rc)) { \
        ra->type = FH_VAL_INTEGER; \
        ra->data.i = rb->data.i op rc->data.i; \
    } else { \
        const double a = fh_to_double(rb); \
        const double b = fh_to_double(rc); \
        ra->type = FH_VAL_FLOAT; \
        ra->data.num = a op b; \
    } \
}
#define do_simple_arithmetic_unary(op, ra, rb_i)  { \
        struct fh_value *rb = LOAD_REG_OR_CONST(rb_i); \
        if (!fh_is_number(rb)) { \
            vm_error(vm, "arithmetic on non-numeric values"); \
            goto user_err; \
        } \
        if (fh_is_integer(rb)) { \
            ra->type = FH_VAL_INTEGER; \
            ra->data.i = op rb->data.i; \
        } else if (fh_is_float(rb)) { \
            ra->type = FH_VAL_FLOAT; \
            ra->data.num = op rb->data.num; \
        }\
}
#define do_simple_arithmetic_unary_i(op, ra, rb_i)  { \
    struct fh_value *rb = LOAD_REG_OR_CONST(rb_i); \
    if (!fh_is_integer(rb)) { \
        vm_error(vm, "bitwise 'not' expects integer"); \
        goto user_err; \
    } \
    ra->type = FH_VAL_INTEGER; \
    ra->data.i = op rb->data.i; \
}
#define do_test_arithmetic(op, ret, rb_i, rc_i)  do { \
    struct fh_value *rb = LOAD_REG_OR_CONST(rb_i); \
    struct fh_value *rc = LOAD_REG_OR_CONST(rc_i); \
    if (!fh_is_number(rb) || !fh_is_number(rc)) { \
        vm_error(vm, "comparison on non-numeric values"); \
        goto user_err; \
    } \
    if (fh_is_integer(rb) && fh_is_integer(rc)) { \
        *(ret) = (rb->data.i op rc->data.i); \
    } else if (fh_is_float(rb) && fh_is_float(rc)) { \
        *(ret) = (rb->data.num op rc->data.num); \
    } else { \
        const double a = fh_to_double(rb); \
        const double b = fh_to_double(rc); \
        *(ret) = (a op b); \
    } \
} while (0)

#define do_bitwise_arithmetic(op, ra, rb_i, rc_i)  { \
    struct fh_value *rb = LOAD_REG_OR_CONST(rb_i); \
    struct fh_value *rc = LOAD_REG_OR_CONST(rc_i); \
    if (!fh_is_integer(rb) || !fh_is_integer(rc)) { \
        vm_error(vm, "bitwise expects integers"); \
        goto user_err; \
    } \
    ra->type = FH_VAL_INTEGER; \
    ra->data.i = rb->data.i op rc->data.i; \
}

int fh_run_vm(struct fh_vm *vm) {
#if !defined(__clang__) && !defined(__GNUC__)
#error "computed goto (direct-threaded dispatch) requires Clang or GCC"
#endif

    struct fh_vm_call_frame *frame = NULL;
    struct fh_value *stack = vm->stack;

    uint32_t *pc = vm->pc;
    struct fh_value *reg_base = NULL;
    struct fh_value *const_base = NULL;

    int cmp_test = 0;


    // --- decode fields (kept in locals)
    uint32_t op = 0;
    uint32_t ra_i = 0, rb_i = 0, rc_i = 0;
    uint32_t ru = 0;
    int32_t rs = 0;
    struct fh_value *ra = NULL;

    static void *dispatch[] = {
        [OPC_LDC] = &&op_LDC,
        [OPC_LDNULL] = &&op_LDNULL,
        [OPC_MOV] = &&op_MOV,
        [OPC_RET] = &&op_RET,
        [OPC_GETEL] = &&op_GETEL,
        [OPC_SETEL] = &&op_SETEL,
        [OPC_NEWARRAY] = &&op_NEWARRAY,
        [OPC_NEWMAP] = &&op_NEWMAP,
        [OPC_CLOSURE] = &&op_CLOSURE,
        [OPC_GETUPVAL] = &&op_GETUPVAL,
        [OPC_SETUPVAL] = &&op_SETUPVAL,

        [OPC_BNOT] = &&op_BNOT,
        [OPC_RSHIFT] = &&op_RSHIFT,
        [OPC_LSHIFT] = &&op_LSHIFT,
        [OPC_BOR] = &&op_BOR,
        [OPC_BAND] = &&op_BAND,
        [OPC_BXOR] = &&op_BXOR,

        [OPC_INC] = &&op_INC,
        [OPC_DEC] = &&op_DEC,

        [OPC_ADD] = &&op_ADD,
        [OPC_ADDF] = &&op_ADDF,
        [OPC_ADDI] = &&op_ADDI,
        [OPC_SUB] = &&op_SUB,
        [OPC_MUL] = &&op_MUL,
        [OPC_DIV] = &&op_DIV,
        [OPC_MOD] = &&op_MOD,
        [OPC_NEG] = &&op_NEG,
        [OPC_NOT] = &&op_NOT,

        [OPC_CALL] = &&op_CALL,

        [OPC_JMP] = &&op_JMP,
        [OPC_TEST] = &&op_TEST,

        [OPC_CMP_EQ] = &&op_CMP_EQ,
        [OPC_CMP_EQI] = &&op_CMP_EQI,
        [OPC_CMP_EQF] = &&op_CMP_EQF,

        [OPC_CMP_GT] = &&op_CMP_GT,
        [OPC_CMP_GTI] = &&op_CMP_GTI,
        [OPC_CMP_GTF] = &&op_CMP_GTF,

        [OPC_CMP_GE] = &&op_CMP_GE,
        [OPC_CMP_GEI] = &&op_CMP_GEI,
        [OPC_CMP_GEF] = &&op_CMP_GEF,

        [OPC_CMP_LT] = &&op_CMP_LT,
        [OPC_CMP_LTI] = &&op_CMP_LTI,
        [OPC_CMP_LTF] = &&op_CMP_LTF,

        [OPC_CMP_LE] = &&op_CMP_LE,
        [OPC_CMP_LEI] = &&op_CMP_LEI,
        [OPC_CMP_LEF] = &&op_CMP_LEF,

        [OPC_LEN] = &&op_LEN,
        [OPC_APPEND] = &&op_APPEND,
    };

#define DISPATCH() do { \
        uint32_t instr__ = *pc++; \
        op   = GET_INSTR_OP(instr__); \
        ra_i = GET_INSTR_RA(instr__); \
        rb_i = GET_INSTR_RB(instr__); \
        rc_i = GET_INSTR_RC(instr__); \
        ru   = GET_INSTR_RU(instr__); \
        rs   = GET_INSTR_RS(instr__); \
        ra   = &reg_base[ra_i]; \
        goto *dispatch[op]; \
    } while (0)

rebind_frame:
    frame = call_frame_stack_top(&vm->call_stack);
    const_base = frame->closure->func_def->consts;
    stack = vm->stack; // stack pointer can move after realloc
    reg_base = stack + frame->base;

    DISPATCH();

    // -----------------------------
    //   OPCODES (labels)
    // -----------------------------

op_LDC: {
        *ra = const_base[ru];
        DISPATCH();
    }

op_LDNULL: {
        ra->type = FH_VAL_NULL;
        DISPATCH();
    }

op_MOV: {
        *ra = *LOAD_REG_OR_CONST(rb_i);
        DISPATCH();
    }

op_RET: {
        if (ra_i)
            stack[frame->base - 1] = *LOAD_REG_OR_CONST(rb_i);
        else
            stack[frame->base - 1].type = FH_VAL_NULL;

        // close function upvalues (only those belonging to this frame)
        struct fh_value *frame_start = stack + frame->base;
        struct fh_value *frame_end = stack + frame->stack_top;

        while (vm->open_upvals != NULL) {
            struct fh_value *p = vm->open_upvals->val;
            if (p < frame_start || p >= frame_end)
                break;
            close_upval(vm);
        }

        uint32_t *ret_addr = frame->ret_addr;
        call_frame_stack_pop(&vm->call_stack, NULL);

        if (!ret_addr) {
            vm->pc = pc;
            return 0;
        }

        frame = call_frame_stack_top(&vm->call_stack);
        if (!frame || !frame->closure) {
            vm->pc = pc;
            return 0;
        }

        pc = ret_addr;
        goto rebind_frame;
    }

op_GETEL: {
        struct fh_value *rb = LOAD_REG_OR_CONST(rb_i);
        struct fh_value *rc = LOAD_REG_OR_CONST(rc_i);

        switch (rb->type) {
            case FH_VAL_ARRAY: {
                int64_t idx;
                if (vm_assert_index(vm, rc, &idx, "array") < 0)
                    goto user_err;

                const struct fh_array *arr = GET_OBJ_ARRAY(rb->data.obj);
                if (idx < arr->len) *ra = arr->items[idx];
                else ra->type = FH_VAL_NULL;
                break;
            }
            case FH_VAL_MAP: {
                if (fh_get_map_value(rb, rc, ra) < 0) {
                    *ra = fh_new_null();
                }
                break;
            }
            case FH_VAL_STRING: {
                int64_t idx;
                if (vm_assert_index(vm, rc, &idx, "string") < 0)
                    goto user_err;

                struct fh_string *s = GET_VAL_STRING(rb);
                if (idx >= (s->size - 1)) {
                    *ra = fh_new_null();
                    break;
                }

                unsigned char ch = (unsigned char) GET_OBJ_STRING_DATA(s)[idx];
                *ra = vm->char_cache[ch];
                break;
            }
            default:
                vm_error(vm, "invalid element access (non-container object)");
                goto user_err;
        }

        DISPATCH();
    }

op_SETEL: {
        struct fh_value *rb = LOAD_REG_OR_CONST(rb_i);
        struct fh_value *rc = LOAD_REG_OR_CONST(rc_i);

        if (ra->type == FH_VAL_ARRAY) {
            int64_t idx;
            if (vm_assert_index(vm, rb, &idx, "array") < 0)
                goto user_err;

            struct fh_array *arr = GET_OBJ_ARRAY(ra->data.obj);
            if (idx >= arr->len) {
                fh_grow_array_object(vm->prog, arr, idx + 1);
            }
            arr->items[idx] = *rc;

            DISPATCH();
        }

        if (ra->type == FH_VAL_MAP) {
            if (fh_add_map_entry(vm->prog, ra, rb, rc) < 0)
                goto err;
            DISPATCH();
        }

        vm_error(vm, "invalid element access (non-container object)");
        goto user_err;
    }

op_NEWARRAY: {
        int n_elems = (int) ru;

        struct fh_array *arr = fh_make_array(vm->prog, false);
        if (!arr)
            goto err;

        if (n_elems != 0) {
            GC_PIN_OBJ(arr);
            struct fh_value *first = fh_grow_array_object_uninit(vm->prog, arr, n_elems);
            if (!first) {
                GC_UNPIN_OBJ(arr);
                goto err;
            }
            GC_UNPIN_OBJ(arr);
            memcpy(first, ra + 1, (size_t)n_elems * sizeof(struct fh_value));
        } else {
            fh_reserve_array_capacity(vm->prog, arr, 8);
        }

        ra->type = FH_VAL_ARRAY;
        ra->data.obj = arr;
        DISPATCH();
    }

op_NEWMAP: {
        int n_elems = (int) ru; // number of registers after ra (key/val pairs)
        int n_pairs = n_elems >> 1;

        struct fh_map *map = fh_make_map(vm->prog, false);
        if (!map)
            goto err;

        // Only reserve/alloc if we actually have elements in the literal
        if (n_pairs != 0) {
            // Allocate enough capacity for the pairs we’ll insert
            if (fh_alloc_map_object_len(map, (uint32_t) n_pairs) < 0) goto err;

            GC_PIN_OBJ(map);
            for (int i = 0; i < n_pairs; i++) {
                int ni = i << 1;
                struct fh_value *key = &ra[ni + 1];
                struct fh_value *val = &ra[ni + 2];
                if (fh_add_map_object_entry(vm->prog, map, key, val) < 0) {
                    GC_UNPIN_OBJ(map);
                    goto err;
                }
            }
            GC_UNPIN_OBJ(map);
        } else {
            if (fh_alloc_map_object_len(map, 8) < 0) goto err; // cap ~16
        }

        ra->type = FH_VAL_MAP;
        ra->data.obj = map;
        DISPATCH();
    }

op_CLOSURE: {
        struct fh_value *rb = LOAD_REG_OR_CONST(rb_i);
        if (rb->type != FH_VAL_FUNC_DEF) {
            vm_error(vm, "invalid value for closure (not a func_def)");
            goto err;
        }

        struct fh_func_def *func_def = GET_VAL_FUNC_DEF(rb);
        struct fh_closure *c = fh_make_closure(vm->prog, false, func_def);
        if (!c) goto err;

        GC_PIN_OBJ(c);
        for (int i = 0; i < func_def->n_upvals; i++) {
            if (func_def->upvals[i].type == FH_UPVAL_TYPE_UPVAL) {
                c->upvals[i] = frame->closure->upvals[func_def->upvals[i].num];
            } else {
                c->upvals[i] = find_or_add_upval(vm, &reg_base[func_def->upvals[i].num]);
                GC_PIN_OBJ(c->upvals[i]);
            }
        }

        ra->type = FH_VAL_CLOSURE;
        ra->data.obj = c;

        for (int i = 0; i < func_def->n_upvals; i++) {
            if (func_def->upvals[i].type != FH_UPVAL_TYPE_UPVAL) {
                GC_UNPIN_OBJ(c->upvals[i]);
            }
        }
        GC_UNPIN_OBJ(c);

        DISPATCH();
    }

op_GETUPVAL: {
        *ra = *frame->closure->upvals[rb_i]->val;
        DISPATCH();
    }

op_SETUPVAL: {
        struct fh_value *rb = LOAD_REG_OR_CONST(rb_i);
        *frame->closure->upvals[ra_i]->val = *rb;
        DISPATCH();
    }

op_BNOT: {
        do_simple_arithmetic_unary_i(~, ra, rb_i);
        DISPATCH();
    }

op_RSHIFT: {
        struct fh_value *rb = LOAD_REG_OR_CONST(rb_i);
        struct fh_value *rc = LOAD_REG_OR_CONST(rc_i);
        if (!fh_is_integer(rb) || !fh_is_integer(rc)) {
            vm_error(vm, "bitwise expects integers");
            goto user_err;
        }
        ra->type = FH_VAL_INTEGER;
        ra->data.i = fh_java_sar_i64(rb->data.i, rc->data.i);
        DISPATCH();
    }

op_LSHIFT: {
        struct fh_value *rb = LOAD_REG_OR_CONST(rb_i);
        struct fh_value *rc = LOAD_REG_OR_CONST(rc_i);
        if (!fh_is_integer(rb) || !fh_is_integer(rc)) {
            vm_error(vm, "bitwise expects integers");
            goto user_err;
        }
        ra->type = FH_VAL_INTEGER;
        ra->data.i = fh_java_shl_i64(rb->data.i, rc->data.i);
        DISPATCH();
    }

op_BOR: {
        do_bitwise_arithmetic(|, ra, rb_i, rc_i);
        DISPATCH();
    }

op_BAND: {
        do_bitwise_arithmetic(&, ra, rb_i, rc_i);
        DISPATCH();
    }

op_BXOR: {
        do_bitwise_arithmetic(^, ra, rb_i, rc_i);
        DISPATCH();
    }

op_INC: {
        struct fh_value *rb = LOAD_REG_OR_CONST(rb_i);
        if (!fh_is_number(rb)) {
            vm_error(vm, "increment on non-numeric value");
            goto user_err;
        }
        if (fh_is_float(rb)) {
            ra->type = FH_VAL_FLOAT;
            ra->data.num = rb->data.num + 1.0;
            DISPATCH();
        }
        ra->type = FH_VAL_INTEGER;
        ra->data.i = rb->data.i + 1;
        DISPATCH();
    }

op_DEC: {
        struct fh_value *rb = LOAD_REG_OR_CONST(rb_i);
        if (!fh_is_number(rb)) {
            vm_error(vm, "decrement on non-numeric value");
            goto user_err;
        }
        if (fh_is_float(rb)) {
            ra->type = FH_VAL_FLOAT;
            ra->data.num = rb->data.num - 1.0;
            DISPATCH();
        }
        ra->type = FH_VAL_INTEGER;
        ra->data.i = rb->data.i - 1;
        DISPATCH();
    }

op_ADDI: {
        struct fh_value *rb = LOAD_REG_OR_CONST(rb_i);
        struct fh_value *rc = LOAD_REG_OR_CONST(rc_i);

        if (!fh_is_integer(rb) || !fh_is_integer(rc)) {
            vm_error(vm, "integer addition expects numeric values");
            goto user_err;
        }
        ra->type = FH_VAL_INTEGER;
        ra->data.i = rb->data.i + rc->data.i;
        DISPATCH();
    }

op_ADDF: {
        struct fh_value *rb = LOAD_REG_OR_CONST(rb_i);
        struct fh_value *rc = LOAD_REG_OR_CONST(rc_i);

        if (!fh_is_float(rb) || !fh_is_float(rc)) {
            vm_error(vm, "float addition expects numeric values");
            goto user_err;
        }
        ra->type = FH_VAL_FLOAT;
        ra->data.num = rb->data.num + rc->data.num;
        DISPATCH();
    }

op_ADD: {
        struct fh_value *rb = LOAD_REG_OR_CONST(rb_i);
        struct fh_value *rc = LOAD_REG_OR_CONST(rc_i);


        if (fh_is_number(rb) && fh_is_number(rc)) {
            // int + int -> int
            if (fh_is_integer(rb) && fh_is_integer(rc)) {
                ra->type = FH_VAL_INTEGER;
                ra->data.i = rb->data.i + rc->data.i;
                DISPATCH();
            }

            // float + float -> float
            if (fh_is_float(rb) && fh_is_float(rc)) {
                ra->type = FH_VAL_FLOAT;
                ra->data.num = rb->data.num + rc->data.num;
                DISPATCH();
            }

            // mixed -> float
            double a = fh_to_double(rb);
            double b = fh_to_double(rc);
            ra->type = FH_VAL_FLOAT;
            ra->data.num = a + b;
            DISPATCH();
        }

        // ---- string concatenations ----
        if (fh_is_string(rb) && fh_is_string(rc)) {
            *ra = fh_add_string_string(vm->prog,GET_OBJ_STRING_DATA(GET_VAL_STRING(rb)),
                                       GET_OBJ_STRING_DATA(GET_VAL_STRING(rc)));
            DISPATCH();
        }

        if (fh_is_string(rb) && fh_is_float(rc)) {
            *ra = fh_add_string_float(vm->prog,GET_VAL_STRING(rb), rc->data.num);
            DISPATCH();
        }

        if (fh_is_string(rb) && fh_is_integer(rc)) {
            *ra = fh_add_string_integer(vm->prog,GET_VAL_STRING(rb), rc->data.i);
            DISPATCH();
        }

        if (fh_is_float(rb) && fh_is_string(rc)) {
            *ra = fh_add_float_string(vm->prog, rb->data.num,GET_VAL_STRING(rc));
            DISPATCH();
        }

        if (fh_is_integer(rb) && fh_is_string(rc)) {
            *ra = fh_add_integer_string(vm->prog, rb->data.i,GET_VAL_STRING(rc));
            DISPATCH();
        }

        if (fh_is_bool(rb) && fh_is_string(rc)) {
            *ra = fh_add_string_string(vm->prog,
                                       rb->data.b != 0.0 ? "true" : "false",
                                       GET_OBJ_STRING_DATA(GET_VAL_STRING(rc)));
            DISPATCH();
        }

        if (fh_is_string(rb) && fh_is_bool(rc)) {
            *ra = fh_add_string_string(vm->prog,
                                       GET_OBJ_STRING_DATA(GET_VAL_STRING(rb)),
                                       rc->data.b != 0.0 ? "true" : "false");
            DISPATCH();
        }

        vm_error(vm, "can't add %s and %s",
                 fh_type_to_str(vm->prog, rb->type),
                 fh_type_to_str(vm->prog, rc->type));
        goto user_err;
    }

op_SUB: {
        do_simple_arithmetic(-, ra, rb_i, rc_i);
        DISPATCH();
    }

op_MUL: {
        do_simple_arithmetic(*, ra, rb_i, rc_i);
        DISPATCH();
    }

op_DIV: {
        struct fh_value *rb = LOAD_REG_OR_CONST(rb_i);
        struct fh_value *rc = LOAD_REG_OR_CONST(rc_i);

        if (!fh_is_number(rb) || !fh_is_number(rc)) {
            vm_error(vm, "arithmetic on non-numeric values");
            goto user_err;
        }

        if (fh_to_double(rc) == 0.0) {
            vm_error(vm, "division by zero");
            goto user_err;
        }

        ra->type = FH_VAL_FLOAT;
        const double a = fh_to_double(rb);
        const double b = fh_to_double(rc);
        ra->data.num = a / b;
        DISPATCH();
    }

op_MOD: {
        struct fh_value *rb = LOAD_REG_OR_CONST(rb_i);
        struct fh_value *rc = LOAD_REG_OR_CONST(rc_i);
        if (!fh_is_integer(rb) || !fh_is_integer(rc)) {
            vm_error(vm, "'mod' expects integers");
            goto user_err;
        }
        if (rc->data.i == 0) {
            vm_error(vm, "division by zero");
            goto user_err;
        }

        ra->type = FH_VAL_INTEGER;
        ra->data.i = rb->data.i % rc->data.i;
        DISPATCH();
    }

op_NEG: {
        do_simple_arithmetic_unary(-, ra, rb_i);
        DISPATCH();
    }

op_NOT: {
        struct fh_value *rb = LOAD_REG_OR_CONST(rb_i);
        *ra = fh_new_bool(!fh_val_is_true(rb));
        DISPATCH();
    }

op_CALL: {
        int ret_reg = frame->base + (int) ra_i;
        const uint8_t t = ra->type;

        if (t == FH_VAL_CLOSURE) {
            struct fh_closure *cl = GET_OBJ_CLOSURE(ra->data.obj);
            uint32_t *func_addr = cl->func_def->code;
            struct fh_vm_call_frame *new_frame = prepare_call(vm, cl, ret_reg, (int) rb_i);
            if (!new_frame) goto err;

            new_frame->ret_addr = pc;
            pc = func_addr;

            // prepare_call may realloc vm->stack
            stack = vm->stack;
            goto rebind_frame;
        }

        if (t == FH_VAL_C_FUNC) {
            struct fh_vm_call_frame *new_frame = prepare_c_call(vm, ret_reg, (int) rb_i);
            if (!new_frame) goto err;

            // stack may have moved
            stack = vm->stack;

            int r = ra->data.c_func(
                vm->prog,
                stack + new_frame->base - 1,
                stack + new_frame->base,
                (int) rb_i
            );

            call_frame_stack_pop(&vm->call_stack, NULL);
            if (r < 0) goto user_err;

            // still in same bytecode function after C call
            goto rebind_frame;
        }

        vm_error(vm, "call to non-function value");
        goto user_err;
    }

op_JMP: {
        while (ra_i-- > 0) {
            if (!vm->open_upvals) break;
            close_upval(vm);
        }
        pc += rs;
        DISPATCH();
    }

op_TEST: {
        struct fh_value *rb = LOAD_REG_OR_CONST(rb_i);
        cmp_test = fh_val_is_true(rb) ^ (int) ra_i;
        if (cmp_test) {
            // skip next instruction
            pc++;
            DISPATCH();
        }
        // next instruction holds signed offset; your old code: pc += GET_INSTR_RS(*pc) + 1;
        int32_t off = GET_INSTR_RS(*pc);
        pc += off + 1;
        DISPATCH();
    }

op_CMP_EQ: {
        struct fh_value *rb = LOAD_REG_OR_CONST(rb_i);
        struct fh_value *rc = LOAD_REG_OR_CONST(rc_i);
        cmp_test = (fh_vals_are_equal(rb, rc) ^ (int) ra_i);
        if (cmp_test) pc++;
        DISPATCH();
    }

op_CMP_EQI: {
        struct fh_value *rb = LOAD_REG_OR_CONST(rb_i);
        struct fh_value *rc = LOAD_REG_OR_CONST(rc_i);
        cmp_test = (vals_are_equali(rb, rc) ^ (int) ra_i);
        if (cmp_test) pc++;
        DISPATCH();
    }

op_CMP_EQF: {
        struct fh_value *rb = LOAD_REG_OR_CONST(rb_i);
        struct fh_value *rc = LOAD_REG_OR_CONST(rc_i);
        cmp_test = vals_are_equalf(rb, rc) ^ (int) ra_i;
        if (cmp_test) pc++;
        DISPATCH();
    }

op_CMP_GT: {
        // printf("CMP_GT ra=%u rb=%u rc=%u (rb_const=%d rc_const=%d)\n", ra_i, rb_i, rc_i, RK_IS_CONST(rb_i),
        // RK_IS_CONST(rc_i));
        cmp_test = 0;
        do_test_arithmetic(>, &cmp_test, rb_i, rc_i);
        cmp_test ^= (int) ra_i;
        if (cmp_test) pc++;
        DISPATCH();
    }

op_CMP_GTI: {
        cmp_test = 0;
        struct fh_value *rb = LOAD_REG_OR_CONST(rb_i);
        struct fh_value *rc = LOAD_REG_OR_CONST(rc_i);
        if (!fh_is_integer(rb) || !fh_is_integer(rc)) {
            vm_error(vm, "using '>' with non-integer values");
            goto user_err;
        }
        cmp_test = (rb->data.i > rc->data.i) ^ (int) ra_i;
        if (cmp_test) pc++;
        DISPATCH();
    }

op_CMP_GTF: {
        cmp_test = 0;
        struct fh_value *rb = LOAD_REG_OR_CONST(rb_i);
        struct fh_value *rc = LOAD_REG_OR_CONST(rc_i);
        if (!fh_is_float(rb) || !fh_is_float(rc)) {
            vm_error(vm, "using '>' with non-float values");
            goto user_err;
        }
        cmp_test = (rb->data.num > rc->data.num) ^ (int) ra_i;
        if (cmp_test) pc++;
        DISPATCH();
    }

op_CMP_GE: {
        cmp_test = 0;
        do_test_arithmetic(>=, &cmp_test, rb_i, rc_i);
        cmp_test ^= (int) ra_i;
        if (cmp_test) pc++;
        DISPATCH();
    }

op_CMP_GEI: {
        cmp_test = 0;
        struct fh_value *rb = LOAD_REG_OR_CONST(rb_i);
        struct fh_value *rc = LOAD_REG_OR_CONST(rc_i);
        if (!fh_is_integer(rb) || !fh_is_integer(rc)) {
            vm_error(vm, "using '>=' with non-integer values");
            goto user_err;
        }
        cmp_test = (rb->data.i >= rc->data.i) ^ (int) ra_i;
        if (cmp_test) pc++;
        DISPATCH();
    }

op_CMP_GEF: {
        cmp_test = 0;
        struct fh_value *rb = LOAD_REG_OR_CONST(rb_i);
        struct fh_value *rc = LOAD_REG_OR_CONST(rc_i);
        if (!fh_is_float(rb) || !fh_is_float(rc)) {
            vm_error(vm, "using '>=' with non-float values");
            goto user_err;
        }
        cmp_test = (rb->data.num >= rc->data.num) ^ (int) ra_i;
        if (cmp_test) pc++;
        DISPATCH();
    }

op_CMP_LT: {
        cmp_test = 0;
        do_test_arithmetic(<, &cmp_test, rb_i, rc_i);
        cmp_test ^= (int) ra_i;
        if (cmp_test) pc++;
        DISPATCH();
    }

op_CMP_LTF: {
        cmp_test = 0;
        struct fh_value *rb = LOAD_REG_OR_CONST(rb_i);
        struct fh_value *rc = LOAD_REG_OR_CONST(rc_i);
        if (!fh_is_float(rb) || !fh_is_float(rc)) {
            vm_error(vm, "using '<' with non-float values");
            goto user_err;
        }
        cmp_test = (rb->data.num < rc->data.num) ^ (int) ra_i;
        if (cmp_test) pc++;
        DISPATCH();
    }

op_CMP_LTI: {
        cmp_test = 0;
        struct fh_value *rb = LOAD_REG_OR_CONST(rb_i);
        struct fh_value *rc = LOAD_REG_OR_CONST(rc_i);
        if (!fh_is_integer(rb) || !fh_is_integer(rc)) {
            vm_error(vm, "using '<' with non-integer values");
            goto user_err;
        }
        cmp_test = (rb->data.i < rc->data.i) ^ (int) ra_i;
        if (cmp_test) pc++;
        DISPATCH();
    }

op_CMP_LE: {
        cmp_test = 0;
        do_test_arithmetic(<=, &cmp_test, rb_i, rc_i);
        cmp_test ^= (int) ra_i;
        if (cmp_test) pc++;
        DISPATCH();
    }

op_CMP_LEI: {
        cmp_test = 0;
        struct fh_value *rb = LOAD_REG_OR_CONST(rb_i);
        struct fh_value *rc = LOAD_REG_OR_CONST(rc_i);
        if (!fh_is_integer(rb) || !fh_is_integer(rc)) {
            vm_error(vm, "using '<=' with non-integer values");
            goto user_err;
        }
        cmp_test = (rb->data.i <= rc->data.i) ^ (int) ra_i;
        if (cmp_test) pc++;
        DISPATCH();
    }

op_CMP_LEF: {
        cmp_test = 0;
        struct fh_value *rb = LOAD_REG_OR_CONST(rb_i);
        struct fh_value *rc = LOAD_REG_OR_CONST(rc_i);
        if (!fh_is_float(rb) || !fh_is_float(rc)) {
            vm_error(vm, "using '<=' with non-float values");
            goto user_err;
        }
        cmp_test = (rb->data.num <= rc->data.num) ^ (int) ra_i;
        if (cmp_test) pc++;
        DISPATCH();
    }

op_LEN: {
        struct fh_value *rb = LOAD_REG_OR_CONST(rb_i);
        switch (rb->type) {
            case FH_VAL_ARRAY:
                ra->type = FH_VAL_INTEGER;
                ra->data.i = GET_OBJ_ARRAY(rb->data.obj)->len;
                break;
            case FH_VAL_MAP:
                ra->type = FH_VAL_INTEGER;
                ra->data.i = GET_OBJ_MAP(rb->data.obj)->len;
                break;
            case FH_VAL_STRING:
                ra->type = FH_VAL_INTEGER;
                ra->data.i = GET_VAL_STRING(rb)->size - 1;
                break;
            default:
                vm_error(vm, "len(): argument must be array/map/string");
                goto user_err;
        }
        DISPATCH();
    }

op_APPEND: {
        // append rA, rB(value), rC(array)
        struct fh_value *rb = LOAD_REG_OR_CONST(rb_i); // value
        struct fh_value *rc = LOAD_REG_OR_CONST(rc_i); // array

        if (rc->type != FH_VAL_ARRAY) {
            vm_error(vm, "append(): argument 1 must be array");
            goto user_err;
        }

        struct fh_array *arr = GET_OBJ_ARRAY(rc->data.obj);

        struct fh_value *slot = fh_grow_array_object_uninit(vm->prog, arr, 1);
        if (!slot) goto err;

        *slot = *rb;
        *ra = *rc;
        DISPATCH();
    }

    // If opcode missing in dispatch table
op_UNHANDLED:
    vm_error(vm, "unhandled opcode");
    goto err;

#undef DISPATCH
#undef LOAD_REG
#undef LOAD_CONST
#undef LOAD_REG_OR_CONST

err:
    fh_running = false;
    vm->pc = pc;
    save_error_loc(vm);
    dump_state(vm);
    return -1;

user_err:
    fh_running = false;
    vm->pc = pc;
    save_error_loc(vm);
    return -1;
}

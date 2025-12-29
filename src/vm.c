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

void fh_init_vm(struct fh_vm *vm, struct fh_program *prog) {
    vm->prog = prog;
    vm->stack = NULL;
    vm->stack_size = 0;
    vm->open_upvals = NULL;
    vm->last_error_loc = fh_make_src_loc(0, 0, 0);
    vm->last_error_addr = -1;
    vm->last_error_frame_index = -1;
    call_frame_stack_init(&vm->call_stack);
}

void fh_destroy_vm(struct fh_vm *vm) {
    if (vm->stack)
        free(vm->stack);
    call_frame_stack_free(&vm->call_stack);
}

static int vm_error(struct fh_vm *vm, char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fh_set_verror(vm->prog, fmt, ap);
    va_end(ap);
    return -1;
}

static int ensure_stack_size(struct fh_vm *vm, size_t size) {
    if (vm->stack_size >= size)
        return 0;
    size_t new_size = (size + 1024 + 1) / 1024 * 1024;
    void *new_stack = realloc(vm->stack, new_size * sizeof(struct fh_value));
    if (!new_stack)
        return vm_error(vm, "out of memory");
    vm->stack = new_stack;
    vm->stack_size = new_size;
    return 0;
}

static struct fh_vm_call_frame *prepare_call(struct fh_vm *vm, struct fh_closure *closure, int ret_reg, int n_args) {
    const struct fh_func_def *func_def = closure->func_def;

    if (ensure_stack_size(vm, ret_reg + 1 + func_def->n_regs) < 0)
        return NULL;
    if (n_args < func_def->n_params)
        memset(vm->stack + ret_reg + 1 + n_args, 0,
           (func_def->n_params - n_args) * sizeof(struct fh_value));

    memset(vm->stack + ret_reg + 1 + func_def->n_params, 0,
           (func_def->n_regs - func_def->n_params) * sizeof(struct fh_value));

    struct fh_vm_call_frame *frame = call_frame_stack_push(&vm->call_stack, NULL);
    if (!frame) {
        vm_error(vm, "out of memory");
        return NULL;
    }
    frame->closure = closure;
    frame->base = ret_reg + 1;
    frame->ret_addr = NULL;
    frame->stack_top = frame->base + closure->func_def->n_regs;

    return frame;
}

static struct fh_vm_call_frame *prepare_c_call(struct fh_vm *vm, int ret_reg, int n_args) {
    if (ensure_stack_size(vm, ret_reg + 1 + n_args) < 0)
        return NULL;

    struct fh_vm_call_frame *frame = call_frame_stack_push(&vm->call_stack, NULL);
    if (!frame) {
        vm_error(vm, "out of memory");
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
    if (n_args > closure->func_def->n_params)
        n_args = closure->func_def->n_params;

    struct fh_vm_call_frame *prev_frame = call_frame_stack_top(&vm->call_stack);
    int ret_reg = (prev_frame) ? prev_frame->base + prev_frame->closure->func_def->n_regs : 0;
    if (ensure_stack_size(vm, ret_reg + n_args + 1) < 0)
        return -1;
    memset(&vm->stack[ret_reg], 0, sizeof(struct fh_value));
    if (args)
        memcpy(&vm->stack[ret_reg+1], args, n_args*sizeof(struct fh_value));

    if (n_args < closure->func_def->n_regs)
        memset(&vm->stack[ret_reg+1+n_args], 0,
           (closure->func_def->n_regs-n_args)*sizeof(struct fh_value));

    if (!prepare_call(vm, closure, ret_reg, n_args))
        return -1;
    vm->pc = closure->func_def->code;
    if (fh_run_vm(vm) < 0)
        return -2;
    if (ret)
        *ret = vm->stack[ret_reg];
    return 0;
}

static int call_c_func(struct fh_vm *vm, fh_c_func func, struct fh_value *ret,
                       struct fh_value *args, int n_args) {
    return func(vm->prog, ret, args, n_args);
}

bool fh_val_is_true(struct fh_value *val) {
    if (val->type == FH_VAL_UPVAL)
        val = GET_OBJ_UPVAL(val)->val;
    switch (val->type) {
        case FH_VAL_NULL: return false;
        case FH_VAL_BOOL: return val->data.b;
        case FH_VAL_FLOAT: return val->data.num != 0.0;
        case FH_VAL_STRING: return GET_VAL_STRING_DATA(val)[0] != '\0';
        case FH_VAL_ARRAY: return true;
        case FH_VAL_MAP: return true;
        case FH_VAL_CLOSURE: return true;
        case FH_VAL_FUNC_DEF: return true;
        case FH_VAL_C_FUNC: return true;
        case FH_VAL_C_OBJ: return true;
        case FH_VAL_UPVAL: return false;
    }
    return false;
}

bool fh_vals_are_equal(struct fh_value *v1, struct fh_value *v2) {
    if (v1->type == FH_VAL_UPVAL)
        v1 = GET_OBJ_UPVAL(v1)->val;
    if (v2->type == FH_VAL_UPVAL)
        v2 = GET_OBJ_UPVAL(v2)->val;

    if (v1->type != v2->type)
        return false;
    switch (v1->type) {
        case FH_VAL_NULL: return true;
        case FH_VAL_BOOL: return v1->data.b == v2->data.b;
        case FH_VAL_FLOAT: return v1->data.num == v2->data.num;
        case FH_VAL_C_OBJ: return v1->data.obj == v2->data.obj;
        case FH_VAL_C_FUNC: return v1->data.c_func == v2->data.c_func;
        case FH_VAL_ARRAY: return v1->data.obj == v2->data.obj;
        case FH_VAL_MAP: return v1->data.obj == v2->data.obj;
        case FH_VAL_CLOSURE: return v1->data.obj == v2->data.obj;
        case FH_VAL_FUNC_DEF: return v1->data.obj == v2->data.obj;
        case FH_VAL_UPVAL: return false;

        case FH_VAL_STRING:
            if (GET_VAL_STRING(v1)->hash != GET_VAL_STRING(v2)->hash)
                return false;
            return strcmp(GET_OBJ_STRING_DATA(v1->data.obj), GET_OBJ_STRING_DATA(v2->data.obj)) == 0;
    }
    return false;
}

static int vm_assert_index(struct fh_vm *vm, struct fh_value *idx_val, uint32_t *out_index, const char *what) {
    if (idx_val->type != FH_VAL_FLOAT) {
        vm_error(vm, "invalid %s access (non-numeric index)", what);
        return -1;
    }

    double d = idx_val->data.num;
    if (!isfinite(d)) {
        vm_error(vm, "invalid %s access (non-finite index)", what);
        return -1;
    }

    if (d < 0.0 || d > (double) UINT32_MAX) {
        vm_error(vm, "invalid %s access (index out of range)", what);
        return -1;
    }

    uint32_t idx = (uint32_t) d;
    if ((double) idx != d) {
        vm_error(vm, "invalid %s access (non-integer index)", what);
        return -1;
    }

    *out_index = idx;
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
    int n = call_frame_stack_size(&vm->call_stack);

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
#define LOAD_REG_OR_CONST(index) \
(((index) < MAX_FUNC_REGS) ? &reg_base[index] : &const_base[(index) - MAX_FUNC_REGS - 1])
#define LOAD_CONST(index) (&const_base[(index) - MAX_FUNC_REGS - 1])

#define LOAD_REG(index)    (&reg_base[index])

#define do_simple_arithmetic(op, ra, instr)  { \
    struct fh_value *rb = LOAD_REG_OR_CONST(GET_INSTR_RB(instr)); \
    struct fh_value *rc = LOAD_REG_OR_CONST(GET_INSTR_RC(instr)); \
    if (rb->type != FH_VAL_FLOAT || rc->type != FH_VAL_FLOAT) { \
        vm_error(vm, "arithmetic on non-numeric values"); \
        goto user_err; \
    } \
    ra->type = FH_VAL_FLOAT; \
    ra->data.num = rb->data.num op rc->data.num; \
}
#define do_simple_arithmetic_unary(op, ra, instr)  { \
    struct fh_value *rb = LOAD_REG_OR_CONST(GET_INSTR_RB(instr)); \
    if (rb->type != FH_VAL_FLOAT) { \
        vm_error(vm, "arithmetic on non-numeric values"); \
        goto user_err; \
    } \
    ra->type = FH_VAL_FLOAT; \
    ra->data.num = op rb->data.num; \
}
#define do_test_arithmetic(op, ret, instr)  { \
    struct fh_value *rb = LOAD_REG_OR_CONST(GET_INSTR_RB(instr)); \
    struct fh_value *rc = LOAD_REG_OR_CONST(GET_INSTR_RC(instr)); \
    if (rb->type != FH_VAL_FLOAT || rc->type != FH_VAL_FLOAT) { \
        char err[128] = {0}; \
        sprintf(err, "using %s with non-numeric values", #op); \
        vm_error(vm, err); \
        goto user_err; \
    } \
    *ret = rb->data.num op rc->data.num; \
}
#define do_bitwise_arithmetic(op, ra, instr)  { \
    struct fh_value *rb = LOAD_REG_OR_CONST(GET_INSTR_RB(instr)); \
    struct fh_value *rc = LOAD_REG_OR_CONST(GET_INSTR_RC(instr)); \
    if (rb->type != FH_VAL_FLOAT || rc->type != FH_VAL_FLOAT) { \
        vm_error(vm, "bitwise arithmetic on non-numeric values"); \
        goto user_err; \
    } \
    ra->type = FH_VAL_FLOAT; \
    ra->data.num = (int)rb->data.num op (int)rc->data.num; \
}

int fh_run_vm(struct fh_vm *vm) {
    struct fh_value *const_base;
    struct fh_value *reg_base;

    uint32_t *pc = vm->pc;
    int cmp_test = 0;

changed_stack_frame: {
        struct fh_vm_call_frame *frame = call_frame_stack_top(&vm->call_stack);
        const_base = frame->closure->func_def->consts;
        reg_base = vm->stack + frame->base;
    }
    while (1) {
        //dump_regs(vm);
        //fh_dump_bc_instr(vm->prog, -1, *pc);

        uint32_t instr = *pc++;
        struct fh_value *ra = &reg_base[GET_INSTR_RA(instr)];
        switch (GET_INSTR_OP(instr)) {
            handle_op(OPC_LDC) {
                *ra = const_base[GET_INSTR_RU(instr)];
                break;
            }

            handle_op(OPC_LDNULL) {
                ra->type = FH_VAL_NULL;
                break;
            }

            handle_op(OPC_MOV) {
                *ra = *LOAD_REG_OR_CONST(GET_INSTR_RB(instr));
                break;
            }

            handle_op(OPC_RET) {
                struct fh_vm_call_frame *frame = call_frame_stack_top(&vm->call_stack);
                if (GET_INSTR_RA(instr))
                    vm->stack[frame->base - 1] = *LOAD_REG_OR_CONST(GET_INSTR_RB(instr));
                else
                    vm->stack[frame->base - 1].type = FH_VAL_NULL;

                // close function upvalues (only those belonging to this frame)
                struct fh_value *frame_start = vm->stack + frame->base;
                struct fh_value *frame_end = vm->stack + frame->stack_top;

                while (vm->open_upvals != NULL) {
                    struct fh_value *p = vm->open_upvals->val;

                    // if already closed, p won't point into vm->stack; stop because list is ordered by stack slots
                    if (p < frame_start || p >= frame_end)
                        break;

                    close_upval(vm);
                }

                uint32_t *ret_addr = frame->ret_addr;
                call_frame_stack_pop(&vm->call_stack, NULL);
                if (call_frame_stack_size(&vm->call_stack) == 0 || !ret_addr) {
                    vm->pc = pc;
                    return 0;
                }
                pc = ret_addr;
                goto changed_stack_frame;
            }

            handle_op(OPC_GETEL) {
                struct fh_value *rb = LOAD_REG_OR_CONST(GET_INSTR_RB(instr));
                struct fh_value *rc = LOAD_REG_OR_CONST(GET_INSTR_RC(instr));
                if (rb->type == FH_VAL_ARRAY) {
                    uint32_t idx;
                    if (vm_assert_index(vm, rc, &idx, "array") < 0)
                        goto user_err;

                    struct fh_value *val = fh_get_array_item(rb, idx);
                    if (!val) {
                        *ra = fh_new_null();
                        break;
                    }
                    *ra = *val;
                    break;
                }
                if (rb->type == FH_VAL_MAP) {
                    if (rc->type == FH_VAL_NULL) {
                        *ra = fh_new_null();
                        break;
                    }
                    if (rc->type == FH_VAL_FLOAT && !isfinite(rc->data.num)) {
                        *ra = fh_new_null();
                        break;
                    }

                    if (fh_get_map_value(rb, rc, ra) < 0) {
                        *ra = fh_new_null();
                    }
                    break;
                }
                if (rb->type == FH_VAL_STRING) {
                    uint32_t idx;
                    if (vm_assert_index(vm, rc, &idx, "string") < 0)
                        goto user_err;

                    struct fh_string *s = GET_VAL_STRING(rb);
                    uint32_t len = s->size ? (s->size - 1) : 0;
                    if (idx >= len) {
                        *ra = fh_new_null();
                        break;
                    }
                    const char out[2] = {GET_OBJ_STRING_DATA(s)[idx], '\0'};
                    *ra = fh_new_string(vm->prog, out);
                    break;
                }
                vm_error(vm, "invalid element access (non-container object)");
                goto user_err;
            }

            handle_op(OPC_SETEL) {
                struct fh_value *rb = LOAD_REG_OR_CONST(GET_INSTR_RB(instr));
                struct fh_value *rc = LOAD_REG_OR_CONST(GET_INSTR_RC(instr));
                if (ra->type == FH_VAL_ARRAY) {
                    uint32_t idx;
                    if (vm_assert_index(vm, rb, &idx, "array") < 0)
                        goto user_err;

                    struct fh_value *val = fh_get_array_item(ra, idx);
                    if (!val) {
                        vm_error(vm, "invalid array index, %u", idx);
                        goto user_err;
                    }

                    *val = *rc;
                    break;
                }
                if (ra->type == FH_VAL_MAP) {
                    if (fh_add_map_entry(vm->prog, ra, rb, rc) < 0)
                        goto err;
                    break;
                }
                vm_error(vm, "invalid element access (non-container object)");
                goto user_err;
            }

            handle_op(OPC_NEWARRAY) {
                int n_elems = GET_INSTR_RU(instr);

                struct fh_array *arr = fh_make_array(vm->prog, false);
                if (!arr)
                    goto err;
                if (n_elems != 0) {
                    GC_PIN_OBJ(arr);
                    struct fh_value *first = fh_grow_array_object(vm->prog, arr, n_elems);
                    if (!first) {
                        GC_UNPIN_OBJ(arr);
                        goto err;
                    }
                    GC_UNPIN_OBJ(arr);
                    memcpy(first, ra + 1, n_elems*sizeof(struct fh_value));
                }
                ra->type = FH_VAL_ARRAY;
                ra->data.obj = arr;
                break;
            }

            handle_op(OPC_NEWMAP) {
                int n_elems = GET_INSTR_RU(instr);
                int n_elems_half = n_elems >> 1;

                struct fh_map *map = fh_make_map(vm->prog, false);
                if (!map)
                    goto err;
                fh_alloc_map_object_len(map, n_elems_half);
                if (n_elems != 0) {
                    GC_PIN_OBJ(map);
                    for (int i = 0; i < n_elems_half; i++) {
                        int ni = i << 1;
                        struct fh_value *key = &ra[ni + 1];
                        struct fh_value *val = &ra[ni + 2];
                        if (fh_add_map_object_entry(vm->prog, map, key, val) < 0) {
                            GC_UNPIN_OBJ(map);
                            goto err;
                        }
                    }
                    GC_UNPIN_OBJ(map);
                }
                ra->type = FH_VAL_MAP;
                ra->data.obj = map;
                break;
            }

            handle_op(OPC_CLOSURE) {
                struct fh_value *rb = LOAD_REG_OR_CONST(GET_INSTR_RB(instr));
                if (rb->type != FH_VAL_FUNC_DEF) {
                    vm_error(vm, "invalid value for closure (not a func_def)");
                    goto err;
                }
                struct fh_func_def *func_def = GET_VAL_FUNC_DEF(rb);
                struct fh_closure *c = fh_make_closure(vm->prog, false, func_def);
                if (!c)
                    goto err;
                GC_PIN_OBJ(c);
                struct fh_vm_call_frame *frame = NULL;
                int i = 0;
                for (; i < func_def->n_upvals; i++) {
                    if (func_def->upvals[i].type == FH_UPVAL_TYPE_UPVAL) {
                        if (frame == NULL)
                            frame = call_frame_stack_top(&vm->call_stack);
                        c->upvals[i] = frame->closure->upvals[func_def->upvals[i].num];
                    } else {
                        c->upvals[i] = find_or_add_upval(vm, &reg_base[func_def->upvals[i].num]);
                        GC_PIN_OBJ(c->upvals[i]);
                    }
                }
                ra->type = FH_VAL_CLOSURE;
                ra->data.obj = c;
                i = 0;
                for (; i < func_def->n_upvals; i++)
                    GC_UNPIN_OBJ(c->upvals[i]);
                GC_UNPIN_OBJ(c);
                break;
            }

            handle_op(OPC_GETUPVAL) {
                int b = GET_INSTR_RB(instr);
                struct fh_vm_call_frame *frame = call_frame_stack_top(&vm->call_stack);
                *ra = *frame->closure->upvals[b]->val;
                break;
            }

            handle_op(OPC_SETUPVAL) {
                int a = GET_INSTR_RA(instr);
                struct fh_value *rb = LOAD_REG_OR_CONST(GET_INSTR_RB(instr));
                struct fh_vm_call_frame *frame = call_frame_stack_top(&vm->call_stack);
                *frame->closure->upvals[a]->val = *rb;
                break;
            }

            handle_op(OPC_BNOT) {
                do_simple_arithmetic_unary(~(int), ra, instr);
                break;
            }

            handle_op(OPC_RSHIFT) {
                do_bitwise_arithmetic(>>, ra, instr);
                break;
            }

            handle_op(OPC_LSHIFT) {
                do_bitwise_arithmetic(<<, ra, instr);
                break;
            }

            handle_op(OPC_BOR) {
                do_bitwise_arithmetic(|, ra, instr);
                break;
            }

            handle_op(OPC_BAND) {
                do_bitwise_arithmetic(&, ra, instr);
                break;
            }

            handle_op(OPC_BXOR) {
                do_bitwise_arithmetic(^, ra, instr);
                break;
            }

            handle_op(OPC_INC) {
                struct fh_value *rb = LOAD_REG_OR_CONST(GET_INSTR_RB(instr));
                if (rb->type != FH_VAL_FLOAT) {
                    vm_error(vm, "increment on non-numeric value");
                    goto user_err;
                }
                ra->type = FH_VAL_FLOAT;
                ra->data.num = rb->data.num + 1.0;
                break;
            }

            handle_op(OPC_DEC) {
                struct fh_value *rb = LOAD_REG_OR_CONST(GET_INSTR_RB(instr));
                if (rb->type != FH_VAL_FLOAT) {
                    vm_error(vm, "decrement on non-numeric value");
                    goto user_err;
                }
                ra->type = FH_VAL_FLOAT;
                ra->data.num = rb->data.num - 1.0;
                break;
            }

            handle_op(OPC_ADD) {
                struct fh_value *rb = LOAD_REG_OR_CONST(GET_INSTR_RB(instr));
                struct fh_value *rc = LOAD_REG_OR_CONST(GET_INSTR_RC(instr));

                if (rb->type == FH_VAL_FLOAT && rc->type == FH_VAL_FLOAT) {
                    ra->type = FH_VAL_FLOAT;
                    ra->data.num = rb->data.num + rc->data.num;
                } else if (rb->type == FH_VAL_STRING) {
                    const char *s1 = GET_OBJ_STRING_DATA(rb->data.obj);
                    if (rc->type == FH_VAL_STRING) {
                        const char *s2 = GET_OBJ_STRING_DATA(rc->data.obj);

                        const size_t len = strlen(s1) + strlen(s2) + 1;
                        char *concate = malloc(len);
                        if (!concate) {
                            vm_error(vm, "out of memory");
                            goto err;
                        }

                        snprintf(concate, len, "%s%s", s1, s2);

                        *ra = fh_new_string(vm->prog, concate);
                        free(concate);
                    } else if (rc->type == FH_VAL_FLOAT) {
                        int needed = snprintf(NULL, 0, "%s%g", s1, rc->data.num);
                        if (needed < 0) {
                            vm_error(vm, "string formatting error");
                            goto err;
                        }

                        char *concate = malloc((size_t) needed + 1);
                        if (!concate) {
                            vm_error(vm, "out of memory");
                            goto err;
                        }

                        snprintf(concate, (size_t)needed + 1, "%s%g", s1, rc->data.num);

                        *ra = fh_new_string(vm->prog, concate);
                        free(concate);
                    } else {
                        vm_error(vm, "can't add the two variables, type %s and type %s",
                                 fh_type_to_str(vm->prog, rb->type),
                                 fh_type_to_str(vm->prog, rc->type));
                        goto user_err;
                    }
                } else if (rc->type == FH_VAL_STRING) {
                    const char *s1 = GET_OBJ_STRING_DATA(rc->data.obj);
                    if (rb->type == FH_VAL_STRING) {
                        const char *s2 = GET_OBJ_STRING_DATA(rb->data.obj);

                        const size_t len = strlen(s1) + strlen(s2) + 1;
                        char *concate = malloc(len);
                        if (!concate) {
                            vm_error(vm, "out of memory");
                            goto err;
                        }
                        snprintf(concate, len, "%s%s", s1, s2);

                        *ra = fh_new_string(vm->prog, concate);
                        free(concate);
                    } else if (rb->type == FH_VAL_FLOAT) {
                        int needed = snprintf(NULL, 0, "%g%s", rb->data.num, s1) + 1;
                        if (needed < 0) {
                            vm_error(vm, "string formatting error");
                            goto err;
                        }
                        char *concate = malloc(needed);
                        if (!concate) {
                            vm_error(vm, "out of memory");
                            goto err;
                        }
                        snprintf(concate, needed, "%g%s", rb->data.num, s1);

                        *ra = fh_new_string(vm->prog, concate);
                        free(concate);
                    } else {
                        vm_error(vm, "can't add the two variables, type %s and type %s",
                                 fh_type_to_str(vm->prog, rb->type),
                                 fh_type_to_str(vm->prog, rc->type));
                        goto user_err;
                    }
                } else {
                    vm_error(vm, "can't add the two variables, type %s and type %s",
                             fh_type_to_str(vm->prog, rb->type),
                             fh_type_to_str(vm->prog, rc->type));
                    goto user_err;
                }
                break;
            }

            handle_op(OPC_SUB) {
                do_simple_arithmetic(-, ra, instr);
                break;
            }

            handle_op(OPC_MUL) {
                do_simple_arithmetic(*, ra, instr);
                break;
            }

            handle_op(OPC_DIV) {
                do_simple_arithmetic(/, ra, instr);
                break;
            }

            handle_op(OPC_MOD) {
                struct fh_value *rb = LOAD_REG_OR_CONST(GET_INSTR_RB(instr));
                struct fh_value *rc = LOAD_REG_OR_CONST(GET_INSTR_RC(instr));
                if (rb->type != FH_VAL_FLOAT || rc->type != FH_VAL_FLOAT) {
                    vm_error(vm, "arithmetic on non-numeric values");
                    goto user_err;
                }
                ra->type = FH_VAL_FLOAT;
                ra->data.num = fmod(rb->data.num, rc->data.num);
                break;
            }

            handle_op(OPC_NEG) {
                do_simple_arithmetic_unary(-, ra, instr);
                break;
            }

            handle_op(OPC_NOT) {
                struct fh_value *rb = LOAD_REG_OR_CONST(GET_INSTR_RB(instr));
                *ra = fh_new_bool(! fh_val_is_true(rb));
                break;
            }

            handle_op(OPC_CALL) {
                //dump_regs(vm);
                struct fh_vm_call_frame *frame = call_frame_stack_top(&vm->call_stack);
                int ret_reg = (int) (ra - vm->stack); // <- slot absolut (R[A])
                int n_args = GET_INSTR_RB(instr); // <- B

                if (ra->type == FH_VAL_CLOSURE) {
                    struct fh_closure *cl = GET_OBJ_CLOSURE(ra->data.obj);
                    uint32_t *func_addr = cl->func_def->code;
                    /*
                     * WARNING: prepare_call() may move the stack, so don't trust reg_base
                     * or ra after calling it -- jumping to changed_stack_frame fixes it.
                     */
                    struct fh_vm_call_frame *new_frame = prepare_call(vm, cl, ret_reg, n_args);

                    if (!new_frame) goto err;

                    new_frame->ret_addr = pc;
                    pc = func_addr;
                    goto changed_stack_frame;
                }
                if (ra->type == FH_VAL_C_FUNC) {
                    struct fh_vm_call_frame *new_frame =
                            prepare_c_call(vm, ret_reg, n_args);
                    if (!new_frame) goto err;

                    int r = call_c_func(vm, ra->data.c_func,
                                        vm->stack + new_frame->base - 1,
                                        vm->stack + new_frame->base,
                                        n_args);

                    call_frame_stack_pop(&vm->call_stack, NULL);
                    if (r < 0) goto user_err;
                    // still in same bytecode function after C call
                    break;
                }
                vm_error(vm, "call to non-function value");
                goto user_err;
            }

            handle_op(OPC_JMP) {
                int a = GET_INSTR_RA(instr);
                while (a-- > 0) {
                    if (!vm->open_upvals) break;
                    close_upval(vm);
                }
                pc += GET_INSTR_RS(instr);
                break;
            }

            handle_op(OPC_TEST) {
                int a = GET_INSTR_RA(instr);
                struct fh_value *rb = LOAD_REG_OR_CONST(GET_INSTR_RB(instr));
                cmp_test = fh_val_is_true(rb) ^ a;
                if (cmp_test) {
                    pc++;
                    break;
                }
                pc += GET_INSTR_RS(*pc) + 1;
                break;
            }

            handle_op(OPC_CMP_EQ) {
                int inv = GET_INSTR_RA(instr);
                struct fh_value *rb = LOAD_REG_OR_CONST(GET_INSTR_RB(instr));
                struct fh_value *rc = LOAD_REG_OR_CONST(GET_INSTR_RC(instr));
                cmp_test = fh_vals_are_equal(rb, rc) ^ inv;
                if (cmp_test)
                    pc++;
                break;
            }

            handle_op(OPC_CMP_GT) {
                cmp_test = 0;
                do_test_arithmetic(>, &cmp_test, instr);
                if (cmp_test)
                    pc++;
                break;
            }

            handle_op(OPC_CMP_GE) {
                cmp_test = 0;
                do_test_arithmetic(>=, &cmp_test, instr);
                if (cmp_test)
                    pc++;
                break;
            }

            handle_op(OPC_CMP_LT) {
                cmp_test = 0;
                do_test_arithmetic(<, &cmp_test, instr);
                if (cmp_test)
                    pc++;
                break;
            }

            handle_op(OPC_CMP_LE) {
                cmp_test = 0;
                do_test_arithmetic(<=, &cmp_test, instr);
                if (cmp_test)
                    pc++;
                break;
            }

            default:
                vm_error(vm, "unhandled opcode");
                goto err;
        }
    }

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
    //dump_state(vm);
    return -1;
}

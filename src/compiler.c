/* compiler.c */
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>

#include "compiler.h"
#include "stack.h"
#include "ast.h"
#include "bytecode.h"
#include "program.h"

#define TMP_VARIABLE     ((fh_symbol_id)-1)
#define MAX_FUNC_CONSTS  (512-MAX_FUNC_REGS)

#define RK_IS_REG(i)   ((i) < MAX_FUNC_REGS)
#define RK_IS_CONST(i) ((i) > MAX_FUNC_REGS)
#define RK_CONST_INDEX(i) ((i) - MAX_FUNC_REGS - 1)

#define LOAD_REG_OR_CONST(i) (RK_IS_REG(i) ? &reg_base[(i)] : &const_base[RK_CONST_INDEX(i)])
#define LOAD_REG(i) (&reg_base[(i)])
#define LOAD_CONST(i) (&const_base[RK_CONST_INDEX(i)])

static void pop_func_info(struct fh_compiler *c);

static int compile_expr_to_reg(struct fh_compiler *c, struct fh_p_expr *expr, int dest_reg);

static int compile_block(struct fh_compiler *c, struct fh_src_loc loc, struct fh_p_stmt_block *block,
                         enum compiler_block_type block_type, int loop_start_addr);

static int compile_stmt(struct fh_compiler *c, struct fh_p_stmt *stmt);

static int compile_expr(struct fh_compiler *c, struct fh_p_expr *expr);

static int compile_func(struct fh_compiler *c, struct fh_src_loc loc, struct fh_p_expr_func *func,
                        struct fh_func_def *func_def, struct func_info *parent);

static int compile_bin_op(struct fh_compiler *c, struct fh_src_loc loc, struct fh_p_expr_bin_op *expr);

static int compile_test_bin_op(struct fh_compiler *c, struct fh_src_loc loc, struct fh_p_expr_bin_op *bin_op,
                               bool invert_test);

static int compile_load_lvalue_to_reg(struct fh_compiler *c, struct fh_p_expr *lv, int dst_reg);

static int compile_store_reg_to_lvalue(struct fh_compiler *c, struct fh_p_expr *lv, int src_rk);

static int compile_postfix_incdec_to_reg(struct fh_compiler *c, struct fh_p_expr_postfix *pf, int dest_reg);

void fh_init_compiler(struct fh_compiler *c, struct fh_program *prog) {
    c->prog = prog;
    c->ast = NULL;
    func_info_stack_init(&c->funcs);
}

static void reset_compiler(struct fh_compiler *c) {
    c->ast = NULL;
    while (func_info_stack_size(&c->funcs) > 0)
        pop_func_info(c);
}

void fh_destroy_compiler(struct fh_compiler *c) {
    reset_compiler(c);
    func_info_stack_free(&c->funcs);
}

static struct func_info *new_func_info(struct fh_compiler *c, struct fh_src_loc loc, struct func_info *parent) {
    struct func_info *fi = func_info_stack_push(&c->funcs, NULL);
    if (!fi)
        return NULL;

    fi->parent = parent;
    fi->num_regs = 0;
    code_stack_init(&fi->code);
    value_stack_init(&fi->consts);
    upval_def_stack_init(&fi->upvals);
    reg_stack_init(&fi->regs);
    int_stack_init(&fi->break_addrs);
    int_stack_init(&fi->continue_addrs);
    block_info_stack_init(&fi->blocks);
    fi->last_instr_src_loc = loc;
    fh_init_buffer(&fi->code_src_loc);

    return func_info_stack_top(&c->funcs);
}

static void pop_func_info(struct fh_compiler *c) {
    struct func_info fi;
    if (func_info_stack_pop(&c->funcs, &fi) < 0)
        return;
    reg_stack_free(&fi.regs);
    int_stack_free(&fi.break_addrs);
    int_stack_free(&fi.continue_addrs);
    code_stack_free(&fi.code);
    value_stack_free(&fi.consts);
    upval_def_stack_free(&fi.upvals);
    block_info_stack_free(&fi.blocks);
    fh_destroy_buffer(&fi.code_src_loc);
}

static struct func_info *get_cur_func_info(struct fh_compiler *c, struct fh_src_loc loc) {
    struct func_info *fi = func_info_stack_top(&c->funcs);
    if (!fi)
        fh_compiler_error(c, loc, "INTERNAL COMPILER ERROR: no current function");
    return fi;
}

static struct block_info *new_block_info(struct func_info *fi) {
    struct block_info *bi = block_info_stack_push(&fi->blocks, NULL);
    if (!bi)
        return NULL;

    bi->type = COMP_BLOCK_PLAIN;
    bi->start_addr = -1;
    bi->parent_num_regs = 0;

    return block_info_stack_top(&fi->blocks);
}

static struct block_info *get_cur_block_info(struct fh_compiler *c,
                                             struct fh_src_loc loc, enum compiler_block_type type) {
    struct func_info *fi = get_cur_func_info(c, loc);
    if (!fi)
        return NULL;
    for (int i = block_info_stack_size(&fi->blocks) - 1; i >= 0; i--) {
        struct block_info *bi = block_info_stack_item(&fi->blocks, i);
        if (!bi) {
            fh_compiler_error(c, loc, "INTERNAL COMPILER ERROR: no current block");
            return NULL;
        }
        if (type == bi->type)
            return bi;
    }
    //    fh_compiler_error(c, loc, "not inside loop");
    return NULL;
}

static int get_cur_pc(struct fh_compiler *c, struct fh_src_loc loc) {
    struct func_info *fi = get_cur_func_info(c, loc);
    if (!fi)
        return -1;
    return code_stack_size(&fi->code);
}

static const char *get_ast_symbol_name(struct fh_compiler *c, fh_symbol_id sym) {
    const char *name = fh_get_ast_symbol(c->ast, sym);
    if (!name)
        name = "<INTERNAL COMPILER ERROR: UNKNOWN VARIABLE>";
    return name;
}

int fh_compiler_error(struct fh_compiler *c, struct fh_src_loc loc, char *fmt, ...) {
    char str[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(str, sizeof(str), fmt, ap);
    va_end(ap);

    fh_set_error(c->prog, "%s:%d:%d: %s", fh_get_ast_file_name(c->ast, loc.file_id), loc.line, loc.col, str);
    return -1;
}

static struct fh_func_def *new_func_def(struct fh_compiler *c, struct fh_src_loc loc, const char *name, int n_params) {
    struct fh_func_def *func_def = fh_make_func_def(c->prog, true);
    if (!func_def)
        return NULL;
    func_def->name = NULL;
    func_def->n_params = n_params;
    func_def->n_regs = 0;
    func_def->code = NULL;
    func_def->code_size = 0;
    func_def->consts = NULL;
    func_def->n_consts = 0;
    func_def->upvals = NULL;
    func_def->n_upvals = 0;
    func_def->code_src_loc = NULL;
    func_def->code_src_loc_size = 0;
    func_def->code_creation_loc = loc;
    if (name) {
        func_def->name = fh_make_string(c->prog, true, name);
        if (!func_def->name)
            return NULL;
    }
    return func_def;
}

static int add_instr(struct fh_compiler *c, struct fh_src_loc loc, uint32_t instr) {
    struct func_info *fi = get_cur_func_info(c, loc);
    if (!fi)
        return -1;

    if (!code_stack_push(&fi->code, &instr))
        return fh_compiler_error(c, loc, "out of memory for bytecode");

    if (fh_encode_src_loc_change(&fi->code_src_loc, &fi->last_instr_src_loc, &loc) < 0)
        return fh_compiler_error(c, loc, "out of memory for bytecode source location");
    fi->last_instr_src_loc = loc;
    return 0;
}

static int set_jmp_target(struct fh_compiler *c, struct fh_src_loc loc, int instr_addr, int target_addr) {
    struct func_info *fi = get_cur_func_info(c, loc);
    if (!fi)
        return -1;

    int diff = target_addr - instr_addr - 1;
    if (diff < -(1 << 17) || diff > (1 << 17))
        return fh_compiler_error(c, loc, "too far to jump (%u to %u)", instr_addr, target_addr);
    int cur_pc = get_cur_pc(c, loc);
    if (target_addr > cur_pc)
        return fh_compiler_error(c, loc, "invalid jump target location (%d)", target_addr);

    //printf("diff = %u - %u - 1 = %ld\n", target_addr, instr_addr, diff);

    uint32_t *p_instr = code_stack_item(&fi->code, instr_addr);
    if (!p_instr)
        return fh_compiler_error(c, loc, "invalid instruction location (%d)", instr_addr);
    *p_instr &= ~INSTR_RS_MASK;
    *p_instr |= PLACE_INSTR_RS(diff);
    return 0;
}

static struct fh_value *add_const(struct fh_compiler *c, struct fh_src_loc loc) {
    struct func_info *fi = get_cur_func_info(c, loc);
    if (!fi)
        return NULL;

    if (value_stack_size(&fi->consts) >= MAX_FUNC_CONSTS) {
        fh_compiler_error(c, loc, "too many constants in function");
        return NULL;
    }

    struct fh_value *val = value_stack_push(&fi->consts, NULL);
    if (!val) {
        fh_compiler_error(c, loc, "out of memory");
        return NULL;
    }
    return val;
}

static int add_const_null(struct fh_compiler *c, struct fh_src_loc loc) {
    struct func_info *fi = get_cur_func_info(c, loc);
    if (!fi)
        return -1;
    int k = 0;
    stack_foreach(struct fh_value, *, c, &fi->consts) {
        if (c->type == FH_VAL_NULL)
            return k;
        k++;
    }

    k = value_stack_size(&fi->consts);
    struct fh_value *val = add_const(c, loc);
    if (!val)
        return -1;
    val->type = FH_VAL_NULL;
    return k;
}

static int add_const_bool(struct fh_compiler *c, struct fh_src_loc loc, bool b) {
    struct func_info *fi = get_cur_func_info(c, loc);
    if (!fi)
        return -1;
    int k = 0;
    stack_foreach(struct fh_value, *, c, &fi->consts) {
        if (c->type == FH_VAL_BOOL && c->data.b == b)
            return k;
        k++;
    }

    k = value_stack_size(&fi->consts);
    struct fh_value *val = add_const(c, loc);
    if (!val)
        return -1;
    val->type = FH_VAL_BOOL;
    val->data.b = b;
    return k;
}

static int add_const_number(struct fh_compiler *c, struct fh_src_loc loc, double num) {
    struct func_info *fi = get_cur_func_info(c, loc);
    if (!fi)
        return -1;
    int k = 0;
    stack_foreach(struct fh_value, *, c, &fi->consts) {
        if (c->type == FH_VAL_FLOAT && c->data.num == num)
            return k;
        k++;
    }

    k = value_stack_size(&fi->consts);
    struct fh_value *val = add_const(c, loc);
    if (!val)
        return -1;
    val->type = FH_VAL_FLOAT;
    val->data.num = num;
    return k;
}

static int add_const_string(struct fh_compiler *c, struct fh_src_loc loc, fh_string_id str_id) {
    struct func_info *fi = get_cur_func_info(c, loc);
    if (!fi)
        return -1;
    int k = 0;
    const char *str = fh_get_ast_string(c->ast, str_id);
    stack_foreach(struct fh_value, *, c, &fi->consts) {
        if (c->type == FH_VAL_STRING && strcmp(fh_get_string(c), str) == 0)
            return k;
        k++;
    }

    k = value_stack_size(&fi->consts);
    struct fh_value *val = add_const(c, loc);
    if (!val)
        return -1;
    struct fh_string *str_obj = fh_make_string(c->prog, true, str);
    if (!str_obj) {
        value_stack_pop(&fi->consts, NULL);
        return -1;
    }
    val->type = FH_VAL_STRING;
    val->data.obj = str_obj;
    return k;
}

static int add_const_global_func(struct fh_compiler *c, struct fh_src_loc loc, fh_symbol_id func) {
    struct func_info *fi = get_cur_func_info(c, loc);
    if (!fi)
        return -1;

    const char *name = fh_get_ast_symbol(c->ast, func);

    // closure
    struct fh_closure *closure = fh_get_global_func_by_name(c->prog, name);
    if (closure) {
        int k = 0;
        stack_foreach(struct fh_value, *, c, &fi->consts) {
            if (c->type == FH_VAL_CLOSURE && c->data.obj == closure)
                return k;
            k++;
        }

        k = value_stack_size(&fi->consts);
        struct fh_value *val = add_const(c, loc);
        if (!val)
            return -1;
        val->type = FH_VAL_CLOSURE;
        val->data.obj = closure;
        return k;
    }

    // C function
    fh_c_func c_func = fh_get_c_func_by_name(c->prog, name);
    if (c_func) {
        int k = 0;
        stack_foreach(struct fh_value, *, c, &fi->consts) {
            if (c->type == FH_VAL_C_FUNC && c->data.c_func == c_func)
                return k;
            k++;
        }
        k = value_stack_size(&fi->consts);
        struct fh_value *val = add_const(c, loc);
        if (!val)
            return -1;
        val->type = FH_VAL_C_FUNC;
        val->data.c_func = c_func;
        return k;
    }

    return fh_compiler_error(c, loc, "undefined function '%s'", get_ast_symbol_name(c, func));
}

static int add_const_func_def(struct fh_compiler *c, struct fh_src_loc loc, struct fh_func_def *func_def) {
    struct func_info *fi = get_cur_func_info(c, loc);
    if (!fi)
        return -1;
    int k = value_stack_size(&fi->consts);
    struct fh_value *val = add_const(c, loc);
    if (!val)
        return -1;
    val->type = FH_VAL_FUNC_DEF;
    val->data.obj = func_def;
    return k;
}

static int add_upval(struct fh_compiler *c, struct fh_src_loc loc, struct func_info *fi, enum fh_upval_def_type type,
                     int num) {
    int upval = 0;
    stack_foreach(struct fh_upval_def, *, uv, &fi->upvals) {
        if (uv->type == type && num == uv->num)
            return upval;
        upval++;
    }

    upval = upval_def_stack_size(&fi->upvals);
    struct fh_upval_def *uv = upval_def_stack_push(&fi->upvals, NULL);
    if (!uv) {
        fh_compiler_error(c, loc, "out of memory");
        return -1;
    }
    uv->type = type;
    uv->num = num;
    return upval;
}

static int alloc_reg(struct fh_compiler *c, struct fh_src_loc loc, fh_symbol_id var) {
    struct func_info *fi = get_cur_func_info(c, loc);
    if (!fi)
        return -1;

    int new_reg = -1;
    int i = 0;
    stack_foreach(struct reg_info, *, ri, &fi->regs) {
        if (!ri->alloc) {
            new_reg = i;
            break;
        }
        i++;
    }

    if (new_reg < 0) {
        new_reg = reg_stack_size(&fi->regs);
        if (new_reg >= MAX_FUNC_REGS)
            return fh_compiler_error(c, loc, "too many registers used");
        if (!reg_stack_push(&fi->regs, NULL))
            return fh_compiler_error(c, loc, "out of memory");
    }

    struct reg_info *ri = reg_stack_item(&fi->regs, new_reg);
    ri->var = var;
    ri->alloc = true;
    ri->used_by_inner_func = false;

    if (fi->num_regs <= new_reg)
        fi->num_regs = new_reg + 1;
    return new_reg;
}

static void free_reg(struct fh_compiler *c, struct fh_src_loc loc, int reg) {
    struct func_info *fi = get_cur_func_info(c, loc);
    if (!fi) {
        fprintf(stderr, "%s\n", fh_get_error(c->prog));
        return;
    }

    struct reg_info *ri = reg_stack_item(&fi->regs, reg);
    if (!ri) {
        fprintf(stderr, "INTERNAL COMPILER ERROR: freeing invalid register (%d)\n", reg);
        return;
    }

    ri->alloc = false;
}

static int alloc_n_regs(struct fh_compiler *c, struct fh_src_loc loc, int n) {
    struct func_info *fi = get_cur_func_info(c, loc);
    if (!fi)
        return -1;

    int last_alloc = -1;
    for (int i = reg_stack_size(&fi->regs) - 1; i >= 0; i--) {
        struct reg_info *ri = reg_stack_item(&fi->regs, i);
        if (ri->alloc) {
            last_alloc = i;
            break;
        }
    }

    int first_reg = last_alloc + 1;
    if (first_reg + n >= MAX_FUNC_REGS)
        return fh_compiler_error(c, loc, "too many registers used");
    for (int i = 0; i < n; i++) {
        int reg = first_reg + i;
        if (reg_stack_size(&fi->regs) <= reg) {
            if (!reg_stack_push(&fi->regs, NULL))
                return fh_compiler_error(c, loc, "out of memory");
        }
        struct reg_info *ri = reg_stack_item(&fi->regs, reg);
        ri->var = TMP_VARIABLE;
        ri->alloc = true;
        ri->used_by_inner_func = false;
    }

    if (fi->num_regs <= first_reg + n - 1)
        fi->num_regs = first_reg + n;
    return first_reg;
}

static void free_tmp_regs(struct fh_compiler *c, struct fh_src_loc loc) {
    struct func_info *fi = get_cur_func_info(c, loc);
    if (!fi)
        return;

    stack_foreach(struct reg_info, *, ri, &fi->regs) {
        if (ri->alloc && ri->var == TMP_VARIABLE)
            ri->alloc = false;
    }
}

static void free_var_regs(struct fh_compiler *c, struct fh_src_loc loc, int first_var_reg) {
    struct func_info *fi = get_cur_func_info(c, loc);
    if (!fi)
        return;

    for (int i = reg_stack_size(&fi->regs) - 1; i >= first_var_reg; i--) {
        struct reg_info *ri = reg_stack_item(&fi->regs, i);
        if (ri->alloc && ri->var != TMP_VARIABLE)
            ri->alloc = false;
    }
}

static int set_reg_var(struct fh_compiler *c, struct fh_src_loc loc, int reg, fh_symbol_id var) {
    struct func_info *fi = get_cur_func_info(c, loc);
    if (!fi)
        return -1;

    struct reg_info *ri = reg_stack_item(&fi->regs, reg);
    if (!ri)
        return fh_compiler_error(c, loc, "INTERNAL COMPILER ERROR: unknown register %d", reg);
    ri->var = var;
    return 0;
}

static int get_func_var_reg(struct func_info *fi, fh_symbol_id var) {
    for (int i = reg_stack_size(&fi->regs) - 1; i >= 0; i--) {
        struct reg_info *ri = reg_stack_item(&fi->regs, i);
        if (ri->alloc && ri->var == var)
            return i;
    }
    return -1;
}

static int get_var_reg(struct fh_compiler *c, struct fh_src_loc loc, fh_symbol_id var) {
    struct func_info *fi = get_cur_func_info(c, loc);
    if (!fi)
        return -1;
    return get_func_var_reg(fi, var);
}

static int add_func_var_upval(struct fh_compiler *c, struct fh_src_loc loc, struct func_info *fi, fh_symbol_id var,
                              int *ret_upval) {
    if (!fi->parent) {
        *ret_upval = -1;
        return 0;
    }

    int reg = get_func_var_reg(fi->parent, var);
    if (reg >= 0) {
        struct reg_info *ri = reg_stack_item(&fi->parent->regs, reg);
        ri->used_by_inner_func = true;

        int upval = add_upval(c, loc, fi, FH_UPVAL_TYPE_REG, reg);
        if (upval < 0)
            return -1;
        *ret_upval = upval;
        return 0;
    }

    if (add_func_var_upval(c, loc, fi->parent, var, ret_upval) < 0)
        return -1;
    if (*ret_upval < 0)
        return 0;
    int upval = add_upval(c, loc, fi, FH_UPVAL_TYPE_UPVAL, *ret_upval);
    if (upval < 0)
        return -1;
    *ret_upval = upval;
    return 0;
}

static int add_var_upval(struct fh_compiler *c, struct fh_src_loc loc, fh_symbol_id var, int *ret_upval) {
    struct func_info *fi = get_cur_func_info(c, loc);
    if (!fi)
        return -1;
    return add_func_var_upval(c, loc, fi, var, ret_upval);
}

static int get_top_var_reg(struct fh_compiler *c, struct fh_src_loc loc) {
    struct func_info *fi = get_cur_func_info(c, loc);
    if (!fi)
        return -1;

    for (int i = reg_stack_size(&fi->regs) - 1; i >= 0; i--) {
        struct reg_info *ri = reg_stack_item(&fi->regs, i);
        if (ri->alloc && ri->var != TMP_VARIABLE)
            return i;
    }
    return -1;
}

static int get_num_open_upvals(struct fh_compiler *c, struct fh_src_loc loc, int first_var_reg) {
    struct func_info *fi = get_cur_func_info(c, loc);
    if (!fi)
        return -1;

    int num_open_upvals = 0;
    for (int i = reg_stack_size(&fi->regs) - 1; i >= first_var_reg; i--) {
        struct reg_info *ri = reg_stack_item(&fi->regs, i);
        if (ri->alloc && ri->used_by_inner_func) {
            if (ri->var == TMP_VARIABLE)
                return fh_compiler_error(c, loc, "INTERNAL COMPILER ERROR: tmp reg used by inner function");
            num_open_upvals++;
        }
    }
    return num_open_upvals;
}

static int compile_var(struct fh_compiler *c, struct fh_src_loc loc, fh_symbol_id var) {
    // local variable
    int reg = get_var_reg(c, loc, var);
    if (reg >= 0)
        return reg;

    // parent function variable
    int upval;
    if (add_var_upval(c, loc, var, &upval) < 0)
        return -1;
    if (upval >= 0) {
        int reg = alloc_reg(c, loc, TMP_VARIABLE);
        if (reg < 0)
            return -1;
        if (add_instr(c, loc, MAKE_INSTR_AB(OPC_GETUPVAL, reg, upval)) < 0)
            return -1;
        return reg;
    }

    // global function
    int k = add_const_global_func(c, loc, var);
    if (k >= 0)
        return k + MAX_FUNC_REGS + 1;

    return fh_compiler_error(c, loc, "unknown variable or function '%s'", get_ast_symbol_name(c, var));
}

static bool is_test_bin_op(struct fh_p_expr_bin_op *expr) {
    switch (expr->op) {
        case '>':
        case '<':
        case AST_OP_GE:
        case AST_OP_LE:
        case AST_OP_EQ:
        case AST_OP_NEQ:
            return true;

        default:
            return false;
    }
}

static int compile_postfix_incdec_to_reg(struct fh_compiler *c, struct fh_p_expr_postfix *pf, int dest_reg) {
    struct fh_p_expr *arg = pf->arg;
    struct fh_src_loc loc = arg->loc;

    if (arg->type != EXPR_VAR && arg->type != EXPR_INDEX)
        return fh_compiler_error(c, loc, "postfix ++/-- expects a variable or index");

    int tmp = alloc_reg(c, loc, TMP_VARIABLE);
    if (tmp < 0) return -1;

    // tmp = old
    if (compile_load_lvalue_to_reg(c, arg, tmp) < 0) return -1;

    // result = old
    if (add_instr(c, loc, MAKE_INSTR_AB(OPC_MOV, dest_reg, tmp)) < 0) return -1;

    // tmp = old +/- 1
    enum fh_bc_opcode opc = (pf->op == AST_OP_INC) ? OPC_INC : OPC_DEC;
    if (add_instr(c, loc, MAKE_INSTR_AB(opc, tmp, tmp)) < 0) return -1;

    // store back
    if (compile_store_reg_to_lvalue(c, arg, tmp) < 0) return -1;

    return dest_reg;
}

static int compile_load_lvalue_to_reg(struct fh_compiler *c, struct fh_p_expr *lv, int dst_reg) {
    struct fh_src_loc loc = lv->loc;

    if (lv->type == EXPR_VAR) {
        // local?
        int r = get_var_reg(c, loc, lv->data.var);
        if (r >= 0) {
            return add_instr(c, loc, MAKE_INSTR_AB(OPC_MOV, dst_reg, r));
        }

        // upval?
        int upval;
        if (add_var_upval(c, loc, lv->data.var, &upval) < 0) return -1;
        if (upval >= 0) {
            return add_instr(c, loc, MAKE_INSTR_AB(OPC_GETUPVAL, dst_reg, upval));
        }

        return fh_compiler_error(c, loc, "undeclared variable: '%s'", fh_get_ast_symbol(c->ast, lv->data.var));
    }

    if (lv->type == EXPR_INDEX) {
        int container_rk = compile_expr(c, lv->data.index.container);
        if (container_rk < 0) return -1;

        if (RK_IS_CONST(container_rk)) {
            int tmp = alloc_reg(c, loc, TMP_VARIABLE);
            if (tmp < 0) return -1;
            if (add_instr(c, loc, MAKE_INSTR_AB(OPC_MOV, tmp, container_rk)) < 0) return -1;
            container_rk = tmp;
        }

        int index_rk = compile_expr(c, lv->data.index.index);
        if (index_rk < 0) return -1;

        return add_instr(c, loc, MAKE_INSTR_ABC(OPC_GETEL, dst_reg, container_rk, index_rk));
    }

    return fh_compiler_error(c, loc, "invalid lvalue");
}

static int compile_store_reg_to_lvalue(struct fh_compiler *c, struct fh_p_expr *lv, int src_rk) {
    struct fh_src_loc loc = lv->loc;

    if (lv->type == EXPR_VAR) {
        // local?
        int r = get_var_reg(c, loc, lv->data.var);
        if (r >= 0) {
            return add_instr(c, loc, MAKE_INSTR_AB(OPC_MOV, r, src_rk));
        }

        // upval?
        int upval;
        if (add_var_upval(c, loc, lv->data.var, &upval) < 0) return -1;
        if (upval >= 0) {
            return add_instr(c, loc, MAKE_INSTR_AB(OPC_SETUPVAL, upval, src_rk));
        }

        return fh_compiler_error(c, loc, "undeclared variable: '%s'", fh_get_ast_symbol(c->ast, lv->data.var));
    }

    if (lv->type == EXPR_INDEX) {
        int container_rk = compile_expr(c, lv->data.index.container);
        if (container_rk < 0) return -1;

        if (RK_IS_CONST(container_rk)) {
            int tmp = alloc_reg(c, loc, TMP_VARIABLE);
            if (tmp < 0) return -1;
            if (add_instr(c, loc, MAKE_INSTR_AB(OPC_MOV, tmp, container_rk)) < 0) return -1;
            container_rk = tmp;
        }

        int index_rk = compile_expr(c, lv->data.index.index);
        if (index_rk < 0) return -1;

        // SETEL A=container, B=index, C=value  (matches your VM)
        return add_instr(c, loc, MAKE_INSTR_ABC(OPC_SETEL, container_rk, index_rk, src_rk));
    }

    return fh_compiler_error(c, loc, "invalid lvalue");
}


static int compile_bin_op_to_reg(struct fh_compiler *c, struct fh_src_loc loc, struct fh_p_expr_bin_op *expr,
                                 int dest_reg) {
    if (expr->op == '=') {
        int reg = compile_bin_op(c, loc, expr);
        if (reg < 0 || add_instr(c, loc, MAKE_INSTR_AB(OPC_MOV, dest_reg, reg)) < 0)
            return -1;
        return dest_reg;
    }

    if (is_test_bin_op(expr)) {
        int k_true = add_const_bool(c, loc, true);
        int k_false = add_const_bool(c, loc, false);
        if (k_true < 0 || k_false < 0)
            return -1;
        k_true += MAX_FUNC_REGS + 1;
        k_false += MAX_FUNC_REGS + 1;
        if (add_instr(c, loc, MAKE_INSTR_AB(OPC_MOV, dest_reg, k_true)) < 0)
            return -1;
        if (compile_test_bin_op(c, loc, expr, false) < 0)
            return -1;
        if (add_instr(c, loc, MAKE_INSTR_AB(OPC_MOV, dest_reg, k_false)) < 0)
            return -1;
        return dest_reg;
    }

    if (expr->op == AST_OP_AND || expr->op == AST_OP_OR) {
        if (compile_expr_to_reg(c, expr->left, dest_reg) < 0)
            return -1;
        if (add_instr(c, loc, MAKE_INSTR_AB(OPC_TEST, expr->op == AST_OP_OR, dest_reg)) < 0)
            return -1;
        int jmp_addr = get_cur_pc(c, loc);
        if (add_instr(c, loc, MAKE_INSTR_AS(OPC_JMP, 0, 0)) < 0)
            return -1;
        if (compile_expr_to_reg(c, expr->right, dest_reg) < 0)
            return -1;
        if (set_jmp_target(c, loc, jmp_addr, get_cur_pc(c, loc)) < 0)
            return -1;
        return dest_reg;
    }

    const int left_rk = compile_expr(c, expr->left);
    if (left_rk < 0) {
        return -1;
    }

    const int right_rk = compile_expr(c, expr->right);
    if (right_rk < 0)
        return -1;

    enum fh_bc_opcode opc;
    switch (expr->op) {
        case '+':
            opc = OPC_ADD;
            break;
        case '-':
            opc = OPC_SUB;
            break;
        case '*':
            opc = OPC_MUL;
            break;
        case '/':
            opc = OPC_DIV;
            break;
        case '%':
            opc = OPC_MOD;
            break;
        case '|':
            opc = OPC_BOR;
            break;
        case '&':
            opc = OPC_BAND;
            break;
        case '^':
            opc = OPC_BXOR;
            break;
        case AST_OP_RSH:
            opc = OPC_RSHIFT;
            break;
        case AST_OP_LSH:
            opc = OPC_LSHIFT;
            break;
        default:
            return fh_compiler_error(c, loc, "compilation of operator '%s' is not implemented",
                                     fh_get_op_name(expr->op));
    }
    if (add_instr(c, loc, MAKE_INSTR_ABC(opc, dest_reg, left_rk, right_rk)) < 0)
        return -1;

    return dest_reg;
}

static int compile_bin_op(struct fh_compiler *c, struct fh_src_loc loc, struct fh_p_expr_bin_op *expr) {
    if (expr->op == '=') {
        if (expr->left->type == EXPR_CONST) {
            return fh_compiler_error(c, expr->left->loc, "cannot reassign constant variable");
        }
        if (expr->left->type == EXPR_VAR) {
            // local var
            int left_reg = get_var_reg(c, loc, expr->left->data.var);
            if (left_reg >= 0)
                return compile_expr_to_reg(c, expr->right, left_reg);

            // var local to parent function
            int upval;
            if (add_var_upval(c, loc, expr->left->data.var, &upval) < 0)
                return -1;
            if (upval >= 0) {
                left_reg = alloc_reg(c, loc, TMP_VARIABLE);
                if (left_reg < 0)
                    return -1;
                if (compile_expr_to_reg(c, expr->right, left_reg) < 0)
                    return -1;
                if (add_instr(c, loc, MAKE_INSTR_AB(OPC_SETUPVAL, upval, left_reg)) < 0)
                    return -1;

                return left_reg;
            }

            // no such variable
            return fh_compiler_error(c, expr->left->loc, "undeclared variable: '%s'",
                                     fh_get_ast_symbol(c->ast, expr->left->data.var));
        }

        if (expr->left->type == EXPR_INDEX) {
            int container_rk = compile_expr(c, expr->left->data.index.container);
            if (container_rk < 0)
                return -1;
            if (RK_IS_CONST(container_rk)) {
                // container must be a register (RA)
                int tmp_reg = alloc_reg(c, loc, TMP_VARIABLE);
                if (add_instr(c, loc, MAKE_INSTR_AB(OPC_MOV, tmp_reg, container_rk)) < 0)
                    return -1;
                container_rk = tmp_reg;
            }

            int index_rk = compile_expr(c, expr->left->data.index.index);
            if (index_rk < 0)
                return -1;
            int val_rk = compile_expr(c, expr->right);
            if (val_rk < 0)
                return -1;

            if (add_instr(c, loc, MAKE_INSTR_ABC(OPC_SETEL, container_rk, index_rk, val_rk)) < 0)
                return -1;
            return val_rk;
        }

        return fh_compiler_error(c, loc, "invalid assignment");
    }

    int dest_reg = alloc_reg(c, loc, TMP_VARIABLE);
    if (dest_reg < 0)
        return -1;
    return compile_bin_op_to_reg(c, loc, expr, dest_reg);
}

static int compile_un_op_to_reg(struct fh_compiler *c, struct fh_src_loc loc, struct fh_p_expr_un_op *expr,
                                int dest_reg) {
    int arg_rk = compile_expr(c, expr->arg);
    if (arg_rk < 0) {
        return -1;
    }

    enum fh_bc_opcode opc;
    switch (expr->op) {
        case '~':
            opc = OPC_BNOT;
            break;
        case '!':
            opc = OPC_NOT;
            break;
        case AST_OP_UNM:
            opc = OPC_NEG;
            break;
        case AST_OP_INC:
        case AST_OP_DEC: {
            if (expr->arg->type != EXPR_VAR && expr->arg->type != EXPR_INDEX)
                return fh_compiler_error(c, loc, "%s operator can only be applied to variables or indexes",
                                         expr->op == AST_OP_INC ? "increment" : "decrement");

            int tmp = alloc_reg(c, loc, TMP_VARIABLE);
            if (tmp < 0) return -1;

            if (compile_load_lvalue_to_reg(c, expr->arg, tmp) < 0) return -1;

            enum fh_bc_opcode opc = (expr->op == AST_OP_INC) ? OPC_INC : OPC_DEC;
            if (add_instr(c, loc, MAKE_INSTR_AB(opc, tmp, tmp)) < 0) return -1;

            if (compile_store_reg_to_lvalue(c, expr->arg, tmp) < 0) return -1;

            if (add_instr(c, loc, MAKE_INSTR_AB(OPC_MOV, dest_reg, tmp)) < 0) return -1;
            return dest_reg;
        }
        default:
            return fh_compiler_error(c, loc, "unknown operator '%s'", fh_get_op_name(expr->op));
    }
    if (add_instr(c, loc, MAKE_INSTR_AB(opc, dest_reg, arg_rk)) < 0)
        return -1;
    return dest_reg;
}

static int compile_un_op(struct fh_compiler *c, struct fh_src_loc loc, struct fh_p_expr_un_op *expr) {
    int dest_reg = alloc_reg(c, loc, TMP_VARIABLE);
    if (dest_reg < 0)
        return -1;
    return compile_un_op_to_reg(c, loc, expr, dest_reg);
}

static int compile_func_call(struct fh_compiler *c, struct fh_src_loc loc, struct fh_p_expr_func_call *expr) {
    int n_args = fh_expr_list_size(expr->arg_list);
    int func_reg = alloc_n_regs(c, loc, n_args + 1);
    if (func_reg < 0 || compile_expr_to_reg(c, expr->func, func_reg) < 0)
        return -1;
    int reg = func_reg + 1;
    for (struct fh_p_expr *e = expr->arg_list; e != NULL; e = e->next) {
        if (compile_expr_to_reg(c, e, reg++) < 0)
            return -1;
    }

    if (add_instr(c, loc, MAKE_INSTR_AB(OPC_CALL, func_reg, n_args)) < 0)
        return -1;
    c->last_func_call = loc;

    for (int i = 1; i < n_args + 1; i++)
        free_reg(c, loc, func_reg + i);

    return func_reg;
}

static int compile_index_to_reg(struct fh_compiler *c, struct fh_src_loc loc, struct fh_p_expr_index *expr,
                                int dest_reg) {
    int container_rk = compile_expr(c, expr->container);
    if (container_rk < 0) {
        return -1;
    }
    int index_rk = compile_expr(c, expr->index);
    if (index_rk < 0)
        return -1;

    if (add_instr(c, loc, MAKE_INSTR_ABC(OPC_GETEL, dest_reg, container_rk, index_rk)) < 0)
        return -1;
    return dest_reg;
}

static int compile_index(struct fh_compiler *c, struct fh_src_loc loc, struct fh_p_expr_index *expr) {
    int dest_reg = alloc_reg(c, loc, TMP_VARIABLE);
    if (dest_reg < 0)
        return -1;
    return compile_index_to_reg(c, loc, expr, dest_reg);
}

static int compile_array_lit(struct fh_compiler *c, struct fh_src_loc loc, struct fh_p_expr_array_lit *expr) {
    int n_elems = fh_expr_list_size(expr->elem_list);
    int array_reg = alloc_n_regs(c, loc, n_elems + 1);
    if (array_reg < 0)
        return -1;
    int reg = array_reg + 1;
    for (struct fh_p_expr *e = expr->elem_list; e != NULL; e = e->next) {
        if (compile_expr_to_reg(c, e, reg++) < 0)
            return -1;
    }

    if (add_instr(c, loc, MAKE_INSTR_AU(OPC_NEWARRAY, array_reg, n_elems)) < 0)
        return -1;

    for (int i = 1; i < n_elems + 1; i++)
        free_reg(c, loc, array_reg + i);

    return array_reg;
}

static int compile_map_lit(struct fh_compiler *c, struct fh_src_loc loc, struct fh_p_expr_map_lit *expr) {
    int n_elems = fh_expr_list_size(expr->elem_list);
    int map_reg = alloc_n_regs(c, loc, n_elems + 1);
    if (map_reg < 0)
        return -1;
    int reg = map_reg + 1;
    for (struct fh_p_expr *e = expr->elem_list; e != NULL; e = e->next) {
        if ((reg - map_reg - 1) % 2 == 0 && e->type == EXPR_NULL)
            return fh_compiler_error(c, loc, "map key can't be null");
        if (compile_expr_to_reg(c, e, reg++) < 0)
            return -1;
    }

    if (add_instr(c, loc, MAKE_INSTR_AU(OPC_NEWMAP, map_reg, n_elems)) < 0)
        return -1;

    for (int i = 1; i < n_elems + 1; i++)
        free_reg(c, loc, map_reg + i);

    return map_reg;
}

static int get_func_inner_func_reg(struct func_info *fi, struct fh_func_def *func_def) {
    /*
        Rules for not matching:
          - Discard any return types which have value (ex: return a, return 'foo' etc)
          - If the number of constants, parameters, registers or upvalues is not the same, discard
          - If one has a name and the other does not then discard
    */
    enum fh_bc_opcode ret_opc = GET_INSTR_RA(func_def->code[func_def->code_size-1]);
    if (ret_opc != 0)
        return -1;
    for (int i = value_stack_size(&fi->consts) - 1; i >= 0; i--) {
        struct fh_value *vi = value_stack_item(&fi->consts, i);
        if (vi->type == FH_VAL_FUNC_DEF) {
            struct fh_func_def *def = (struct fh_func_def *) vi->data.obj;
            ret_opc = GET_INSTR_RA(def->code[def->code_size-1]);
            if ((def->name != NULL && func_def->name == NULL) ||
                (def->name == NULL && func_def->name != NULL))
                continue;
            if (ret_opc != 0 ||
                (def->n_regs != func_def->n_regs) ||
                (def->n_consts != func_def->n_consts) ||
                (def->n_params != func_def->n_params) ||
                (def->n_upvals != func_def->n_upvals) ||
                (def->code_size != func_def->code_size))
                continue;
            // Check for same op codes
            bool same_opcode = true;
            for (int j = 0; j < def->code_size; j++) {
                if (def->code[j] != func_def->code[j]) {
                    same_opcode = false;
                    break;
                }
            }
            // Check for the same constants
            if (same_opcode) {
                bool same_consts = true;
                for (int j = 0; j < def->n_consts; j++) {
                    if (!fh_vals_are_equal(&def->consts[j], &func_def->consts[j])) {
                        same_consts = false;
                        break;
                    }
                }
                if (same_consts)
                    return i;
            }
        }
    }
    return -1;
}

static int compile_inner_func_to_reg_special(struct fh_compiler *c, struct fh_src_loc loc, struct fh_p_expr_func *expr,
                                             int dest_reg, const char *name) {
    struct func_info *fi = get_cur_func_info(c, loc);
    if (!fi)
        return -1;

    struct fh_func_def *func_def = new_func_def(c, loc, name, expr->n_params);
    if (!func_def || compile_func(c, loc, expr, func_def, fi) < 0)
        return -1;

    // Look for an already cached inner function
    int k = get_func_inner_func_reg(fi, func_def);
    if (k >= 0) {
        k += MAX_FUNC_REGS + 1;
        if (add_instr(c, loc, MAKE_INSTR_AB(OPC_CLOSURE, dest_reg, k)) < 0)
            return -1;
        return dest_reg;
    }

    // Nothing found, create the inner function
    k = add_const_func_def(c, loc, func_def);
    if (k >= 0)
        k += MAX_FUNC_REGS + 1;
    if (add_instr(c, loc, MAKE_INSTR_AB(OPC_CLOSURE, dest_reg, k)) < 0)
        return -1;

    return dest_reg;
}


static int compile_inner_func_to_reg(struct fh_compiler *c, struct fh_src_loc loc, struct fh_p_expr_func *expr,
                                     int dest_reg) {
    return compile_inner_func_to_reg_special(c, loc, expr, dest_reg, NULL);
}

static int compile_inner_func(struct fh_compiler *c, struct fh_src_loc loc, struct fh_p_expr_func *expr) {
    int dest_reg = alloc_reg(c, loc, TMP_VARIABLE);
    if (dest_reg < 0)
        return -1;
    return compile_inner_func_to_reg(c, loc, expr, dest_reg);
}

static int compile_expr(struct fh_compiler *c, struct fh_p_expr *expr) {
    switch (expr->type) {
        case EXPR_CONST:
        case EXPR_VAR: return compile_var(c, expr->loc, expr->data.var);
        case EXPR_BIN_OP: return compile_bin_op(c, expr->loc, &expr->data.bin_op);
        case EXPR_UN_OP: return compile_un_op(c, expr->loc, &expr->data.un_op);
        case EXPR_FUNC_CALL: return compile_func_call(c, expr->loc, &expr->data.func_call);
        case EXPR_ARRAY_LIT: return compile_array_lit(c, expr->loc, &expr->data.array_lit);
        case EXPR_MAP_LIT: return compile_map_lit(c, expr->loc, &expr->data.map_lit);
        case EXPR_INDEX: return compile_index(c, expr->loc, &expr->data.index);
        case EXPR_FUNC: return compile_inner_func(c, expr->loc, &expr->data.func);
        case EXPR_POST_INC:
        case EXPR_POST_DEC: {
            int dest_reg = alloc_reg(c, expr->loc, TMP_VARIABLE);
            if (dest_reg < 0) return -1;
            return compile_postfix_incdec_to_reg(c, &expr->data.postfix, dest_reg);
        }

        case EXPR_NULL: {
            int k = add_const_null(c, expr->loc);
            if (k >= 0)
                k += MAX_FUNC_REGS + 1;
            return k;
        }

        case EXPR_BOOL: {
            int k = add_const_bool(c, expr->loc, expr->data.b);
            if (k >= 0)
                k += MAX_FUNC_REGS + 1;
            return k;
        }

        case EXPR_FLOAT: {
            int k = add_const_number(c, expr->loc, expr->data.num);
            if (k >= 0)
                k += MAX_FUNC_REGS + 1;
            return k;
        }

        case EXPR_STRING: {
            int k = add_const_string(c, expr->loc, expr->data.str);
            if (k >= 0)
                k += MAX_FUNC_REGS + 1;
            return k;
        }

        case EXPR_NONE:
            if (add_instr(c, expr->loc, MAKE_INSTR_AB(OPC_MOV, 0, 0)) < 0) // NOP
                return -1;
            return 0;
    }

    return fh_compiler_error(c, expr->loc, "INTERNAL COMPILER ERROR: invalid expression type %d", expr->type);
}

static int compile_expr_to_reg_special(struct fh_compiler *c, struct fh_p_expr *expr, int dest_reg, const char *name) {
    switch (expr->type) {
        case EXPR_BIN_OP: return compile_bin_op_to_reg(c, expr->loc, &expr->data.bin_op, dest_reg);
        case EXPR_UN_OP: return compile_un_op_to_reg(c, expr->loc, &expr->data.un_op, dest_reg);
        case EXPR_INDEX: return compile_index_to_reg(c, expr->loc, &expr->data.index, dest_reg);
        case EXPR_FUNC: return compile_inner_func_to_reg_special(c, expr->loc, &expr->data.func, dest_reg, name);
        default: break;
    }

    int tmp_rk = compile_expr(c, expr);
    if (tmp_rk < 0)
        return -1;
    if (tmp_rk <= MAX_FUNC_REGS) {
        if (add_instr(c, expr->loc, MAKE_INSTR_AB(OPC_MOV, dest_reg, tmp_rk)) < 0)
            return -1;
    } else {
        if (add_instr(c, expr->loc, MAKE_INSTR_AB(OPC_LDC, dest_reg, tmp_rk - MAX_FUNC_REGS - 1)) < 0)
            return -1;
    }
    return dest_reg;
}

static int compile_expr_to_reg(struct fh_compiler *c, struct fh_p_expr *expr, int dest_reg) {
    switch (expr->type) {
        case EXPR_BIN_OP: return compile_bin_op_to_reg(c, expr->loc, &expr->data.bin_op, dest_reg);
        case EXPR_UN_OP: return compile_un_op_to_reg(c, expr->loc, &expr->data.un_op, dest_reg);
        case EXPR_INDEX: return compile_index_to_reg(c, expr->loc, &expr->data.index, dest_reg);
        case EXPR_FUNC: return compile_inner_func_to_reg(c, expr->loc, &expr->data.func, dest_reg);
        case EXPR_POST_INC:
        case EXPR_POST_DEC:
            return compile_postfix_incdec_to_reg(c, &expr->data.postfix, dest_reg);
        default: break;
    }

    int tmp_rk = compile_expr(c, expr);
    if (tmp_rk < 0)
        return -1;
    if (tmp_rk <= MAX_FUNC_REGS) {
        if (add_instr(c, expr->loc, MAKE_INSTR_AB(OPC_MOV, dest_reg, tmp_rk)) < 0)
            return -1;
    } else {
        if (add_instr(c, expr->loc, MAKE_INSTR_AB(OPC_LDC, dest_reg, tmp_rk - MAX_FUNC_REGS - 1)) < 0)
            return -1;
    }
    return dest_reg;
}

static int compile_var_decl(struct fh_compiler *c, struct fh_src_loc loc, struct fh_p_stmt_decl *decl) {
    int reg = alloc_reg(c, loc, TMP_VARIABLE);
    if (reg < 0)
        return -1;
    if (decl->val) {
        const char *name = get_ast_symbol_name(c, decl->var);
        if (compile_expr_to_reg_special(c, decl->val, reg, name) < 0)
            return -1;
    } else {
        if (add_instr(c, loc, MAKE_INSTR_A(OPC_LDNULL, reg)) < 0)
            return -1;
    }
    if (set_reg_var(c, loc, reg, decl->var) < 0)
        return -1;
    free_tmp_regs(c, loc);
    return 0;
}

static int compile_const_decl(struct fh_compiler *c, struct fh_src_loc loc, struct fh_p_stmt_decl *decl) {
    int reg = alloc_reg(c, loc, TMP_VARIABLE);
    if (reg < 0)
        return -1;
    if (decl->val) {
        if (compile_expr_to_reg(c, decl->val, reg) < 0)
            return -1;
    } else {
        fh_compiler_error(c, loc, "constant variable cannot be set to null");
        return -1;
    }
    if (set_reg_var(c, loc, reg, decl->var) < 0)
        return -1;
    free_tmp_regs(c, loc);
    return 0;
}

static int get_opcode_for_test(struct fh_compiler *c, struct fh_src_loc loc, uint32_t op, bool *invert) {
    switch (op) {
        case '<': return OPC_CMP_LT;
        case '>': return OPC_CMP_GT;
        case AST_OP_LE: return OPC_CMP_LE;
        case AST_OP_GE: return OPC_CMP_GE;
        case AST_OP_EQ: *invert = false;
            return OPC_CMP_EQ;
        case AST_OP_NEQ: *invert = true;
            return OPC_CMP_EQ;

        default:
            return fh_compiler_error(c, loc, "invalid operator for test: '%u", op);
    }
}

static int compile_test_bin_op(struct fh_compiler *c, struct fh_src_loc loc, struct fh_p_expr_bin_op *bin_op,
                               bool invert_test) {
    int left_rk = compile_expr(c, bin_op->left);
    if (left_rk < 0)
        return -1;
    int right_rk = compile_expr(c, bin_op->right);
    if (right_rk < 0)
        return -1;
    bool invert = false;
    int opcode = get_opcode_for_test(c, loc, bin_op->op, &invert);
    if (opcode < 0)
        return -1;
    if (add_instr(c, loc, MAKE_INSTR_ABC(opcode, invert_test ^ invert, left_rk, right_rk)) < 0)
        return -1;
    return 0;
}

static int compile_test(struct fh_compiler *c, struct fh_p_expr *test, bool invert_test) {
    if (test->type == EXPR_UN_OP && test->data.un_op.op == '!') {
        invert_test = !invert_test;
        test = test->data.un_op.arg;
    }

    if (test->type == EXPR_BIN_OP && is_test_bin_op(&test->data.bin_op))
        return compile_test_bin_op(c, test->loc, &test->data.bin_op, invert_test);

    int rk;
    if (test->type == EXPR_FLOAT) {
        rk = add_const_number(c, test->loc, test->data.num);
        if (rk >= 0) rk += MAX_FUNC_REGS + 1;
    } else {
        rk = compile_expr(c, test);
    }
    if (rk < 0)
        return -1;
    if (add_instr(c, test->loc, MAKE_INSTR_AB(OPC_TEST, invert_test, rk)) < 0)
        return -1;
    return 0;
}

static int compile_if(struct fh_compiler *c, struct fh_src_loc loc, struct fh_p_stmt_if *stmt_if) {
    if (compile_test(c, stmt_if->test, false) < 0)
        return -1;
    free_tmp_regs(c, loc);

    /* In case the test failed jump to else if or else */
    int addr_jmp_if_false = get_cur_pc(c, loc);
    if (add_instr(c, loc, MAKE_INSTR_AS(OPC_JMP, 0, 0)) < 0)
        return -1;

    /* Compile the true statement */
    if (compile_stmt(c, stmt_if->true_stmt) < 0)
        return -1;

    /* If the true statement has been executed jump to end of if*/
    int addr_jmp_if_end = get_cur_pc(c, loc);
    if (add_instr(c, loc, MAKE_INSTR_AS(OPC_JMP, 0, 0)) < 0)
        return -1;

    /* Compile "else if" and "else" */
    if (stmt_if->num_elif_stmts > 0) {
        if (stmt_if->num_elif_stmts >= FH_MAX_NESTED_ELIF) {
            return fh_compiler_error(c, loc, "Cannot compile more than 32 elif statements");
        }

        /* Jump to "else if" if "if" returns false */
        if (set_jmp_target(c, loc, addr_jmp_if_false, get_cur_pc(c, loc)) < 0)
            return -1;

        int addr_jmp_elif_end[stmt_if->num_elif_stmts];
        size_t elif_curr = 0;
        while (elif_curr < stmt_if->num_elif_stmts) {
            struct fh_p_stmt_elif stmt_elif = stmt_if->elif_stmt[elif_curr]->data.stmt_elif;
            if (compile_test(c, stmt_elif.test, false) < 0)
                return -1;
            free_tmp_regs(c, loc);

            //printf("Total elifs statements: %zu", stmt_if->num_elif_stmts);

            int addr_jmp_elif_false = get_cur_pc(c, loc);
            if (add_instr(c, loc, MAKE_INSTR_AS(OPC_JMP, 0, 0)) < 0)
                return -1;

            if (compile_stmt(c, stmt_elif.stmt) < 0)
                return -1;

            addr_jmp_elif_end[elif_curr] = get_cur_pc(c, loc);
            if (add_instr(c, loc, MAKE_INSTR_AS(OPC_JMP, 0, 0)) < 0)
                return -1;

            if (set_jmp_target(c, loc, addr_jmp_elif_false, get_cur_pc(c, loc)) < 0)
                return -1;

            elif_curr++;
        }

        /* Jump to "else" or exit when "if" returns true */
        if (set_jmp_target(c, loc, addr_jmp_if_end, get_cur_pc(c, loc)) < 0)
            return -1;

        /* Check if we have to parse an else statement */
        if (stmt_if->false_stmt) {
            if (compile_stmt(c, stmt_if->false_stmt) < 0)
                return -1;

            if (set_jmp_target(c, loc, addr_jmp_if_end, get_cur_pc(c, loc)) < 0)
                return -1;

            size_t i = 0;
            while (i < elif_curr) {
                if (set_jmp_target(c, loc, addr_jmp_elif_end[i], get_cur_pc(c, loc)) < 0)
                    return -1;
                i++;
            }
        }
    } else {
        /* When we don't have an "else if" and the "if" returns false jump to the end of the block which
         * may contain an "else" or not */
        if (set_jmp_target(c, loc, addr_jmp_if_false, get_cur_pc(c, loc)) < 0)
            return -1;

        /* Check to see if we have "else" statement and parse it */
        if (stmt_if->false_stmt) {
            if (set_jmp_target(c, loc, addr_jmp_if_false, get_cur_pc(c, loc)) < 0)
                return -1;

            if (compile_stmt(c, stmt_if->false_stmt) < 0)
                return -1;

            if (set_jmp_target(c, loc, addr_jmp_if_end, get_cur_pc(c, loc)) < 0)
                return -1;
        }
    }
    return 0;
}

static int compile_while(struct fh_compiler *c, struct fh_src_loc loc, struct fh_p_stmt_while *stmt_while) {
    struct func_info *fi = get_cur_func_info(c, loc);
    if (!fi)
        return -1;

    int parent_num_break_addrs = int_stack_size(&fi->break_addrs);
    int parent_num_continue_addrs = int_stack_size(&fi->continue_addrs);

    int addr_jmp_to_end = -1;
    int start_addr = get_cur_pc(c, loc);
    if (!(stmt_while->test->type == EXPR_BOOL && stmt_while->test->data.b)) {
        if (compile_test(c, stmt_while->test, false) < 0)
            return -1;
        free_tmp_regs(c, loc);

        // jmp to_end
        addr_jmp_to_end = get_cur_pc(c, loc);
        if (add_instr(c, loc, MAKE_INSTR_AS(OPC_JMP, 0, 0)) < 0)
            return -1;
    }

    // statement
    switch (stmt_while->stmt->type) {
        case STMT_VAR_DECL:
        case STMT_CONST_DECL: return fh_compiler_error(c, stmt_while->stmt->loc,
                                                       "variable declaration must be inside block");
        case STMT_BREAK: return fh_compiler_error(c, stmt_while->stmt->loc, "break must be inside while block");
        case STMT_CONTINUE: return fh_compiler_error(c, stmt_while->stmt->loc, "continue must be inside while block");

        case STMT_BLOCK:
            if (compile_block(c, stmt_while->stmt->loc, &stmt_while->stmt->data.block, COMP_BLOCK_WHILE,
                              start_addr) < 0)
                return -1;
            break;

        default:
            if (compile_stmt(c, stmt_while->stmt) < 0)
                return -1;
            if (add_instr(c, loc, MAKE_INSTR_AS(OPC_JMP, 0, start_addr - get_cur_pc(c, loc) - 1)) < 0)
                return -1;
    }

    // to_end:
    int addr_end = get_cur_pc(c, loc);
    if (addr_jmp_to_end >= 0) {
        if (set_jmp_target(c, loc, addr_jmp_to_end, addr_end) < 0)
            return -1;
    }

    while (int_stack_size(&fi->break_addrs) > parent_num_break_addrs) {
        int break_addr;
        if (int_stack_pop(&fi->break_addrs, &break_addr) < 0)
            return fh_compiler_error(c, loc, "INTERNAL COMPILER ERROR: can't pop break address");
        if (set_jmp_target(c, loc, break_addr, addr_end) < 0)
            return -1;
    }
    while (int_stack_size(&fi->continue_addrs) > parent_num_continue_addrs) {
        int continue_addr;
        if (int_stack_pop(&fi->continue_addrs, &continue_addr) < 0)
            return fh_compiler_error(c, loc, "INTERNAL COMPILER ERROR: can't pop continue address");
        if (set_jmp_target(c, loc, continue_addr, addr_end - 1) < 0)
            return -1;
    }
    return 0;
}

static int compile_repeat(struct fh_compiler *c, struct fh_src_loc loc, struct fh_p_stmt_while *stmt_while) {
    struct func_info *fi = get_cur_func_info(c, loc);
    if (!fi)
        return -1;

    int parent_num_break_addrs = int_stack_size(&fi->break_addrs);
    int parent_num_continue_addrs = int_stack_size(&fi->continue_addrs);

    int start_addr = get_cur_pc(c, loc);

    // statement
    switch (stmt_while->stmt->type) {
        case STMT_VAR_DECL:
        case STMT_CONST_DECL:
            return fh_compiler_error(c, stmt_while->stmt->loc, "variable declaration must be inside block");
        case STMT_BREAK:
            return fh_compiler_error(c, stmt_while->stmt->loc, "break must be inside while block");
        case STMT_CONTINUE:
            return fh_compiler_error(c, stmt_while->stmt->loc, "continue must be inside while block");

        case STMT_BLOCK:
            if (compile_block(c, stmt_while->stmt->loc, &stmt_while->stmt->data.block, COMP_BLOCK_FOR, start_addr) < 0)
                return -1;
            break;
        default:
            if (compile_stmt(c, stmt_while->stmt) < 0)
                return -1;
    }

    if (compile_test(c, stmt_while->test, true) < 0)
        return -1;
    free_tmp_regs(c, loc);

    // jmp to start
    if (add_instr(c, stmt_while->test->loc, MAKE_INSTR_AS(OPC_JMP, 0, start_addr - get_cur_pc(c, loc) - 1)) < 0)
        return -1;

    // the end
    int addr_end = get_cur_pc(c, loc);

    while (int_stack_size(&fi->break_addrs) > parent_num_break_addrs) {
        int break_addr;
        if (int_stack_pop(&fi->break_addrs, &break_addr) < 0)
            return fh_compiler_error(c, loc, "INTERNAL COMPILER ERROR: can't pop break address");
        if (set_jmp_target(c, loc, break_addr, addr_end) < 0)
            return -1;
    }
    while (int_stack_size(&fi->continue_addrs) > parent_num_continue_addrs) {
        int continue_addr;
        if (int_stack_pop(&fi->continue_addrs, &continue_addr) < 0)
            return fh_compiler_error(c, loc, "INTERNAL COMPILER ERROR: can't pop continue address");
        if (set_jmp_target(c, loc, continue_addr, start_addr) < 0)
            return -1;
    }
    return 0;
}


static int compile_for(struct fh_compiler *c, struct fh_src_loc loc, struct fh_p_stmt_for *stmt_for) {
    struct func_info *fi = get_cur_func_info(c, loc);
    if (!fi)
        return -1;

    int parent_num_break_addrs = int_stack_size(&fi->break_addrs);
    int parent_num_continue_addrs = int_stack_size(&fi->continue_addrs);

    if (compile_stmt(c, stmt_for->init) < 0) {
        fh_compiler_error(c, stmt_for->stmt->loc, "failed to compile init section in for-loop");
        return -1;
    }

    int addr_jmp_to_end = -1;
    int start_addr = get_cur_pc(c, loc);
    if (!(stmt_for->test->type == EXPR_BOOL && stmt_for->test->data.b)) {
        if (compile_test(c, stmt_for->test, false) < 0)
            return -1;
        free_tmp_regs(c, loc);

        // jmp to_end
        addr_jmp_to_end = get_cur_pc(c, loc);
        if (add_instr(c, loc, MAKE_INSTR_AS(OPC_JMP, 0, 0)) < 0)
            return -1;
    }

    // statement
    switch (stmt_for->stmt->type) {
        case STMT_VAR_DECL:
        case STMT_CONST_DECL:
            return fh_compiler_error(c, stmt_for->stmt->loc, "variable declaration must be inside block");
        case STMT_BREAK:
            return fh_compiler_error(c, stmt_for->stmt->loc, "break must be inside while block");
        case STMT_CONTINUE:
            return fh_compiler_error(c, stmt_for->stmt->loc, "continue must be inside while block");

        case STMT_BLOCK: {
            if (compile_block(c, stmt_for->stmt->loc, &stmt_for->stmt->data.block, COMP_BLOCK_FOR, start_addr) < 0)
                return -1;

            if (compile_expr(c, stmt_for->increment) < 0) {
                fh_compiler_error(c, stmt_for->stmt->loc, "failed to compile increment section in for-loop");
                return -1;
            }

            if (add_instr(c, loc, MAKE_INSTR_AS(OPC_JMP, 0, start_addr - get_cur_pc(c, loc) - 1)) < 0)
                return -1;
            break;
        }

        default:
            if (compile_stmt(c, stmt_for->stmt) < 0)
                return -1;

            if (compile_expr(c, stmt_for->increment) < 0) {
                fh_compiler_error(c, stmt_for->stmt->loc, "failed to compile increment section in for-loop");
                return -1;
            }
            if (add_instr(c, loc, MAKE_INSTR_AS(OPC_JMP, 0, start_addr - get_cur_pc(c, loc) - 1)) < 0)
                return -1;
    }

    // to_end:
    int addr_end = get_cur_pc(c, loc);
    if (addr_jmp_to_end >= 0) {
        if (set_jmp_target(c, loc, addr_jmp_to_end, addr_end) < 0)
            return -1;
    }

    while (int_stack_size(&fi->break_addrs) > parent_num_break_addrs) {
        int break_addr;
        if (int_stack_pop(&fi->break_addrs, &break_addr) < 0)
            return fh_compiler_error(c, loc, "INTERNAL COMPILER ERROR: can't pop break address");
        if (set_jmp_target(c, loc, break_addr, addr_end) < 0)
            return -1;
    }
    while (int_stack_size(&fi->continue_addrs) > parent_num_continue_addrs) {
        int continue_addr;
        if (int_stack_pop(&fi->continue_addrs, &continue_addr) < 0)
            return fh_compiler_error(c, loc, "INTERNAL COMPILER ERROR: can't pop continue address");
        if (set_jmp_target(c, loc, continue_addr, addr_end - 2) < 0)
            return -1;
    }
    return 0;
}

static int compile_break(struct fh_compiler *c, struct fh_src_loc loc) {
    struct func_info *fi = get_cur_func_info(c, loc);
    if (!fi)
        return -1;
    struct block_info *bi = get_cur_block_info(c, loc, COMP_BLOCK_WHILE);
    if (!bi) {
        bi = get_cur_block_info(c, loc, COMP_BLOCK_FOR);
        if (!bi)
            return fh_compiler_error(c, loc, "break must be inside while or for");
    }
    int num_open_upvals = get_num_open_upvals(c, loc, bi->parent_num_regs);
    int break_addr = get_cur_pc(c, loc);
    if (!int_stack_push(&fi->break_addrs, &break_addr))
        return fh_compiler_error(c, loc, "out of memory");
    if (add_instr(c, loc, MAKE_INSTR_AS(OPC_JMP, num_open_upvals, 0)) < 0)
        return -1;
    return 0;
}

static int compile_continue(struct fh_compiler *c, struct fh_src_loc loc) {
    struct func_info *fi = get_cur_func_info(c, loc);
    if (!fi)
        return -1;
    /*
     * This keyword will behave differently when
     * it's inside a while compared to a for loop.
     */
    struct block_info *bi = get_cur_block_info(c, loc, COMP_BLOCK_WHILE);
    if (!bi) {
        bi = get_cur_block_info(c, loc, COMP_BLOCK_FOR);
        if (!bi)
            return fh_compiler_error(c, loc, "continue must be inside while or for");
    }
    int num_open_upvals = get_num_open_upvals(c, loc, bi->parent_num_regs);
    int continue_addr = get_cur_pc(c, loc);
    if (!int_stack_push(&fi->continue_addrs, &continue_addr))
        return fh_compiler_error(c, loc, "out of memory");

    if (add_instr(c, loc, MAKE_INSTR_AS(OPC_JMP, num_open_upvals, 0)) < 0)
        return -1;
    return 0;
}

static int compile_return(struct fh_compiler *c, struct fh_src_loc loc, struct fh_p_stmt_return *ret) {
    if (ret->val) {
        int tmp_rk = compile_expr(c, ret->val);
        if (tmp_rk < 0)
            return -1;
        free_tmp_regs(c, loc);
        return add_instr(c, loc, MAKE_INSTR_AB(OPC_RET, 1, tmp_rk));
    }
    return add_instr(c, loc, MAKE_INSTR_AB(OPC_RET, 0, 0));
}

static int compile_stmt(struct fh_compiler *c, struct fh_p_stmt *stmt) {
    switch (stmt->type) {
        case STMT_NONE:
        case STMT_EMPTY:
            return 0;

        case STMT_EXPR:
            if (compile_expr(c, stmt->data.expr) < 0)
                return -1;
            free_tmp_regs(c, stmt->loc);
            return 0;

        case STMT_VAR_DECL:
            return compile_var_decl(c, stmt->loc, &stmt->data.decl);
        case STMT_CONST_DECL:
            return compile_const_decl(c, stmt->loc, &stmt->data.decl);
        case STMT_BLOCK:
            return compile_block(c, stmt->loc, &stmt->data.block, COMP_BLOCK_PLAIN, -1);
        case STMT_RETURN:
            return compile_return(c, stmt->loc, &stmt->data.ret);
        case STMT_IF:
            return compile_if(c, stmt->loc, &stmt->data.stmt_if);
        case STMT_ELIF:
            return -1;
        case STMT_WHILE:
            return compile_while(c, stmt->loc, &stmt->data.stmt_while);
        case STMT_REPEAT:
            return compile_repeat(c, stmt->loc, &stmt->data.stmt_while);
        case STMT_FOR:
            return compile_for(c, stmt->loc, &stmt->data.stmt_for);
        case STMT_BREAK:
            return compile_break(c, stmt->loc);
        case STMT_CONTINUE:
            return compile_continue(c, stmt->loc);
    }

    return fh_compiler_error(c, stmt->loc, "invalid statement node type: %d", stmt->type);
}

static int compile_block(struct fh_compiler *c, struct fh_src_loc loc,
                         struct fh_p_stmt_block *block, enum compiler_block_type block_type,
                         int32_t block_start_addr) {
    struct func_info *fi = get_cur_func_info(c, loc);
    if (!fi)
        return -1;

    struct block_info *bi = new_block_info(fi);
    if (!bi)
        return fh_compiler_error(c, loc, "out of memory");

    bi->type = block_type;
    bi->start_addr = block_start_addr;
    bi->parent_num_regs = get_top_var_reg(c, loc) + 1;

    for (int i = 0; i < block->stmt_vector.length; i++) {
        struct fh_p_stmt *s = block->stmt_vector.data[i];
        if (compile_stmt(c, s) < 0)
            return -1;
    }

    int num_open_upvals = get_num_open_upvals(c, loc, bi->parent_num_regs);
    switch (bi->type) {
        case COMP_BLOCK_WHILE:
            if (add_instr(c, loc, MAKE_INSTR_AS(OPC_JMP, num_open_upvals, bi->start_addr - get_cur_pc(c, loc) - 1)) < 0)
                return -1;
            break;
        case COMP_BLOCK_FOR:
        case COMP_BLOCK_FUNC:
            break;

        case COMP_BLOCK_PLAIN:
            if (num_open_upvals > 0) {
                if (add_instr(c, loc, MAKE_INSTR_AS(OPC_JMP, num_open_upvals, 0)) < 0)
                    return -1;
            }
            break;
    }
    free_var_regs(c, loc, bi->parent_num_regs);
    return 0;
}

static int compile_func(struct fh_compiler *c, struct fh_src_loc loc,
                        struct fh_p_expr_func *func, struct fh_func_def *func_def,
                        struct func_info *parent) {
    struct func_info *fi = new_func_info(c, loc, parent);
    if (!fi) {
        fh_compiler_error(c, loc, "out of memory");
        goto err;
    }

    for (int i = 0; i < func_def->n_params; i++) {
        if (alloc_reg(c, loc, func->params[i]) < 0)
            goto err;
    }

    if (compile_block(c, loc, &func->body, COMP_BLOCK_FUNC, -1) < 0)
        goto err;

    struct fh_p_stmt *last_stmt = func->body.stmt_vector.length > 0
                                      ? func->body.stmt_vector.data[func->body.stmt_vector.length - 1]
                                      : NULL;

    if (!last_stmt || last_stmt->type != STMT_RETURN) {
        if (add_instr(c, loc, MAKE_INSTR_AB(OPC_RET, 0, 0)) < 0)
            goto err;
    }

    if (code_stack_shrink_to_fit(&fi->code) < 0
        || value_stack_shrink_to_fit(&fi->consts) < 0
        || fh_buf_shrink_to_fit(&fi->code_src_loc) < 0) {
        fh_compiler_error(c, loc, "out of memory");
        goto err;
    }

    func_def->n_regs = fi->num_regs;

    func_def->code_size = code_stack_size(&fi->code);
    func_def->code = code_stack_data(&fi->code);
    code_stack_init(&fi->code);

    func_def->n_consts = value_stack_size(&fi->consts);
    func_def->consts = value_stack_data(&fi->consts);
    value_stack_init(&fi->consts);

    func_def->n_upvals = upval_def_stack_size(&fi->upvals);
    func_def->upvals = upval_def_stack_data(&fi->upvals);
    upval_def_stack_init(&fi->upvals);

    func_def->code_src_loc_size = fi->code_src_loc.size;
    func_def->code_src_loc = fi->code_src_loc.p;
    fh_init_buffer(&fi->code_src_loc);

    pop_func_info(c);
    return 0;

err:
    pop_func_info(c);
    return -1;
}

static int compile_named_func(struct fh_compiler *c,
                              struct fh_p_named_func *func, struct fh_func_def *func_def) {
    if (compile_func(c, func->loc, &func->func->data.func, func_def, NULL) < 0)
        return -1;

    if (func_info_stack_size(&c->funcs) > 0)
        return fh_compiler_error(c, func->loc, "INTERNAL COMPILER ERROR: function info was not cleared");

    return 0;
}

static const char *get_func_name(struct fh_compiler *c, struct fh_p_named_func *f) {
    const char *name = fh_get_ast_symbol(c->ast, f->name);
    if (!name) {
        fh_compiler_error(c, f->loc, "INTERNAL COMPILER ERROR: can't find function name");
        return NULL;
    }
    return name;
}

int fh_compile(struct fh_compiler *c, struct fh_ast *ast) {
    reset_compiler(c);
    c->ast = ast;

    int pin_state = fh_get_pin_state(c->prog);

    for (int i = 0; i < c->ast->func_vector->length; i++) {
        struct fh_p_named_func *f = c->ast->func_vector->data[i];

        const char *name = get_func_name(c, f);
        if (!name)
            goto err;
        if (fh_get_global_func_by_name(c->prog, name))
            return fh_compiler_error(c, f->loc, "function '%s' already exists", name);

        struct fh_func_def *func_def = new_func_def(c, f->loc, name, f->func->data.func.n_params);
        if (!func_def) {
            fh_compiler_error(c, f->loc, "out of memory");
            goto err;
        }

        struct fh_closure *closure = fh_make_closure(c->prog, true, func_def);
        if (!closure) {
            fh_compiler_error(c, f->loc, "out of memory");
            goto err;
        }

        if (f->func->data.func.doc_string) {
            closure->doc_string = fh_make_string(c->prog, true, f->func->data.func.doc_string);
            if (fh_dump_doc) {
                printf("documenation for function '%s' in %s:%d:%d: %s\n", name,
                       fh_get_symbol_name(&c->prog->src_file_names, f->loc.file_id),
                       f->loc.line, f->loc.col, f->func->data.func.doc_string);
            }
            free(f->func->data.func.doc_string);
        } else {
            closure->doc_string = NULL;
        }

        if (fh_add_global_func(c->prog, closure) < 0) {
            fh_compiler_error(c, f->loc, "out of memory");
            goto err;
        }
    }

    for (int i = 0; i < c->ast->func_vector->length; i++) {
        struct fh_p_named_func *f = c->ast->func_vector->data[i];

        const char *name = get_func_name(c, f);
        if (!name)
            goto err;
        struct fh_closure *closure = fh_get_global_func_by_name(c->prog, name);
        if (!closure) {
            fh_compiler_error(c, f->loc, "INTERNAL COMPILER ERROR: can't find function '%s'", name);
            goto err;
        }
        if (compile_named_func(c, f, closure->func_def) < 0)
            goto err;
    }

    fh_restore_pin_state(c->prog, pin_state);
    return 0;

err:
    fh_restore_pin_state(c->prog, pin_state);

    return -1;
}

/* compiler.h */

#ifndef COMPILER_H_FILE
#define COMPILER_H_FILE

#include "fh_internal.h"
#include "stack.h"
#include "value.h"
#include "ast.h"

DECLARE_STACK(int_stack, int);
DECLARE_STACK(code_stack, uint32_t);

DECLARE_STACK(upval_def_stack, struct fh_upval_def);

enum compiler_block_type {
    COMP_BLOCK_PLAIN,
    COMP_BLOCK_FUNC,
    COMP_BLOCK_WHILE,
    COMP_BLOCK_FOR,
};

struct block_info {
    enum compiler_block_type type;
    int32_t start_addr;
    int parent_num_regs;
};

DECLARE_STACK(block_info_stack, struct block_info);

enum fh_type_hint {
    H_UNKNOWN = 0,
    H_INT = 1,
    H_FLOAT = 2,
};

struct reg_info {
    fh_symbol_id var;
    bool alloc;
    bool used_by_inner_func;
    uint8_t hint;
};

DECLARE_STACK(reg_stack, struct reg_info);

struct func_info {
    struct func_info *parent;
    int num_regs;
    struct reg_stack regs;
    struct int_stack break_addrs;
    struct int_stack continue_addrs;
    struct block_info_stack blocks;
    struct code_stack code;
    struct value_stack consts;
    struct upval_def_stack upvals;
    struct fh_src_loc last_instr_src_loc;
    struct fh_buffer code_src_loc;
};

DECLARE_STACK(func_info_stack, struct func_info);

struct fh_compiler {
    struct fh_program *prog;
    struct fh_ast *ast;
    struct func_info_stack funcs;
    struct fh_src_loc last_func_call;
};

void fh_init_compiler(struct fh_compiler *c, struct fh_program *prog);

void fh_destroy_compiler(struct fh_compiler *c);

int fh_compile(struct fh_compiler *c, struct fh_ast *ast);

int fh_compiler_error(struct fh_compiler *c, struct fh_src_loc loc, char *fmt, ...) FH_PRINTF_FORMAT(3, 4);

uint32_t *fh_get_compiler_instructions(struct fh_compiler *c, int32_t *len);

#endif /* COMPILER_H_FILE */

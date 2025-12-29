/* ast.h */

#ifndef AST_H_FILE
#define AST_H_FILE

#include "vec/vec.h"

#include "fh_internal.h"

#define FUNC_CALL_PREC 1000

enum {
    AST_OP_UNM = 256,
    AST_OP_EQ,
    AST_OP_NEQ,
    AST_OP_GT,
    AST_OP_GE,
    AST_OP_LT,
    AST_OP_LE,
    AST_OP_OR,
    AST_OP_AND,
    AST_OP_RSH,
    AST_OP_LSH,
    AST_OP_INC,
    AST_OP_DEC
};

/* =========================================== */
/* == statements ============================= */

enum fh_stmt_type {
    STMT_NONE,
    STMT_EMPTY,
    STMT_VAR_DECL,
    STMT_CONST_DECL,
    STMT_EXPR,
    STMT_BLOCK,
    STMT_RETURN,
    STMT_IF,
    STMT_ELIF,
    STMT_WHILE,
    STMT_REPEAT,
    STMT_FOR,
    STMT_BREAK,
    STMT_CONTINUE
};

struct fh_p_stmt_decl {
    fh_symbol_id var;
    struct fh_p_expr *val;
};

struct fh_p_stmt_return {
    struct fh_p_expr *val;
};

struct fh_p_stmt_elif {
    struct fh_p_expr *test;
    struct fh_p_stmt *stmt;
};

#define FH_MAX_NESTED_ELIF 32

struct fh_p_stmt_if {
    struct fh_p_expr *test;
    struct fh_p_stmt *true_stmt;
    struct fh_p_stmt *false_stmt;
    struct fh_p_stmt *elif_stmt[FH_MAX_NESTED_ELIF];
    size_t num_elif_stmts; /* Counts how many elif have been alocated */
};

struct fh_p_stmt_for {
    struct fh_p_expr *test, *increment;
    struct fh_p_stmt *init, *stmt;
};

struct fh_p_stmt_while {
    struct fh_p_expr *test;
    struct fh_p_stmt *stmt;
};

struct fh_p_stmt_block {
    vec_void_t stmt_vector;
};

struct fh_p_stmt {
    enum fh_stmt_type type;
    struct fh_src_loc loc;
    struct fh_p_stmt *next;

    union {
        struct fh_p_stmt_decl decl;
        struct fh_p_stmt_block block;
        struct fh_p_stmt_return ret;
        struct fh_p_stmt_if stmt_if;
        struct fh_p_stmt_elif stmt_elif;
        struct fh_p_stmt_while stmt_while;
        struct fh_p_stmt_for stmt_for;
        struct fh_p_expr *expr;
    } data;
};

/* =========================================== */
/* == expressions ============================ */

enum fh_expr_type {
    EXPR_NONE,
    EXPR_VAR,
    EXPR_CONST,
    EXPR_NULL,
    EXPR_BOOL,
    EXPR_FLOAT,
    EXPR_STRING,
    EXPR_BIN_OP,
    EXPR_UN_OP,
    EXPR_FUNC,
    EXPR_FUNC_CALL,
    EXPR_INDEX,
    EXPR_ARRAY_LIT,
    EXPR_MAP_LIT,
    EXPR_POST_INC,
    EXPR_POST_DEC,
};

struct fh_p_expr_bin_op {
    uint32_t op;
    struct fh_p_expr *left;
    struct fh_p_expr *right;
};

struct fh_p_expr_un_op {
    uint32_t op;
    struct fh_p_expr *arg;
};

struct fh_p_expr_func_call {
    struct fh_p_expr *func;
    struct fh_p_expr *arg_list;
};

struct fh_p_expr_func {
    int n_params;
    fh_symbol_id *params;
    struct fh_p_stmt_block body;
    char *doc_string;
};

struct fh_p_expr_index {
    struct fh_p_expr *container;
    struct fh_p_expr *index;
};

struct fh_p_expr_array_lit {
    struct fh_p_expr *elem_list;
};

struct fh_p_expr_map_lit {
    struct fh_p_expr *elem_list;
};

struct fh_p_expr_postfix {
    uint32_t op; // AST_OP_INC / AST_OP_DEC
    struct fh_p_expr *arg; // l-value
};

struct fh_p_expr {
    enum fh_expr_type type;
    struct fh_src_loc loc;
    struct fh_p_expr *next;

    union {
        fh_symbol_id var;
        double num;
        bool b;
        fh_string_id str;
        struct fh_p_expr_bin_op bin_op;
        struct fh_p_expr_un_op un_op;
        struct fh_p_expr_func func;
        struct fh_p_expr_func_call func_call;
        struct fh_p_expr_index index;
        struct fh_p_expr_array_lit array_lit;
        struct fh_p_expr_map_lit map_lit;
        struct fh_p_expr_postfix postfix;
    } data;
};

/* =========================================== */
/* == named function ========================= */

struct fh_p_named_func {
    struct fh_p_named_func *next;
    fh_symbol_id name;
    struct fh_src_loc loc;
    struct fh_p_expr *func;
};

/* =========================================== */

struct fh_ast {
    struct fh_buffer string_pool;
    struct fh_symtab symtab;
    struct fh_symtab *file_names;
    vec_void_t *func_vector;
};

struct fh_ast *fh_new_ast(struct fh_symtab *file_names);

void fh_free_ast(struct fh_ast *ast);

const char *fh_get_ast_symbol(struct fh_ast *ast, fh_symbol_id id);

const char *fh_get_ast_string(struct fh_ast *ast, fh_string_id id);

const char *fh_get_ast_file_name(struct fh_ast *ast, fh_symbol_id file_id);

fh_symbol_id fh_add_ast_file_name(struct fh_ast *ast, const char *filename);

int fh_ast_visit_expr_nodes(struct fh_p_expr *expr, int (*visit)(struct fh_p_expr *expr, void *data), void *data);

struct fh_p_expr *fh_new_expr(struct fh_ast *ast, struct fh_src_loc loc, enum fh_expr_type type, size_t extra_size);

struct fh_p_stmt *fh_new_stmt(struct fh_ast *ast, struct fh_src_loc loc, enum fh_stmt_type type, size_t extra_size);

struct fh_p_named_func *fh_new_named_func(struct fh_ast *ast, struct fh_src_loc loc);

int fh_expr_list_size(struct fh_p_expr *list);

int fh_stmt_list_size(struct fh_p_stmt *list);

void fh_free_named_func(struct fh_p_named_func *func);

void fh_free_named_func_vector(vec_void_t *vector);

void fh_free_block(struct fh_p_stmt_block block);

void fh_free_stmt(struct fh_p_stmt *stmt);

void fh_free_stmt_children(struct fh_p_stmt *stmt);

void fh_free_stmt_list(struct fh_p_stmt *list);

void fh_free_stmt_vector(vec_void_t *vector);

void fh_free_expr(struct fh_p_expr *expr);

void fh_free_expr_children(struct fh_p_expr *expr);

void fh_free_expr_list(struct fh_p_expr *list);

void fh_dump_named_func(struct fh_ast *ast, struct fh_p_named_func *func);

void fh_dump_expr(struct fh_ast *ast, struct fh_p_expr *expr);

void fh_dump_ast(struct fh_ast *p);

#endif /* AST_H_FILE */

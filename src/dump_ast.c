/* dump_ast.c */

#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>

#include "fh_internal.h"
#include "ast.h"

#define INDENT 4

static bool expr_needs_paren(struct fh_p_expr *expr) {
    switch (expr->type) {
        case EXPR_VAR:
        case EXPR_CONST:
        case EXPR_FLOAT:
        case EXPR_STRING:
        case EXPR_FUNC_CALL:
            return false;

        default:
            return true;
    }
}

static void dump_string(struct fh_ast *ast, const char *str) {
    UNUSED(ast);
    printf("\"");
    for (const char *p = str; *p != '\0'; p++) {
        switch (*p) {
            case '\n': printf("\\n");
                break;
            case '\r': printf("\\r");
                break;
            case '\t': printf("\\t");
                break;
            case '\\': printf("\\\\");
                break;
            case '"': printf("\\\"");
                break;
            default:
                if (*p < 32)
                    printf("\\x%02x", (unsigned char) *p);
                else
                    printf("%c", *p);
                break;
        }
    }
    printf("\"");
}

static void dump_expr(struct fh_ast *ast, int indent, struct fh_p_expr *expr) {
    switch (expr->type) {
        case EXPR_NONE:
            printf("<INTERNAL ERROR: expression node of type 'NONE'>");
            return;

        case EXPR_VAR:
        case EXPR_CONST:
            printf("%s", fh_get_ast_symbol(ast, expr->data.var));
            return;

        case EXPR_NULL:
            printf("null");
            return;

        case EXPR_BOOL:
            printf("%s", (expr->data.b) ? "true" : "false");
            return;

        case EXPR_FLOAT:
            printf("%g", expr->data.num);
            return;

        case EXPR_STRING:
            dump_string(ast, fh_get_ast_string(ast, expr->data.str));
            return;

        case EXPR_POST_INC:
        case EXPR_POST_DEC: {
            // operand
            if (expr_needs_paren(expr->data.postfix.arg)) printf("(");
            dump_expr(ast, indent, expr->data.postfix.arg);
            if (expr_needs_paren(expr->data.postfix.arg)) printf(")");

            // suffix operator
            printf("%s", fh_get_op_name(expr->data.postfix.op));
            return;
        }
        case EXPR_BIN_OP:
            if (expr_needs_paren(expr->data.bin_op.left)) printf("(");
            dump_expr(ast, indent, expr->data.bin_op.left);
            if (expr_needs_paren(expr->data.bin_op.left)) printf(")");
            printf(" %s ", fh_get_op_name(expr->data.bin_op.op));
            if (expr_needs_paren(expr->data.bin_op.right)) printf("(");
            dump_expr(ast, indent, expr->data.bin_op.right);
            if (expr_needs_paren(expr->data.bin_op.right)) printf(")");
            return;

        case EXPR_INDEX:
            if (expr_needs_paren(expr->data.index.container)) printf("(");
            dump_expr(ast, indent, expr->data.index.container);
            if (expr_needs_paren(expr->data.index.container)) printf(")");
            printf("[");
            dump_expr(ast, indent, expr->data.index.index);
            printf("]");
            return;

        case EXPR_UN_OP:
            printf("%s", fh_get_op_name(expr->data.un_op.op));
            if (expr_needs_paren(expr->data.un_op.arg)) printf("(");
            dump_expr(ast, indent, expr->data.un_op.arg);
            if (expr_needs_paren(expr->data.un_op.arg)) printf(")");
            return;

        case EXPR_FUNC_CALL:
            if (expr_needs_paren(expr->data.func_call.func)) printf("(");
            dump_expr(ast, indent, expr->data.func_call.func);
            if (expr_needs_paren(expr->data.func_call.func)) printf(")");
            printf("(");
            for (struct fh_p_expr *e = expr->data.func_call.arg_list; e != NULL; e = e->next) {
                dump_expr(ast, indent, e);
                if (e->next)
                    printf(", ");
            }
            printf(")");
            return;

        case EXPR_ARRAY_LIT:
            printf("[ ");
            for (struct fh_p_expr *e = expr->data.array_lit.elem_list; e != NULL; e = e->next) {
                dump_expr(ast, indent, e);
                if (e->next)
                    printf(", ");
            }
            printf(" ]");
            return;

        case EXPR_MAP_LIT:
            printf("{");
            for (struct fh_p_expr *e = expr->data.map_lit.elem_list; e != NULL; e = e->next) {
                printf(" ");
                dump_expr(ast, indent, e);
                printf(" : ");
                if (!(e = e->next)) {
                    printf("<ERROR>");
                    break;
                }
                dump_expr(ast, indent, e);
                if (e->next)
                    printf(",");
            }
            printf("}");
            return;

        case EXPR_FUNC:
            printf("<...func...>");
            return;
    }

    printf("<unknown expr type: %d>", expr->type);
}

static void dump_block(struct fh_ast *ast, int indent, struct fh_p_stmt_block block);

static void dump_stmt(struct fh_ast *ast, int indent, struct fh_p_stmt *stmt) {
    switch (stmt->type) {
        case STMT_NONE:
            printf("%*s<INTERNAL ERROR: statement node of type 'NONE'>;", indent, "");
            return;

        case STMT_EMPTY:
            printf("%*s;\n", indent, "");
            return;

        case STMT_BREAK:
            printf("%*sbreak;\n", indent, "");
            return;

        case STMT_CONTINUE:
            printf("%*scontinue;\n", indent, "");
            return;

        case STMT_CONST_DECL:
            printf("%*sconst %s", indent, "", fh_get_ast_symbol(ast, stmt->data.decl.var));
            if (stmt->data.decl.val) {
                printf(" = ");
                dump_expr(ast, indent + INDENT, stmt->data.decl.val);
            }
            printf(";\n");
            return;

        case STMT_VAR_DECL:
            printf("%*slet %s", indent, "", fh_get_ast_symbol(ast, stmt->data.decl.var));
            if (stmt->data.decl.val) {
                printf(" = ");
                dump_expr(ast, indent + INDENT, stmt->data.decl.val);
            }
            printf(";\n");
            return;

        case STMT_EXPR:
            printf("%*s", indent, "");
            dump_expr(ast, indent + INDENT, stmt->data.expr);
            printf(";\n");
            return;

        case STMT_RETURN:
            printf("%*sreturn", indent, "");
            if (stmt->data.ret.val) {
                printf(" ");
                dump_expr(ast, indent + INDENT, stmt->data.ret.val);
            }
            printf(";\n");
            return;

        case STMT_BLOCK:
            printf("%*s", indent, "");
            dump_block(ast, indent, stmt->data.block);
            printf("\n");
            return;

        case STMT_IF:
            printf("%*sif (", indent, "");
            dump_expr(ast, indent + INDENT, stmt->data.stmt_if.test);
            printf(")");

            if (stmt->data.stmt_if.true_stmt->type == STMT_BLOCK) {
                printf(" ");
                dump_block(ast, indent, stmt->data.stmt_if.true_stmt->data.block);
            } else {
                printf("\n");
                dump_stmt(ast, indent + INDENT, stmt->data.stmt_if.true_stmt);
            }

            // elif chain
            if (stmt->data.stmt_if.num_elif_stmts > 0) {
                for (size_t i = 0; i < stmt->data.stmt_if.num_elif_stmts; i++) {
                    struct fh_p_stmt *elif_stmt = stmt->data.stmt_if.elif_stmt[i];
                    if (!elif_stmt) continue;

                    // print "elif (...) ..."
                    printf("%*selif (", indent, "");
                    dump_expr(ast, indent + INDENT, elif_stmt->data.stmt_elif.test);
                    printf(")");

                    if (elif_stmt->data.stmt_elif.stmt->type == STMT_BLOCK) {
                        printf(" ");
                        dump_block(ast, indent, elif_stmt->data.stmt_elif.stmt->data.block);
                        printf("\n");
                    } else {
                        printf("\n");
                        dump_stmt(ast, indent + INDENT, elif_stmt->data.stmt_elif.stmt);
                    }
                }
            }

            if (stmt->data.stmt_if.false_stmt) {
                if (stmt->data.stmt_if.true_stmt->type == STMT_BLOCK)
                    printf(" else");
                else
                    printf("%*selse", indent, "");
                if (stmt->data.stmt_if.false_stmt->type == STMT_BLOCK) {
                    printf(" ");
                    dump_block(ast, indent, stmt->data.stmt_if.false_stmt->data.block);
                    printf("\n");
                } else {
                    printf("\n");
                    dump_stmt(ast, indent + INDENT, stmt->data.stmt_if.false_stmt);
                }
            } else {
                if (stmt->data.stmt_if.true_stmt->type == STMT_BLOCK)
                    printf("\n");
            }
            return;


        case STMT_ELIF:
            printf("%*selif (", indent, "");
            dump_expr(ast, indent + INDENT, stmt->data.stmt_elif.test);
            printf(")");

            if (stmt->data.stmt_elif.stmt->type == STMT_BLOCK) {
                printf(" ");
                dump_block(ast, indent, stmt->data.stmt_elif.stmt->data.block);
                printf("\n");
            } else {
                printf("\n");
                dump_stmt(ast, indent + INDENT, stmt->data.stmt_elif.stmt);
            }
            return;

        case STMT_FOR:
            printf("%*sfor (", indent, "");

            // init is a statement (usually STMT_VAR_DECL or STMT_EXPR or STMT_EMPTY)
            if (stmt->data.stmt_for.init) {
                // print it inline without trailing '\n'
                // easiest: special-case the common ones
                const struct fh_p_stmt *init = stmt->data.stmt_for.init;
                switch (init->type) {
                    case STMT_EMPTY:
                        printf(";");
                        break;

                    case STMT_VAR_DECL:
                        printf("let %s", fh_get_ast_symbol(ast, init->data.decl.var));
                        if (init->data.decl.val) {
                            printf(" = ");
                            dump_expr(ast, indent + INDENT, init->data.decl.val);
                        }
                        printf(";");
                        break;

                    case STMT_CONST_DECL:
                        printf("const %s", fh_get_ast_symbol(ast, init->data.decl.var));
                        if (init->data.decl.val) {
                            printf(" = ");
                            dump_expr(ast, indent + INDENT, init->data.decl.val);
                        }
                        printf(";");
                        break;

                    case STMT_EXPR:
                        dump_expr(ast, indent + INDENT, init->data.expr);
                        printf(";");
                        break;

                    default:
                        printf("<bad for-init>;");
                        break;
                }
            } else {
                printf(";");
            }

            printf(" ");

            // test
            if (stmt->data.stmt_for.test) {
                dump_expr(ast, indent + INDENT, stmt->data.stmt_for.test);
            }
            printf("; ");

            // increment
            if (stmt->data.stmt_for.increment) {
                dump_expr(ast, indent + INDENT, stmt->data.stmt_for.increment);
            }

            printf(")");

            // body
            if (stmt->data.stmt_for.stmt && stmt->data.stmt_for.stmt->type == STMT_BLOCK) {
                printf(" ");
                dump_block(ast, indent, stmt->data.stmt_for.stmt->data.block);
                printf("\n");
            } else {
                printf("\n");
                if (stmt->data.stmt_for.stmt)
                    dump_stmt(ast, indent + INDENT, stmt->data.stmt_for.stmt);
            }
            return;

        case STMT_WHILE:
            printf("%*swhile (", indent, "");
            dump_expr(ast, indent + INDENT, stmt->data.stmt_while.test);
            printf(")");

            if (stmt->data.stmt_while.stmt->type == STMT_BLOCK) {
                printf(" ");
                dump_block(ast, indent, stmt->data.stmt_while.stmt->data.block);
                printf("\n");
            } else {
                printf("\n");
                dump_stmt(ast, indent + INDENT, stmt->data.stmt_while.stmt);
            }
            return;

        case STMT_REPEAT:
            printf("%*srepeat ", indent, "");
            if (stmt->data.stmt_while.stmt->type == STMT_BLOCK) {
                printf(" ");
                dump_block(ast, indent, stmt->data.stmt_while.stmt->data.block);
                printf("\n");
            } else {
                printf("\n");
                dump_stmt(ast, indent + INDENT, stmt->data.stmt_while.stmt);
            }
            printf("until (");
            dump_expr(ast, indent + INDENT, stmt->data.stmt_while.test);
            printf(")\n");
            return;
    }

    printf("%*s# unknown statement type: %d\n", indent, "", stmt->type);
}

static void dump_block(struct fh_ast *ast, int indent, struct fh_p_stmt_block block) {
    printf("{\n");
    for (int i = 0; i < block.stmt_vector.length; i++) {
        struct fh_p_stmt *s = block.stmt_vector.data[i];
        dump_stmt(ast, indent + INDENT, s);
    }
    printf("%*s}", indent, "");
}

void fh_dump_expr(struct fh_ast *ast, struct fh_p_expr *expr) {
    dump_expr(ast, 0, expr);
}

/*static void fh_dump_block(struct fh_ast *ast, struct fh_p_stmt_block block)
  {
  dump_block(ast, 0, block);
  }*/

void fh_dump_named_func(struct fh_ast *ast, struct fh_p_named_func *func) {
    printf("function %s(", fh_get_ast_symbol(ast, func->name));
    for (int i = 0; i < func->func->data.func.n_params; i++) {
        printf("%s", fh_get_ast_symbol(ast, func->func->data.func.params[i]));
        if (i + 1 < func->func->data.func.n_params)
            printf(", ");
    }
    printf(") ");
    dump_block(ast, 0, func->func->data.func.body);
    printf("\n");
}

void fh_dump_ast(struct fh_ast *ast) {
    //for (struct fh_p_named_func *f = ast->func_list; f != NULL; f = f->next) {
    for (int i = 0; i < ast->func_vector->length; i++) {
        struct fh_p_named_func *f = ast->func_vector->data[i];
        if (f == NULL)
            continue;
        fh_dump_named_func(ast, f);
    }
}

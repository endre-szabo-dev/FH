/* main.c */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "fh.h"
#include "program.h"

#include "functions.h"

int fh_run_string(struct fh_program *prog, bool dump_bytecode, const char *string, const char *main_function_name) {
    char *template = "fb main(){%s;}";
    char *code = malloc(strlen(template) - 2 + strlen(string) + 1);
    if (!code) {
        fh_set_error(prog, "out of memory for string");
        return -1;
    }
    sprintf(code, template, string);

    struct fh_input *in = fh_open_input_string(code);
    if (!in) {
        free(code);
        fh_set_error(prog, "out of memory for string input");
        return -1;
    }
    free(code);

    if (fh_compile_input(prog, in) < 0)
        return -1;

    if (dump_bytecode)
        fh_dump_bytecode(prog);

    struct fh_value script_ret;
    if (main_function_name != NULL && fh_call_function(prog, main_function_name, NULL, 0, &script_ret) < 0)
        return -1;

    if (fh_is_float(&script_ret))
        return (int) fh_get_float(&script_ret);
    return 0;
}

int fh_run_pack(struct fh_program *prog, bool dump_bytecode, const char *pack_path,
                const char *filename, const char *main_function_name, char **args, int n_args, bool is_mandatory) {
    int err = mtar_open(&fh_tar, pack_path, "r");
    if (err != MTAR_ESUCCESS) {
        printf("cannot open pack: %s\n", pack_path);
        return -1;
    }

    fh_is_packed = true;

    if (fh_compile_pack(prog, filename, is_mandatory) < 0)
        return -1;

    if (dump_bytecode)
        fh_dump_bytecode(prog);

    struct fh_value script_args = fh_new_array(prog);
    if (fh_is_null(&script_args))
        return -1;
    struct fh_value *items = fh_grow_array(prog, &script_args, n_args + 1);
    if (!items)
        return -1;
    items[0] = fh_new_string(prog, filename);
    for (int i = 0; i < n_args; i++)
        items[i + 1] = fh_new_string(prog, args[i]);

    struct fh_value script_ret;
    if (main_function_name != NULL && fh_call_function(prog, main_function_name, &script_args, 1, &script_ret) < 0)
        return -1;

    if (fh_is_float(&script_ret))
        return (int) fh_get_float(&script_ret);

    return 0;
}

int fh_run_script_file(struct fh_program *prog, bool dump_bytecode, const char *filename,
                       const char *main_function_name, char **args, int n_args, bool is_mandatory) {
    if (fh_compile_file(prog, filename, is_mandatory) < 0)
        return -1;

    if (dump_bytecode)
        fh_dump_bytecode(prog);

    struct fh_value script_args = fh_new_array(prog);
    if (fh_is_null(&script_args))
        return -1;
    struct fh_value *items = fh_grow_array(prog, &script_args, n_args + 1);
    if (!items)
        return -1;
    items[0] = fh_new_string(prog, filename);
    for (int i = 0; i < n_args; i++)
        items[i + 1] = fh_new_string(prog, args[i]);

    struct fh_value script_ret;
    if (main_function_name != NULL && fh_call_function(prog, main_function_name, &script_args, 1, &script_ret) < 0)
        return -1;

    if (fh_is_float(&script_ret))
        return (int) fh_get_float(&script_ret);
    return 0;
}

#ifdef FH_USE_MAIN_FUNC
static void print_usage(char *progname) {
    printf("USAGE: %s [options] [filename [args...]]\n", progname);
    printf("\n");
    printf("options:\n");
    printf("\n");
    printf("  -e STRING               execute STRING\n");
    printf("  -d                      dump bytecode before execution\n");
    printf("  -p PATH ?MAIN_FILE?.fh  execute a .fhpack project\n");
    printf("  -o                      dump all documentation before execution\n");
    printf("  -l                      load dynamic library\n");
    printf("  -v                      prints the version\n");
    printf("  -h                      display this help\n");
    printf("\n");
    printf("Version: %s\n", FH_VERSION);
    printf("Contact: muresanvladmihail@gmail.com\n");
}

int main(int argc, char **argv) {
    char *execute_code = NULL;
    char *filename = NULL;
    char **args = NULL;
    int num_args = 0;
    bool dump_bytecode = false;
    char *package_path = NULL;

    fh_init();

    struct fh_program *prog = fh_new_program();
    if (!prog) {
        printf("ERROR: out of memory for program\n");
        return 1;
    }

    for (int i = 1; i < argc; i++) {
        if (argv[i][0] != '-') {
            filename = argv[i];
            args = argv + i + 1;
            num_args = argc - i - 1;
            break;
        }
        switch (argv[i][1]) {
            case 'h':
                print_usage(argv[0]);
                return 0;

            case 'd':
                dump_bytecode = true;
                break;

            case 'v':
                printf("%s\n", FH_VERSION);
                return 0;

            case 'o':
                fh_dump_doc = true;
                break;

            case 'p':
                package_path = argv[++i];
                if (!package_path) {
                    puts("option '-p' requires an argument");
                    return 1;
                }

                fh_main_file_packed = argv[++i];
                if (!fh_main_file_packed) {
                    /* If the user didn't explicitly tell FH which
                     * main file to use, fallback to default, main.fh. */
                    i--;
                    fh_main_file_packed = "main.fh";
                }

                break;

            case 'e':
                execute_code = argv[++i];
                if (!execute_code) {
                    printf("%s: option '-e' requires an argument\n", argv[0]);
                    return 1;
                }
                break;

            case 'l': {
                const char *path = argv[++i];
                void *handle = fh_load_dynamic_library(path, prog);
                if (!handle) {
                    fh_deinit(prog);
                    return -1;
                }
                break;
            }
            default:
                printf("%s: unknown option '%s'\n", argv[0], argv[i]);
                return 1;
        }
    }
    if (!filename && !execute_code && !fh_is_packed) {
        print_usage(argv[0]);
        return 0;
    }

    int ret;
    if (execute_code)
        ret = fh_run_string(prog, dump_bytecode, execute_code, "main");
    else if (fh_is_packed)
        ret = fh_run_pack(prog, dump_bytecode, fh_main_file_packed, fh_main_file_packed, "main", args, num_args, true);
    else
        ret = fh_run_script_file(prog, dump_bytecode, filename, "main", args, num_args, true);
    if (ret < 0) {
        printf("ERROR: %s\n", fh_get_error(prog));
        ret = 1;
    }

    fh_deinit(prog);

    return ret;
}
#endif

/* c_funcs.c */

#include <stdlib.h>
#include <limits.h>
#include <stdio.h>
#include <math.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <float.h>
#include <inttypes.h>
#include <errno.h>

#include "fh.h"
#include "value.h"
#include "fh_internal.h"
#include "program.h"
#include "regex/re.h"
#include "crypto/md5.h"
#include "crypto/bcrypt.h"

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

#ifndef FLT_EPSILON
#define FLT_EPSILON 1E-6
#endif

#define DEG_TO_RAD(angleInDegrees) ((angleInDegrees) * M_PI / 180.0)
#define RAD_TO_DEG(angleInRadians) ((angleInRadians) * 180.0 / M_PI)
#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

#define MAX_ITEM 512

#if defined(WIN32) || defined(_WIN32)
#include <direct.h>
#if defined(_MSC_VER) || defined(_MSC_EXTENSIONS)
#define DELTA_EPOCH_IN_MICROSECS  11644473600000000Ui64
#else
#define DELTA_EPOCH_IN_MICROSECS  11644473600000000ULL
#endif

/*
 * gettimeofday.c
 *    Win32 gettimeofday() replacement
 *
 * src/port/gettimeofday.c
 *
 * Copyright (c) 2003 SRA, Inc.
 * Copyright (c) 2003 SKC, Inc.
 *
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose, without fee, and without a
 * written agreement is hereby granted, provided that the above
 * copyright notice and this paragraph and the following two
 * paragraphs appear in all copies.
 *
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE TO ANY PARTY FOR DIRECT,
 * INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING
 * LOST PROFITS, ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS
 * DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA HAS BEEN ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * THE AUTHOR SPECIFICALLY DISCLAIMS ANY WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS
 * IS" BASIS, AND THE AUTHOR HAS NO OBLIGATIONS TO PROVIDE MAINTENANCE,
 * SUPPORT, UPDATES, ENHANCEMENTS, OR MODIFICATIONS.
 */

#include <windows.h>
#include <stdint.h>
#include <io.h>
#include <tchar.h>
#include <sys/stat.h>

/* FILETIME of Jan 1 1970 00:00:00. */
static const unsigned __int64 epoch = ((unsigned __int64) 116444736000000000ULL);

/*
 * timezone information is stored outside the kernel so tzp isn't used anymore.
 *
 * Note: this function is not for Win32 high precision timing purpose. See
 * elapsed_time().
 */
int
gettimeofday(struct timeval *tp, struct timezone *tzp) {
    FILETIME file_time;
    SYSTEMTIME system_time;
    ULARGE_INTEGER ularge;

    GetSystemTime(&system_time);
    SystemTimeToFileTime(&system_time, &file_time);
    ularge.LowPart = file_time.dwLowDateTime;
    ularge.HighPart = file_time.dwHighDateTime;

    tp->tv_sec = (uint64_t) ((ularge.QuadPart - epoch) / 10000000L);
    tp->tv_usec = (uint64_t) (system_time.wMilliseconds * 1000);

    return 0;
}
#else
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#endif


#ifndef S_IFMT
#define S_IFMT 0160000 /* type of file: */
#endif
#ifndef S_IFDIR
#define S_IFDIR 0040000 /* directory */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "program.h"
#include "value.h"
#include "fh.h"

static void fh_value_repr(struct fh_program *prog, const struct fh_value *v,
                          char *out, size_t out_sz) {
    if (!out || out_sz == 0) return;

    const char *t = fh_type_to_str(prog, v->type);

    switch (v->type) {
        case FH_VAL_NULL:
            snprintf(out, out_sz, "%s", t);
            return;

        case FH_VAL_BOOL:
            snprintf(out, out_sz, "%s %s", t, v->data.b ? "true" : "false");
            return;

        case FH_VAL_INTEGER:
            snprintf(out, out_sz, "%s %lld", t, (long long)v->data.i);
            return;

        case FH_VAL_FLOAT: {
            double d = v->data.num;
            if (isnan(d)) {
                snprintf(out, out_sz, "%s NaN", t);
            } else if (!isfinite(d)) {
                snprintf(out, out_sz, "%s %sInfinity", t, (d < 0.0 ? "-" : "+"));
            } else {
                // %g gives compact representation; tweak if you want fixed decimals
                snprintf(out, out_sz, "%s %g", t, d);
            }
            return;
        }

        case FH_VAL_STRING: {
            const char *s = fh_get_string(v);
            if (!s) {
                snprintf(out, out_sz, "%s <invalid>", t);
                return;
            }
            // avoid flooding the error with huge strings
            const size_t max_preview = 120;
            size_t n = strlen(s);
            if (n <= max_preview) {
                snprintf(out, out_sz, "%s \"%s\"", t, s);
            } else {
                // print prefix only
                char tmp[128];
                memcpy(tmp, s, max_preview);
                tmp[max_preview] = 0;
                snprintf(out, out_sz, "%s \"%s…\" (len=%zu)", t, tmp, n);
            }
            return;
        }

        case FH_VAL_ARRAY: {
            const struct fh_array *arr = GET_VAL_ARRAY((struct fh_value*)v);
            const uint32_t len = arr ? arr->len : 0;
            snprintf(out, out_sz, "%s(len=%u)", t, (unsigned)len);
            return;
        }

        case FH_VAL_MAP: {
            const struct fh_map *map = GET_VAL_MAP((struct fh_value*)v);
            uint32_t len = map ? map->len : 0;
            snprintf(out, out_sz, "%s(len=%u)", t, (unsigned)len);
            return;
        }

        case FH_VAL_CLOSURE: {
            struct fh_closure *c = GET_VAL_CLOSURE((struct fh_value*)v);
            const char *name = (c && c->func_def) ? fh_get_func_def_name(c->func_def) : NULL;
            if (name)
                snprintf(out, out_sz, "%s(%s)", t, name);
            else
                snprintf(out, out_sz, "%s", t);
            return;
        }

        case FH_VAL_FUNC_DEF: {
            struct fh_func_def *fd = GET_VAL_FUNC_DEF((struct fh_value*)v);
            const char *name = fd ? fh_get_func_def_name(fd) : NULL;
            if (name)
                snprintf(out, out_sz, "%s(%s)", t, name);
            else
                snprintf(out, out_sz, "%s", t);
            return;
        }

        case FH_VAL_C_FUNC:
            snprintf(out, out_sz, "%s(%p)", t, (void*)v->data.c_func);
            return;

        case FH_VAL_C_OBJ: {
            struct fh_c_obj *o = fh_get_c_obj((struct fh_value*)v);
            int usr_type = o ? o->type : 0;
            void *ptr = o ? o->ptr : NULL;
            snprintf(out, out_sz, "%s(type=%d, ptr=%p)", t, usr_type, ptr);
            return;
        }

        default:
            snprintf(out, out_sz, "%s", t);
            return;
    }
}

static void print_value(struct fh_value *val) {
    if (val->type == FH_VAL_UPVAL)
        val = GET_OBJ_UPVAL(val->data.obj)->val;

    switch (val->type) {
        case FH_VAL_NULL: printf("null");
            return;
        case FH_VAL_BOOL: printf("%s", (val->data.b) ? "true" : "false");
            return;
        case FH_VAL_FLOAT: printf("%.17g", val->data.num);
            return;
        case FH_VAL_INTEGER: printf("%lld", val->data.i);
            return;
        case FH_VAL_STRING: printf("%s", GET_VAL_STRING_DATA(val));
            return;
        case FH_VAL_ARRAY: {
            const struct fh_array *v = GET_VAL_ARRAY(val);
            if (v->len == 0) {
                printf("[]");
                return;
            }
            for (uint32_t i = 0; i < v->len; i++) {
                printf("[%u] ", i);
                fh_dump_value(&v->items[i]);
                printf("\n");
            }
            return;
        }
        case FH_VAL_MAP: {
            const struct fh_map *v = GET_VAL_MAP(val);
            if (v->len == 0) {
                printf("{}");
                return;
            }
            for (uint32_t i = 0; i < v->cap; i++) {
                const struct fh_map_entry *e = &v->entries[i];
                if (e->key.type != FH_VAL_NULL) {
                    printf("[%u] ", i);

                    fh_dump_value(&e->key);
                    printf(" -> ");
                    fh_dump_value(&e->val);
                    printf("\n");
                }
            }
            return;
        }
        case FH_VAL_CLOSURE: printf("<closure %p>", val->data.obj);
            return;
        case FH_VAL_UPVAL: printf("<internal error (upval)>");
            return;
        case FH_VAL_FUNC_DEF: printf("<func def %p>", val->data.obj);
            return;
        case FH_VAL_C_FUNC: {
            printf("<C function 0x");
            unsigned char *p = (unsigned char *) &val->data.c_func;
            p += sizeof(val->data.c_func);
            for (size_t i = 0; i < sizeof(val->data.c_func); i++)
                if (*--p)
                    printf("%02x", *p);
            printf(">");
            return;
        }
        case FH_VAL_C_OBJ: {
            printf("<C obj 0x");
            unsigned char *p = (unsigned char *) &val->data.obj;
            p += sizeof(val->data.obj);
            for (size_t i = 0; i < sizeof(val->data.obj); i++)
                if (*--p)
                    printf("%02x", *p);
            printf(">");
            return;
        }
    }
    printf("<invalid value %d>", val->type);
}

static int check_n_args(struct fh_program *prog, const char *func_name, int n_expected, int n_received) {
    if (n_expected >= 0 && n_received != n_expected)
        return fh_set_error(prog, "%s: expected %d argument(s), got %d", func_name, n_expected, n_received);
    if (n_received != INT_MIN && n_received < -n_expected)
        return fh_set_error(prog, "%s: expected at least %d argument(s), got %d", func_name, -n_expected, n_received);
    return 0;
}

/*********** Math functions ***********/
static int fn_math_md5(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    FH_REQUIRE_EXACT_ARGS(prog, "math_md5()", 1, n_args);

    const char *key = fh_get_string(&args[0]);
    uint8_t *res_i = md5String((char *) key);
    char res_s[33]; // 16 * 2 + 1
    char *ptr = &res_s[0];
    for (int i = 0; i < 16; ++i) {
        /* "sprintf" converts each byte in the "buf" array into a 2 hex string
         * characters appended with a null byte, for example 10 => "0A\0".
         *
         * This string would then be added to the output array starting from the
         * position pointed at by "ptr". For example if "ptr" is pointing at the 0
         * index then "0A\0" would be written as output[0] = '0', output[1] = 'A' and
         * output[2] = '\0'.
         *
         * "sprintf" returns the number of chars in its output excluding the null
         * byte, in our case this would be 2. So we move the "ptr" location two
         * steps ahead so that the next hex string would be written at the new
         * location, overriding the null byte from the previous hex string.
         *
         * We don't need to add a terminating null byte because it's been already
         * added for us from the last hex string. */
        ptr += sprintf(ptr, "%02x", res_i[i]);
    }

    *ret = fh_new_string(prog, res_s);
    free(res_i);
    return 0;
}

static int fn_math_bcrypt_gen_salt(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    FH_REQUIRE_EXACT_ARGS(prog, "math_bcrypt_gen_salt()", 1, n_args);

    char salt[BCRYPT_HASHSIZE];

    int32_t factor32;
    if (fh_arg_int32(prog, &args[0], "math_bcrypt_gen_salt()", 0, &factor32) < 0) return -1;
    const int factor = (int) factor32;
    if (factor < 4 || factor > 31) {
        return fh_set_error(
            prog, "math_bcrypt_gen_salt(): expected first argument, 'factor', to be between 4 and 31, got %d", factor);
    }

    if (bcrypt_gensalt(factor, salt) != 0) {
        return fh_set_error(prog, "math_bcrypt_gen_salt(): failed to generate salt");
    }

    *ret = fh_new_string(prog, salt);

    return 0;
}

static int fn_math_bcrypt_hashpw(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    if (check_n_args(prog, "math_bcrypt_hashpw()", 2, n_args))
        return -1;

    if (!fh_is_string(&args[0])) {
        return fh_set_error(prog, "math_bcrypt_hashpw(): expected string as first argument, got %s",
                            fh_type_to_str(prog, args[0].type));
    }
    if (!fh_is_string(&args[1])) {
        return fh_set_error(prog, "math_bcrypt_hashpw(): expected string as second argument, got %s",
                            fh_type_to_str(prog, args[1].type));
    }

    const char *passwd = fh_get_string(&args[0]);
    const char *salt = fh_get_string(&args[1]);
    char hash[BCRYPT_HASHSIZE];

    if (bcrypt_hashpw(passwd, salt, hash) != 0) {
        return fh_set_error(prog, "math_bcrypt_hashpw(): failed to hash");
    }

    *ret = fh_new_string(prog, hash);
    return 0;
}

static int fn_math_abs(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    FH_REQUIRE_EXACT_ARGS(prog, "math_abs()", 1, n_args);

    if (fh_is_float(&args[0])) {
        *ret = fh_make_float(fabs(args[0].data.num));
        return 0;
    }
    if (fh_is_integer(&args[0])) {
        const int64_t x = args[0].data.i;
        if (x == INT64_MIN) {
            return fh_set_error(prog, "math_abs(): integer overflow");
        }
        *ret = fh_make_integer(llabs((long long)x));
        return 0;
    }
    return fh_set_error(prog, "math_abs(): expected number/integer, got %s", fh_type_to_str(prog, args[0].type));
}

static int fn_math_acos(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    FH_REQUIRE_EXACT_ARGS(prog, "math_acos()", 1, n_args);

    double x;
    if (fh_arg_double(prog, &args[0], "math_acos()", 0, &x) < 0) return -1;

    *ret = fh_make_float(acos(x));
    return 0;
}

static int fn_math_asin(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    FH_REQUIRE_EXACT_ARGS(prog, "math_asin()", 1, n_args);

    double x;
    if (fh_arg_double(prog, &args[0], "math_asin()", 0, &x) < 0) return -1;

    *ret = fh_make_float(asin(x));
    return 0;
}

static int fn_math_atan(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    FH_REQUIRE_EXACT_ARGS(prog, "math_atan()", 1, n_args);

    double x;
    if (fh_arg_double(prog, &args[0], "math_atan()", 0, &x) < 0) return -1;

    *ret = fh_make_float(atan(x));
    return 0;
}

static int fn_math_cos(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    FH_REQUIRE_EXACT_ARGS(prog, "math_cos()", 1, n_args);
    double x;
    if (fh_arg_double(prog, &args[0], "math_cos()", 0, &x) < 0) return -1;
    *ret = fh_make_float(cos(x));
    return 0;
}

static int fn_math_cosh(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    FH_REQUIRE_EXACT_ARGS(prog, "math_cosh()", 1, n_args);
    double x;
    if (fh_arg_double(prog, &args[0], "math_cosh()", 0, &x) < 0) return -1;
    *ret = fh_make_float(cosh(x));
    return 0;
}

static int fn_math_exp(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    FH_REQUIRE_EXACT_ARGS(prog, "math_exp()", 1, n_args);
    double x;
    if (fh_arg_double(prog, &args[0], "math_exp()", 0, &x) < 0) return -1;
    *ret = fh_make_float(exp(x));
    return 0;
}

static int fn_math_log(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    FH_REQUIRE_EXACT_ARGS(prog, "math_log()", 1, n_args);
    double x;
    if (fh_arg_double(prog, &args[0], "math_log()", 0, &x) < 0) return -1;
    *ret = fh_make_float(log(x));
    return 0;
}

static int fn_math_log10(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    FH_REQUIRE_EXACT_ARGS(prog, "math_log10()", 1, n_args);
    double x;
    if (fh_arg_double(prog, &args[0], "math_log10()", 0, &x) < 0) return -1;
    *ret = fh_make_float(log10(x));
    return 0;
}

static int fn_math_deg(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    FH_REQUIRE_EXACT_ARGS(prog, "math_deg()", 1, n_args);
    double x;
    if (fh_arg_double(prog, &args[0], "math_deg()", 0, &x) < 0) return -1;
    *ret = fh_make_float(RAD_TO_DEG(x));
    return 0;
}

static int fn_math_rad(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    FH_REQUIRE_EXACT_ARGS(prog, "math_rad()", 1, n_args);
    double x;
    if (fh_arg_double(prog, &args[0], "math_rad()", 0, &x) < 0) return -1;
    *ret = fh_make_float(DEG_TO_RAD(x));
    return 0;
}

static int fn_math_atan2(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    if (check_n_args(prog, "math_atan2()", 2, n_args))
        return -1;

    if (!fh_is_float(&args[0]) || !fh_is_float(&args[1])) {
        return fh_set_error(prog, "math_atan2(): expected number, got %s and %s", fh_type_to_str(prog, args[0].type),
                            fh_type_to_str(prog, args[1].type));
    }

    *ret = fh_make_float(atan2(args[0].data.num, args[1].data.num));

    return 0;
}

static int fn_math_ceil(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    FH_REQUIRE_EXACT_ARGS(prog, "math_ceil()", 1, n_args);

    if (fh_is_integer(&args[0])) {
        *ret = fh_make_integer(args[0].data.i);
        return 0;
    }
    if (fh_is_float(&args[0])) {
        *ret = fh_make_float(ceil(args[0].data.num));
        return 0;
    }
    return fh_set_error(prog, "math_ceil(): expected number/integer, got %s", fh_type_to_str(prog, args[0].type));
}

static int fn_math_floor(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    FH_REQUIRE_EXACT_ARGS(prog, "math_floor()", 1, n_args);

    if (fh_is_integer(&args[0])) {
        *ret = fh_make_integer(args[0].data.i);
        return 0;
    }
    if (fh_is_float(&args[0])) {
        *ret = fh_make_float(floor(args[0].data.num));
        return 0;
    }
    return fh_set_error(prog, "math_floor(): expected number/integer, got %s", fh_type_to_str(prog, args[0].type));
}

static int fn_math_fmod(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    if (check_n_args(prog, "math_fmod()", 2, n_args))
        return -1;

    if (!fh_is_float(&args[0]) || !fh_is_float(&args[1])) {
        return fh_set_error(prog, "math_fmod(): expected number, got %s and %s", fh_type_to_str(prog, args[0].type),
                            fh_type_to_str(prog, args[1].type));
    }

    *ret = fh_make_float(fmod(args[0].data.num, args[1].data.num));
    return 0;
}

static int fn_math_frexp(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    if (check_n_args(prog, "math_frexp()", 1, n_args))
        return -1;

    if (!fh_is_number(&args[0])) {
        return fh_set_error(prog, "math_frexp(): expected number, got %s", fh_type_to_str(prog, args[0].type));
    }

    double fract_part = 0;
    int e = 0;
    fract_part = frexp(fh_to_double(&args[0]), &e);

    int pin_state = fh_get_pin_state(prog);
    struct fh_array *arr = fh_make_array(prog, true);
    const struct fh_value fp = fh_new_float(fract_part);
    const struct fh_value ip = fh_make_float(e);

    struct fh_value *new_items = fh_grow_array_object(prog, arr, 2);
    if (!new_items)
        return fh_set_error(prog, "out of memory");

    arr->items[1] = fp;
    arr->items[0] = ip;

    struct fh_value v = fh_new_array(prog);
    v.data.obj = arr;

    *ret = v;
    fh_restore_pin_state(prog, pin_state);
    return 0;
}

static int fn_math_huge(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    UNUSED(args);
    *ret = fh_make_integer(HUGE_VAL);
    return 0;
}

static int fn_math_ldexp(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    FH_REQUIRE_EXACT_ARGS(prog, "math_ldexp()", 2, n_args);

    if (!fh_is_number(&args[0]) || !fh_is_number(&args[1])) {
        return fh_set_error(prog, "math_ldexp(): expected numbers as arguments");
    }

    int32_t n32;
    if (fh_arg_int32(prog, &args[1], "math_ldexp()", 1, &n32) < 0) return -1;

    *ret = fh_new_float(ldexp(fh_to_double(&args[0]), n32));
    return 0;
}

static int fn_math_clamp(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    FH_REQUIRE_EXACT_ARGS(prog, "math_clamp()", 3, n_args);

    if (!fh_is_number(&args[0]) || !fh_is_number(&args[1]) || !fh_is_number(&args[2]))
        return fh_set_error(prog, "math_clamp(): expected 3 numbers|integers");

    double a;
    if (fh_arg_double(prog, &args[0], "math_clamp()", 0, &a) < 0) return -1;
    double x;
    if (fh_arg_double(prog, &args[1], "math_clamp()", 1, &x) < 0) return -1;
    double y;
    if (fh_arg_double(prog, &args[2], "math_clamp()", 2, &y) < 0) return -1;

    *ret = fh_new_float(MAX(x, MIN(y, a)));
    return 0;
}

static int fn_math_max(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    FH_REQUIRE_EXACT_ARGS(prog, "math_max()", 2, n_args);


    if (!fh_is_number(&args[0]) || !fh_is_number(&args[1])) {
        return fh_set_error(prog, "math_max(): expected number|integer, got %s and %s",
                            fh_type_to_str(prog, args[0].type), fh_type_to_str(prog, args[1].type));
    }

    double x;
    if (fh_arg_double(prog, &args[0], "math_max()", 0, &x) < 0) return -1;
    double y;
    if (fh_arg_double(prog, &args[1], "math_max()", 1, &y) < 0) return -1;

    *ret = fh_make_float(MAX(x, y));
    return 0;
}

static int fn_math_min(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    FH_REQUIRE_EXACT_ARGS(prog, "math_min()", 2, n_args);

    if (!fh_is_number(&args[0]) || !fh_is_number(&args[1])) {
        return fh_set_error(prog, "math_min(): expected number, got %s and %s", fh_type_to_str(prog, args[0].type),
                            fh_type_to_str(prog, args[1].type));
    }

    *ret = fh_make_float(MIN(fh_to_double(&args[0]), fh_to_double(&args[1])));
    return 0;
}

static int fn_math_modf(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    FH_REQUIRE_EXACT_ARGS(prog, "math_modf()", 1, n_args);

    if (!fh_is_number(&args[0])) {
        return fh_set_error(prog, "math_modf(): expected number, got %s", fh_type_to_str(prog, args[0].type));
    }

    double fract_part = 0, int_part = 0;
    fract_part = modf(fh_to_double(&args[0]), &int_part);

    int pin_state = fh_get_pin_state(prog);
    struct fh_array *arr = fh_make_array(prog, true);
    const struct fh_value fp = fh_new_float(fract_part);
    const struct fh_value ip = fh_make_float(int_part);

    struct fh_value *new_items = fh_grow_array_object(prog, arr, 2);
    if (!new_items)
        return fh_set_error(prog, "out of memory");

    arr->items[1] = fp;
    arr->items[0] = ip;

    struct fh_value v = fh_new_array(prog);
    v.data.obj = arr;

    *ret = v;
    fh_restore_pin_state(prog, pin_state);
    return 0;
}

static int fn_math_pi(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    FH_REQUIRE_EXACT_ARGS(prog, "math_pi()", 0, n_args);
    *ret = fh_make_float(M_PI);
    return 0;
}

static int fn_math_flt_epsilon(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    UNUSED(args);

    *ret = fh_make_float(FLT_EPSILON);
    return 0;
}

static int fn_math_pow(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    if (check_n_args(prog, "math_pow()", 2, n_args))
        return -1;

    if (!fh_is_number(&args[0]) || !fh_is_number(&args[1])) {
        return fh_set_error(prog, "math_pow(): expected two numbers, got %s and %s", fh_type_to_str(prog, args[0].type),
                            fh_type_to_str(prog, args[1].type));
    }

    *ret = fh_make_float(pow(fh_to_double(&args[0]), fh_to_double(&args[1])));
    return 0;
}

static uint32_t rand_uniform(uint32_t range) {
    uint32_t x;
    const uint32_t limit = UINT32_MAX - (UINT32_MAX % range);
    do {
        x = mt19937_next32(mt19937_generator);
    } while (x >= limit);
    return x % range;
}

static int fn_math_random(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    if (n_args > 2)
        return fh_set_error(prog, "math_random(): expected 0, 1 or 2 arguments");

    /* math_random() -> float [0,1) */
    if (n_args == 0) {
        const uint32_t r = mt19937_next32(mt19937_generator);
        *ret = fh_make_float((double) r / (double) UINT32_MAX);
        return 0;
    }

    /* Validate args are numbers */
    if (!fh_is_number(&args[0]) || (n_args == 2 && !fh_is_number(&args[1])))
        return fh_set_error(prog, "math_random(): arguments must be numbers");

    /* math_random(n) -> int [1..n] */
    if (n_args == 1) {
        int32_t max32;
        if (fh_arg_int32(prog, &args[0], "math_random()", 0, &max32) < 0) return -1;
        const int max = (int) max32;
        if (max <= 0)
            return fh_set_error(prog, "math_random(): argument must be > 0");

        const uint32_t r = rand_uniform((uint32_t) max);
        *ret = fh_make_float((double) (r + 1));
        return 0;
    }

    /* math_random(min, max) -> int [min..max] */
    int32_t min32, max32;
    if (fh_arg_int32(prog, &args[0], "math_random()", 0, &min32) < 0) return -1;
    if (fh_arg_int32(prog, &args[1], "math_random()", 1, &max32) < 0) return -1;

    const int min = (int) min32;
    const int max = (int) max32;

    if (min > max)
        return fh_set_error(prog, "math_random(): min must be <= max");

    const int64_t diff = (int64_t) max - (int64_t) min;
    if (diff < 0) return fh_set_error(prog, "math_random(): min must be <= max");
    if (diff >= (int64_t) UINT32_MAX) return fh_set_error(prog, "math_random(): range too large");
    const uint32_t range = (uint32_t) (diff + 1);

    const uint32_t r = rand_uniform(range);

    *ret = fh_make_float((double) (min + r));
    return 0;
}

static int fn_math_randomseed(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    uint32_t seed;

    if (n_args == 0) {
        seed = (uint32_t) time(NULL);
    } else if (n_args == 1 && fh_is_float(&args[0])) {
        seed = (uint32_t) fh_get_float(&args[0]);
    } else {
        return fh_set_error(prog, "math_randomseed(): expected 0 or 1 number");
    }

    mt19937_seed(mt19937_generator, seed);
    *ret = fh_make_null();
    return 0;
}

static int fn_math_sin(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    FH_REQUIRE_EXACT_ARGS(prog, "math_sin()", 1, n_args);
    double x;
    if (fh_arg_double(prog, &args[0], "math_sin()", 0, &x) < 0) return -1;
    *ret = fh_make_float(sin(x));
    return 0;
}

static int fn_math_sinh(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    FH_REQUIRE_EXACT_ARGS(prog, "math_sinh()", 1, n_args);
    double x;
    if (fh_arg_double(prog, &args[0], "math_sinh()", 0, &x) < 0) return -1;
    *ret = fh_make_float(sinh(x));
    return 0;
}

static int fn_math_sqrt(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    FH_REQUIRE_EXACT_ARGS(prog, "math_sqrt()", 1, n_args);
    double x;
    if (fh_arg_double(prog, &args[0], "math_sqrt()", 0, &x) < 0) return -1;
    *ret = fh_make_float(sqrt(x));
    return 0;
}

static int fn_math_tan(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    FH_REQUIRE_EXACT_ARGS(prog, "math_tan()", 1, n_args);
    double x;
    if (fh_arg_double(prog, &args[0], "math_tan()", 0, &x) < 0) return -1;
    *ret = fh_make_float(tan(x));
    return 0;
}

static int fn_math_tanh(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    FH_REQUIRE_EXACT_ARGS(prog, "math_tanh()", 1, n_args);
    double x;
    if (fh_arg_double(prog, &args[0], "math_tanh()", 0, &x) < 0) return -1;
    *ret = fh_make_float(tanh(x));
    return 0;
}

static int fn_math_maxval(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    UNUSED(args);
    if (check_n_args(prog, "math_maxval()", 0, n_args))
        return -1;

    *ret = fh_new_float(DBL_MAX);
    return 0;
}

/*********** End Math functions ***********/

/*********** I/O functions ***********/

static int fn_io_tar_open(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    if (n_args < 1 || n_args > 2) {
        return fh_set_error(prog, "io_tar_open(): expected 1 or 2 arguments, got %d", n_args);
    }
    if (!fh_is_string(&args[0])) {
        return fh_set_error(prog, "io_tar_open(): expected tar path (string)");
    }

    const char *path = fh_get_string(&args[0]);
    const char *mode = fh_optstring(args, n_args, 1, "r");

    mtar_t *tar = malloc(sizeof(mtar_t));

    if (mtar_open(tar, path, mode) != MTAR_ESUCCESS) {
        free(tar);
        return fh_set_error(prog, "Couldn't open tar file at location: %s", path);
    }

    *ret = fh_new_c_obj(prog, tar, NULL, FH_IO_TAR_STRUCT_ID);
    return 0;
}

static int fn_io_tar_read(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    if (n_args != 2) {
        return fh_set_error(prog, "Invalid number of arguments");
    }
    if (!fh_is_c_obj_of_type(&args[0], FH_IO_TAR_STRUCT_ID)) {
        return fh_set_error(prog, "Expected tar object as first argument");
    }
    if (!fh_is_string(&args[1])) {
        return fh_set_error(prog, "Expected string as second argument");
    }

    mtar_t *tar = fh_get_c_obj_value(&args[0]);
    const char *file = fh_get_string(&args[1]);

    mtar_header_t h;

    int err = mtar_find(tar, file, &h);
    if (err != MTAR_ESUCCESS) {
        return fh_set_error(prog, "Couldn't read file: %s in tar", file);
    }
    char *c = malloc((size_t) h.size + 1);
    if (!c) {
        return fh_set_error(prog, "io_tar_read(): out of memory");
    }
    c[h.size] = 0;
    c[h.size] = 0;
    err = mtar_read_data(tar, c, h.size);
    if (err != MTAR_ESUCCESS) {
        free(c);
        return fh_set_error(prog, "Couldn't read file: %s", file);
    }

    *ret = fh_new_string(prog, c);
    free(c);
    return 0;
}

static int fn_io_tar_list(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    FH_REQUIRE_EXACT_ARGS(prog, "io_tar_list()", 1, n_args);

    if (!fh_is_c_obj_of_type(&args[0], FH_IO_TAR_STRUCT_ID)) {
        return fh_set_error(prog, "Expected tar object as first argument");
    }

    struct fh_value arr = fh_new_array(prog);
    const struct fh_array *arr_val = GET_VAL_ARRAY(&arr);

    mtar_t *tar = fh_get_c_obj_value(&args[0]);
    mtar_header_t h;

    size_t len = 0;
    while ((mtar_read_header(tar, &h)) != MTAR_ENULLRECORD) {
        fh_grow_array(prog, &arr, len | 1);
        arr_val->items[len++] = fh_new_string(prog, h.name);
        mtar_next(tar);
    }

    *ret = arr;
    return 0;
}

static int fn_io_tar_write_header(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    FH_REQUIRE_EXACT_ARGS(prog, "io_tar_write_header()", 3, n_args);

    if (!fh_is_c_obj_of_type(&args[0], FH_IO_TAR_STRUCT_ID))
        return fh_set_error(prog, "Expected tar object as first argument");
    if (!fh_is_string(&args[1]))
        return fh_set_error(prog, "Expected string (file name) as second argument");

    int32_t size32;
    if (fh_arg_int32(prog, &args[2], "io_tar_write_header()", 2, &size32) < 0) return -1;
    if (size32 < 0) return fh_set_error(prog, "io_tar_write_header(): size must be >= 0");

    mtar_t *tar = fh_get_c_obj_value(&args[0]);
    const char *file_name = fh_get_string(&args[1]);

    int err = mtar_write_file_header(tar, file_name, (unsigned) size32);
    *ret = fh_new_bool(err == MTAR_ESUCCESS);
    return 0;
}

static int fn_io_tar_write_data(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    FH_REQUIRE_EXACT_ARGS(prog, "io_tar_write_data()", 2, n_args);

    if (!fh_is_c_obj_of_type(&args[0], FH_IO_TAR_STRUCT_ID))
        return fh_set_error(prog, "Expected tar object as first argument");
    if (!fh_is_string(&args[1]))
        return fh_set_error(prog, "Expected string (data) as second argument");

    mtar_t *tar = fh_get_c_obj_value(&args[0]);
    const char *data = fh_get_string(&args[1]);
    const size_t len = strlen(data);

    if (len > UINT32_MAX)
        return fh_set_error(prog, "io_tar_write_data(): data too large");

    const int err = mtar_write_data(tar, data, (unsigned) len);
    *ret = fh_new_bool(err == MTAR_ESUCCESS);
    return 0;
}

static int fn_io_tar_write_finalize(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    UNUSED(n_args);
    if (!fh_is_c_obj_of_type(&args[0], FH_IO_TAR_STRUCT_ID)) {
        return fh_set_error(prog, "Expected tar object as first argument");
    }

    mtar_t *tar = fh_get_c_obj_value(&args[0]);
    mtar_finalize(tar);
    *ret = fh_new_null();
    return 0;
}

static int fn_io_tar_close(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    UNUSED(n_args);
    if (!fh_is_c_obj_of_type(&args[0], FH_IO_TAR_STRUCT_ID)) {
        return fh_set_error(prog, "Expected tar object as first argument");
    }
    mtar_t *tar = fh_get_c_obj_value(&args[0]);
    mtar_close(tar);
    free(tar);
    *ret = fh_new_null();
    return 0;
}

static int fn_io_open(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    if (n_args == 0 || n_args > 2) {
        return fh_set_error(prog, "io_open(): expected 1 or 2 arguments, got %d", n_args);
    }

    if (!fh_is_string(&args[0])) {
        return fh_set_error(prog, "io_open(): expected string, got %s", fh_type_to_str(prog, args[0].type));
    }
    const char *path = fh_get_string(&args[0]);
    const char *mode = "r";
    if (n_args == 2) {
        if (!fh_is_string(&args[1])) {
            return fh_set_error(prog, "io_open(): expected string as the second argument, got %s",
                                fh_type_to_str(prog, args[1].type));
        }
        mode = fh_get_string(&args[1]);
    }

    FILE *fp = fopen(path, mode);
    if (!fp) {
        return fh_set_error(prog, "io_open(): failed to open file: %s", path);
    }

    *ret = fh_new_c_obj(prog, fp, NULL, FH_IO_STRUCT_ID);
    return 0;
}

char *scan_line(char *line) {
    int ch; // as getchar() returns `int`
    long capacity = 0; // capacity of the buffer
    long length = 0; // maintains the length of the string
    char *temp = NULL; // use additional pointer to perform allocations in order to avoid memory leaks

    while (((ch = getchar()) != '\n') && (ch != EOF)) {
        if ((length + 1) >= capacity) {
            // resetting capacity
            if (capacity == 0) {
                capacity = 8;
            } else {
                capacity <<= 1; // double the size
            }

            if ((temp = realloc(line, capacity * sizeof(char))) == NULL) {
                return NULL;
            }

            line = temp;
        }
        line[length] = (char) ch;
        length++;
    }
    if (length == 0) {
        return NULL;
    }
    line[length] = '\0';

    temp = realloc(line, (length + 1) * sizeof(char));
    if (!temp) {
        return line; // keep original buffer; it's still valid
    }
    line = temp;
    return line;
}


static int fn_io_scan_line(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    UNUSED(args);
    FH_REQUIRE_EXACT_ARGS(prog, "io_scan_line()", 0, n_args);

    char *line = NULL;
    line = scan_line(line);

    if (line != NULL) {
        *ret = fh_new_string(prog, line);
        free(line);
    } else {
        *ret = fh_new_string(prog, "");
    }
    return 0;
}

static int fn_io_read(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    if (n_args == 0) {
        size_t max_len = 1024;
        char *read = malloc(max_len);
        if (!read) return fh_set_error(prog, "io_read(): out of memory");

        size_t i = 0;
        int c = 0;
        while ((c = getchar()) != '\n' && c != EOF) {
            if (i + 1 >= max_len) {
                if (max_len > SIZE_MAX / 2) {
                    free(read);
                    return fh_set_error(prog, "io_read(): input too large");
                }
                max_len <<= 1;
                char *tmp = realloc(read, max_len);
                if (!tmp) {
                    free(read);
                    return fh_set_error(prog, "io_read(): out of memory");
                }
                read = tmp;
            }
            read[i++] = (char) c;
        }
        read[i] = '\0';
        *ret = fh_new_string(prog, read);
        free(read);
        return 0;
    }

    FH_REQUIRE_EXACT_ARGS(prog, "io_read()", 1, n_args);

    if (!fh_is_c_obj(&args[0]) || fh_get_c_obj(&args[0])->type != FH_IO_STRUCT_ID)
        return fh_set_error(prog, "io_read(): expected IO handler");

    FILE *fp = fh_get_c_obj_value(&args[0]);
    if (!fp) return fh_set_error(prog, "io_read(): invalid file pointer");

    if (fseek(fp, 0, SEEK_END) != 0)
        return fh_set_error(prog, "io_read(): couldn't seek to end");

    const long len = ftell(fp);
    if (len < 0)
        return fh_set_error(prog, "io_read(): couldn't determine file size");

    rewind(fp);

    char *buf = malloc((size_t) len + 1);
    if (!buf) return fh_set_error(prog, "io_read(): out of memory");

    size_t nread = fread(buf, 1, (size_t) len, fp);
    buf[nread] = '\0';

    if (nread != (size_t) len) {
        free(buf);
        return fh_set_error(prog, "io_read(): couldn't read the file");
    }

    *ret = fh_new_string(prog, buf);
    free(buf);
    return 0;
}

static int fn_io_write(struct fh_program *prog, struct fh_value *ret,
                       struct fh_value *args, int n_args) {
    if (check_n_args(prog, "io_write()", 2, n_args))
        return -1;

    if (!fh_is_c_obj(&args[0])) {
        return fh_set_error(prog, "io_write(): expected IO handler (cobj), got %s",
                            fh_type_to_str(prog, args[0].type));
    }

    struct fh_c_obj *h = fh_get_c_obj(&args[0]);
    if (!h || h->type != FH_IO_STRUCT_ID) {
        return fh_set_error(prog, "io_write(): expected IO handler (type=%d), got cobj(type=%d)",
                            FH_IO_STRUCT_ID, h ? h->type : 0);
    }

    FILE *fp = (FILE *) fh_get_c_obj_value(&args[0]);
    if (!fp) {
        return fh_set_error(prog, "io_write(): IO handler has NULL FILE*");
    }

    const struct fh_value v = args[1];
    int rc = 0;

    switch (v.type) {
        case FH_VAL_NULL:
            rc = fprintf(fp, "null");
            break;
        case FH_VAL_BOOL:
            rc = fprintf(fp, "%s", v.data.b ? "true" : "false");
            break;
        case FH_VAL_FLOAT: {
            const double d = v.data.num;
            if (isnan(d)) rc = fprintf(fp, "NaN");
            else if (!isfinite(d)) rc = fprintf(fp, "%sInfinity", d < 0.0 ? "-" : "+");
            else rc = fprintf(fp, "%g", d);
            break;
        }
        case FH_VAL_INTEGER:
            rc = fprintf(fp, "%" PRId64, (int64_t) v.data.i);
            break;
        case FH_VAL_STRING: {
            const char *s = fh_get_string(&v);
            rc = fprintf(fp, "%s", s ? s : "");
            break;
        }
        default:
            return fh_set_error(prog, "io_write(): cannot write type: %s",
                                fh_type_to_str(prog, v.type));
    }

    if (rc < 0) {
        return fh_set_error(prog, "io_write(): I/O error: %s", strerror(errno));
    }

    *ret = fh_new_null();
    return 0;
}

static int fn_io_close(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    if (check_n_args(prog, "io_close()", 1, n_args))
        return -1;

    if (!fh_is_c_obj(&args[0]) || fh_get_c_obj(&args[0])->type != FH_IO_STRUCT_ID)
        return fh_set_error(prog, "Expected IO handler");

    FILE *fp = fh_get_c_obj_value(&args[0]);

    const int close = fclose(fp);
    *ret = fh_new_bool(close == 0 ? true : false);

    return 0;
}


static int fn_io_seek(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    if (check_n_args(prog, "io_seek()", 3, n_args))
        return -1;

    if (!fh_is_c_obj(&args[0]) || fh_get_c_obj(&args[0])->type != FH_IO_STRUCT_ID)
        return fh_set_error(prog, "Expected IO handler");

    FILE *fp = fh_get_c_obj_value(&args[0]);
    if (!fh_is_number(&args[1])) {
        return fh_set_error(prog, "expected number for the second argument, got: %s",
                            fh_type_to_str(prog, args[1].type));
    }
    int32_t off32;
    if (fh_arg_int32(prog, &args[1], "io_seek()", 1, &off32) < 0) return -1;
    const int offset = (int) off32;
    if (!fh_is_string(&args[2])) {
        return fh_set_error(prog, "expected string for the second argument, got: %s",
                            fh_type_to_str(prog, args[2].type));
    }
    const char *whence = GET_OBJ_STRING_DATA(args[2].data.obj);

    if (strcmp(whence, "set") == 0) {
        *ret = fh_make_bool(fseek(fp, offset, SEEK_SET) == 0 ? true : false);
    } else if (strcmp(whence, "cur") == 0) {
        *ret = fh_make_bool(fseek(fp, offset, SEEK_CUR) == 0 ? true : false);
    } else if (strcmp(whence, "end") == 0) {
        *ret = fh_make_bool(fseek(fp, offset, SEEK_END) == 0 ? true : false);
    } else {
        return fh_set_error(prog, "expected 'set', 'cur' or 'end', got: %s", whence);
    }
    return 0;
}

static int fn_io_remove(struct fh_program *prog,
                        struct fh_value *ret, struct fh_value *args, int n_args) {
    FH_REQUIRE_EXACT_ARGS(prog, "io_remove()", 1, n_args);

    if (!fh_is_string(&args[0]))
        return fh_set_error(prog, "Illegal parameter, expected filename:string");
    const char *filename = fh_get_string(&args[0]);

    const int err = remove(filename);
    if (err != 0)
        return fh_set_error(prog, "Couldn't remove file %s\n", filename);

    *ret = fh_new_bool(true);
    return 0;
}

static int fn_io_rename(struct fh_program *prog,
                        struct fh_value *ret, struct fh_value *args, int n_args) {
    FH_REQUIRE_EXACT_ARGS(prog, "io_rename()", 2, n_args);

    if (!fh_is_string(&args[0]) || !fh_is_string(&args[1]))
        return fh_set_error(prog, "Illegal parameter, expected old_filename:string and new_filename:string");
    const char *old_filename = fh_get_string(&args[0]);
    const char *new_filename = fh_get_string(&args[1]);

    *ret = fh_new_bool(rename(old_filename, new_filename) == 0 ? true : false);
    return 0;
}

static int fn_io_mkdir(struct fh_program *prog, struct fh_value *ret,
                       struct fh_value *args, int n_args) {
    FH_REQUIRE_EXACT_ARGS(prog, "io_mkdir()", 1, n_args);

    if (!fh_is_string(&args[0]))
        return fh_set_error(prog, "Illegal parameter, expected string");

    const char *name = fh_get_string(&args[0]);
    int err = 0;
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32) || defined(__WIN32__)
    err = _mkdir(name);
#else
    err = mkdir(name, 0777);
#endif
    *ret = fh_new_bool(err == 0 ? true : false);
    return 0;
}

static int fn_io_filetype(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    FH_REQUIRE_EXACT_ARGS(prog, "io_filetype()", 1, n_args);

    if (!fh_is_string(&args[0]))
        return fh_set_error(prog, "Illegal parameter, expected string");

    const char *path = fh_get_string(&args[0]);

#if defined(WIN32) || defined(_WIN32)
    if (_access_s(path, 0) == 0) {
        struct stat s;
        _tstat(path, &s);
        if (s.st_mode & S_IFDIR) {
            *ret = fh_new_string(prog, "directory");
        } else if (s.st_mode & S_IFMT) {
            *ret = fh_new_string(prog, "file");
        } else {
            *ret = fh_new_string(prog, "unknown");
        }
    } else {
        *ret = fh_new_null();
    }

#else

    struct stat s;
    if (stat(path, &s) == 0) {
        if (s.st_mode & S_IFDIR) {
            *ret = fh_new_string(prog, "directory");
        } else if (s.st_mode & S_IFMT) {
            *ret = fh_new_string(prog, "file");
        } else {
            *ret = fh_new_string(prog, "unknown");
        }
    } else {
        *ret = fh_new_null();
    }
#endif
    return 0;
}

/*********** End I/O functions ***********/

/*********** String functions ***********/
static struct fh_value fh_new_string_slice_local(struct fh_program *prog, const char *src, size_t off, size_t n) {
    char *buf = (char *) malloc(n + 1);
    if (!buf) {
        return fh_new_null();
    }
    if (n)
        memcpy(buf, src + off, n);
    buf[n] = '\0';

    struct fh_value v = fh_new_string(prog, buf);
    free(buf);
    return v;
}

static int fn_string_slice(struct fh_program *prog, struct fh_value *ret,
                           struct fh_value *args, int n_args) {
    if (n_args != 2 && n_args != 3)
        return fh_set_error(prog, "string_slice() expects 2 or 3 arguments");

    if (!fh_is_string(&args[0]) || !fh_is_integer(&args[1]) || (n_args == 3 && !fh_is_integer(&args[2])))
        return fh_set_error(prog, "string_slice() expects (string, number[, number])");

    const char *s = fh_get_string(&args[0]);
    const size_t len = strlen(s);

    int32_t start_i32;
    if (fh_arg_int32(prog, &args[1], "string_slice()", 1, &start_i32) < 0) return -1;
    if (start_i32 < 0) return fh_set_error(prog, "Start index out of bounds!");
    if (start_i32 > len) return fh_set_error(prog, "Start index out of bounds!");

    size_t end = len;
    if (n_args == 3) {
        int32_t end_i32;
        if (fh_arg_int32(prog, &args[2], "string_slice()", 2, &end_i32) < 0) return -1;
        if (end_i32 < 0) return fh_set_error(prog, "Invalid end index value");
        end = (size_t) end_i32;
        if (end < start_i32 || end > len)
            return fh_set_error(prog, "Invalid end index value");
    }

    struct fh_value out = fh_new_array(prog);
    if (out.type != FH_VAL_ARRAY)
        return fh_set_error(prog, "out of memory");

    const uint32_t out_len = (n_args == 2) ? 2u : 3u;
    if (!fh_grow_array(prog, &out, out_len))
        return fh_set_error(prog, "out of memory");

    const struct fh_array *a = GET_VAL_ARRAY(&out);

    // prefix: [0..start)
    a->items[0] = fh_new_string_slice_local(prog, s, 0, start_i32);
    if (a->items[0].type == FH_VAL_NULL) return fh_set_error(prog, "out of memory");

    if (n_args == 2) {
        // suffix: [start..len)
        a->items[1] = fh_new_string_slice_local(prog, s, start_i32, len - start_i32);
        if (a->items[1].type == FH_VAL_NULL) return fh_set_error(prog, "out of memory");
    } else {
        // middle: [start..end)
        a->items[1] = fh_new_string_slice_local(prog, s, start_i32, end - start_i32);
        if (a->items[1].type == FH_VAL_NULL) return fh_set_error(prog, "out of memory");

        // suffix: [end..len)
        a->items[2] = fh_new_string_slice_local(prog, s, end, len - end);
        if (a->items[2].type == FH_VAL_NULL) return fh_set_error(prog, "out of memory");
    }

    *ret = out;
    return 0;
}

static int fn_string_split(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    if (check_n_args(prog, "string_split()", 2, n_args))
        return -1;

    if (!fh_is_string(&args[0]) || !fh_is_string(&args[1]))
        return fh_set_error(prog, "expected two strings, got: %s and %s",
                            fh_type_to_str(prog, args[0].type), fh_type_to_str(prog, args[1].type));

    const char *string = fh_get_string(&args[0]);
    const char *delimiter = fh_get_string(&args[1]);

    char *buffer[1024];
    uint32_t arr_len = 0;
    for (uint32_t i = 0; i < 1024; i++) buffer[i] = NULL;

    char *str_cpy = malloc(strlen(string) + 1);
    if (!str_cpy) return fh_set_error(prog, "string_split(): out of memory");
    strcpy(str_cpy, string);

    char *token = strtok(str_cpy, delimiter);
    while (token) {
        if (arr_len >= 1024) {
            for (uint32_t i = 0; i < arr_len; i++) free(buffer[i]);
            free(str_cpy);
            return fh_set_error(prog, "Cannot have more than 1024 split objects");
        }

        buffer[arr_len] = malloc(strlen(token) + 1);
        if (!buffer[arr_len]) {
            for (uint32_t i = 0; i < arr_len; i++) free(buffer[i]);
            free(str_cpy);
            return fh_set_error(prog, "string_split(): out of memory");
        }
        strcpy(buffer[arr_len], token);
        arr_len++;

        token = strtok(NULL, delimiter);
    }
    free(str_cpy);

    struct fh_value arr = fh_new_array(prog);
    struct fh_array *arr_val = GET_VAL_ARRAY(&arr);
    if (!fh_grow_array(prog, &arr, arr_len)) {
        for (uint32_t i = 0; i < arr_len; i++) free(buffer[i]);
        return fh_set_error(prog, "string_split(): out of memory");
    }

    for (uint32_t i = 0; i < arr_len; i++) {
        arr_val->items[i] = fh_new_string(prog, buffer[i]);
        free(buffer[i]);
    }

    *ret = arr;
    return 0;
}

static int fn_string_upper(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    if (check_n_args(prog, "string_upper()", 1, n_args))
        return -1;

    if (!fh_is_string(&args[0]))
        return fh_set_error(prog, "expected string value, got: %s", fh_type_to_str(prog, args[0].type));

    const char *str = GET_VAL_STRING_DATA(&args[0]);
    size_t i = 0, len = strlen(str);
    char *s = malloc(sizeof(char) * len + 1);
    if (!s) return fh_set_error(prog, "string_lower(): out of memory");

    while (i < len) {
        s[i] = (char) toupper(str[i]);
        i++;
    }
    s[len] = '\0';
    *ret = fh_new_string(prog, s);
    free(s);
    return 0;
}

static int fn_string_lower(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    if (check_n_args(prog, "string_lower()", 1, n_args))
        return -1;

    if (!fh_is_string(&args[0]))
        return fh_set_error(prog, "expected string value, got: %s", fh_type_to_str(prog, args[0].type));

    const char *str = GET_VAL_STRING_DATA(&args[0]);
    size_t i = 0, len = strlen(str);
    char *s = malloc(len + 1);
    if (!s) return fh_set_error(prog, "string_lower(): out of memory");

    while (i < len) {
        s[i] = (char) tolower((unsigned char) str[i]);
        i++;
    }
    s[len] = '\0';
    *ret = fh_new_string(prog, s);
    free(s);
    return 0;
}

static int fn_string_match(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    if (check_n_args(prog, "string_match()", 2, n_args))
        return -1;

    if (!fh_is_string(&args[0]) || !fh_is_string(&args[1]))
        return fh_set_error(prog, "expected string values, got: %s and %s",
                            fh_type_to_str(prog, args[0].type), fh_type_to_str(prog, args[1].type)
        );

    const char *input_str = GET_VAL_STRING_DATA(&args[0]);
    const char *input_pat = GET_VAL_STRING_DATA(&args[1]);

    re_t pattern = re_compile(input_pat);
    int match_idx = re_matchp(pattern, input_str);
    if (match_idx != -1) {
        *ret = fh_new_float(match_idx);
        return 0;
    }
    *ret = fh_new_null();
    return 0;
}

static int fn_string_find(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    if (check_n_args(prog, "string_find()", 2, n_args))
        return -1;

    if (!fh_is_string(&args[0]) || !fh_is_string(&args[1]))
        return fh_set_error(prog, "expected string values, got: %s and %s", fh_type_to_str(prog, args[0].type),
                            fh_type_to_str(prog, args[1].type));

    const char *str = GET_VAL_STRING_DATA(&args[0]);
    const char *find = GET_VAL_STRING_DATA(&args[1]);

    const char *r = strstr(str, find);
    *ret = fh_new_integer(r ? (int)(r - str) : -1);
    return 0;
}

static void reverse_string(char *str) {
    const size_t len = strlen(str);
    if (len == 0)
        return;

    /* get range */
    char *start = str;
    char *end = start + len - 1; /* -1 for \0 */
    char temp;

    /* reverse */
    while (end > start) {
        /* swap */
        temp = *start;
        *start = *end;
        *end = temp;

        /* move */
        ++start;
        --end;
    }
}

static int fn_string_reverse(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    if (check_n_args(prog, "string_reverse()", 1, n_args))
        return -1;

    if (!fh_is_string(&args[0]))
        return fh_set_error(prog, "expected string values, got: %s", fh_type_to_str(prog, args[0].type));

    const char *str = GET_VAL_STRING_DATA(&args[0]);

    /* We have to alloc a new space in memory because otherwise there's no way to avoid this:
     * let a = "hi";
     * let b = string_reverse(a);
     * b becomes "ih" but 'a' as well!
     */
    char *reverse = malloc(sizeof(char) * strlen(str) + 1);
    strcpy(reverse, str);

    reverse_string(reverse);

    *ret = fh_new_string(prog, reverse);
    free(reverse);
    return 0;
}

static char *substr(char const *input, size_t start, size_t len) {
    char *ret = malloc(len + 1);
    if (!ret) return NULL;
    memcpy(ret, input + start, len);
    ret[len] = '\0';
    return ret;
}

static int fn_string_substr(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    if (check_n_args(prog, "string_substr()", 3, n_args))
        return -1;

    if (!fh_is_string(&args[0]) || !fh_is_integer(&args[1]) || !fh_is_integer(&args[2]))
        return fh_set_error(prog, "expected string, integer and integer values, got: %s %s and %s",
                            fh_type_to_str(prog, args[0].type),
                            fh_type_to_str(prog, args[1].type), fh_type_to_str(prog, args[2].type));

    const char *str = GET_VAL_STRING_DATA(&args[0]);
    int32_t start32, len32;
    if (fh_arg_int32(prog, &args[1], "string_substr()", 1, &start32) < 0) return -1;
    if (fh_arg_int32(prog, &args[2], "string_substr()", 2, &len32) < 0) return -1;

    const int start = (int) start32;
    const int len = (int) len32;
    if (len < 0 || start < 0)
        return fh_set_error(prog, "cannot have a negative start or length");
    if (start > (int) strlen(str))
        return fh_set_error(prog, "start index out of bounds");
    char *ret_str = substr(str, start, len);
    *ret = fh_new_string(prog, ret_str);
    free(ret_str);
    return 0;
}

static int fn_string_join(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    if (n_args < 2) {
        return fh_set_error(prog, "Expected at least 2 arguments of type string for string_join()\n");
    }

    if (!fh_is_string(&args[0]))
        return fh_set_error(prog, "Expected string for the first parameter, got %s\n",
                            fh_type_to_str(prog, args[0].type));

    const char *join = GET_OBJ_STRING_DATA((&args[0])->data.obj);
    size_t join_len = strlen(join);

    // Validate all args and compute total length
    size_t total = 0;
    for (int i = 1; i < n_args; i++) {
        if (!fh_is_string(&args[i])) {
            return fh_set_error(prog, "Expected string for parameter %d, got %s\n", i,
                                fh_type_to_str(prog, args[i].type));
        }
        total += strlen(GET_OBJ_STRING_DATA((&args[i])->data.obj));
        if (n_args == 2) {
            // old behavior: always append join once
            total += join_len;
        } else {
            // join only between elements
            if (i < n_args - 1) total += join_len;
        }
    }

    char *res = malloc(total + 1);
    if (!res) return fh_set_error(prog, "string_join(): out of memory");
    char *p = res;

    for (int i = 1; i < n_args; i++) {
        const char *val = GET_OBJ_STRING_DATA((&args[i])->data.obj);
        size_t val_len = strlen(val);

        memcpy(p, val, val_len);
        p += val_len;

        if (n_args == 2) {
            memcpy(p, join, join_len);
            p += join_len;
        } else {
            if (i < n_args - 1) {
                memcpy(p, join, join_len);
                p += join_len;
            }
        }
    }

    *p = '\0';
    *ret = fh_new_string(prog, res);
    free(res);
    return 0;
}

static int fn_string_char(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    if (check_n_args(prog, "string_char()", 1, n_args))
        return -1;

    if (fh_is_string(&args[0])) {
        const char *c = GET_VAL_STRING_DATA(&args[0]);
        *ret = fh_new_integer(*c - '0');
    } else if (fh_is_integer(&args[0])) {
        int32_t d32;
        if (fh_arg_int32(prog, &args[0], "string_char()", 0, &d32) < 0) return -1;
        const int c = (int) d32 + '0';
        char ret_str[32];
        snprintf(ret_str, 32, "%c", c);

        *ret = fh_new_string(prog, ret_str);
    } else
        return fh_set_error(prog, "expected string or integer value, got: %s", fh_type_to_str(prog, args[0].type));

    return 0;
}

static int fn_string_format(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    if (n_args == 0 || !fh_is_string(&args[0])) {
        *ret = fh_make_null();
        return 0;
    }

    const char *format = fh_get_string(&args[0]);
    int next_arg = 1;

    char buffer[MAX_ITEM];
    size_t occupied = 0;

    for (const char *c = format; *c != '\0'; c++) {
        if (*c != '%') {
            if (occupied + 1 >= MAX_ITEM)
                return fh_set_error(prog, "string_format(): output too long");
            buffer[occupied++] = *c;
            continue;
        }

        c++;
        if (*c == '\0')
            return fh_set_error(prog, "string_format(): dangling '%%' at end");

        if (next_arg >= n_args)
            return fh_set_error(prog, "string_format(): no argument supplied for '%%%c'", *c);

        size_t remaining = (occupied < MAX_ITEM) ? (MAX_ITEM - occupied) : 0;
        if (remaining == 0)
            return fh_set_error(prog, "string_format(): output too long");

        int written = 0;
        switch (*c) {
            case 'd':
                if (!fh_is_number(&args[next_arg]))
                    return fh_set_error(prog, "string_format(): invalid argument type for '%%%c'", *c);
                written = snprintf(buffer + occupied, remaining, "%lld",
                                   (long long)fh_as_i64(prog, &args[next_arg], "string_format()"));
                break;

            case 'u':
            case 'x': {
                if (!fh_is_number(&args[next_arg]))
                    return fh_set_error(prog, "string_format(): invalid argument type for '%%%c'", *c);
                unsigned long long v = (unsigned long long) fh_as_i64(prog, &args[next_arg], "string_format()");
                written = snprintf(buffer + occupied, remaining, (*c == 'u') ? "%llu" : "%llx", v);
                break;
            }

            case 'f':
            case 'g':
                if (!fh_is_float(&args[next_arg]))
                    return fh_set_error(prog, "string_format(): invalid argument type for '%%%c'", *c);
                written = snprintf(buffer + occupied, remaining, (*c == 'f') ? "%f" : "%g", args[next_arg].data.num);
                break;

            case 's':
            case 'c':
                if (!fh_is_string(&args[next_arg]))
                    return fh_set_error(prog, "string_format(): invalid argument type for '%%%c'", *c);
                written = snprintf(buffer + occupied, remaining, "%s", GET_VAL_STRING_DATA(&args[next_arg]));
                break;

            case '%':
                written = snprintf(buffer + occupied, remaining, "%%");
                next_arg--;
                break;

            default:
                return fh_set_error(prog, "string_format(): invalid format specifier: '%%%c'", *c);
        }

        if (written < 0 || (size_t) written >= remaining)
            return fh_set_error(prog, "string_format(): output too long");

        occupied += (size_t) written;
        next_arg++;
    }

    buffer[occupied] = '\0';
    *ret = fh_new_string(prog, buffer);
    return 0;
}

static inline size_t trimwhitespace(char *out, const size_t len, const char *str) {
    if (len == 0)
        return 0;

    // Trim leading space
    while (isspace((unsigned char) *str)) str++;

    if (*str == 0) {
        // All spaces?
        *out = 0;
        return 1;
    }

    // Trim trailing space
    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char) *end)) end--;
    end++;

    // Set output size to minimum of trimmed string length and buffer size minus 1
    size_t out_size = (end - str) < len - 1 ? (end - str) : len - 1;

    // Copy trimmed string and add null terminator
    memcpy(out, str, out_size);
    out[out_size] = 0;

    return out_size;
}

static int fn_string_trim(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    FH_REQUIRE_MIN_ARGS(prog, "string_trim()", 1, n_args);

    if (!fh_is_string(&args[0]))
        return fh_set_error(prog, "expected string value, got: %s", fh_type_to_str(prog, args[0].type));

    const char *input_str = GET_VAL_STRING_DATA(&args[0]);
    const size_t len = strlen(input_str);

    char *out = malloc(len + 1);
    if (!out) return fh_set_error(prog, "string_trim(): out of memory");

    trimwhitespace(out, len + 1, input_str);

    *ret = fh_new_string(prog, out);
    free(out);
    return 0;
}

/*********** End String functions ***********/

/*********** OS functions ***********/
static long timedifference_usec(const struct timeval t0, const struct timeval t1) {
    return (t1.tv_sec - t0.tv_sec) * 1000000.0 + (t1.tv_usec - t0.tv_usec);
}

static fh_c_obj_gc_callback os_time_gc(struct timeval *t) {
    free(t);
    return (fh_c_obj_gc_callback) 1;
}

static int fn_os_time(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    UNUSED(args);
    FH_REQUIRE_EXACT_ARGS(prog, "os_time()", 0, n_args);

    struct timeval *t = malloc(sizeof(struct timeval));
    if (!t) return fh_set_error(prog, "os_time(): out of memory");

    gettimeofday(t, NULL);
    *ret = fh_new_c_obj(prog, t, (fh_c_obj_gc_callback) os_time_gc, FH_TIME_STRUCT_ID);
    return 0;
}

static int fn_os_difftime(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    if (check_n_args(prog, "os_difftime()", 2, n_args))
        return -1;

    if (!fh_is_c_obj_of_type(&args[0], FH_TIME_STRUCT_ID) || !fh_is_c_obj_of_type(&args[1], FH_TIME_STRUCT_ID))
        return fh_set_error(prog, "expected two time objects");

    const struct timeval *start = (struct timeval *) fh_get_c_obj_value(&args[0]);
    const struct timeval *final = (struct timeval *) fh_get_c_obj_value(&args[1]);
    *ret = fh_new_integer(timedifference_usec(*start, *final));
    return 0;
}

static int fn_os_localtime(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    UNUSED(args);
    FH_REQUIRE_EXACT_ARGS(prog, "os_localtime()", 0, n_args);

    time_t rawtime;
    time(&rawtime);

    struct tm *timeinfo = localtime(&rawtime);
    *ret = fh_new_string(prog, asctime(timeinfo));
    return 0;
}

static int fn_os_command(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    if (check_n_args(prog, "os_command()", 1, n_args))
        return -1;
    if (!fh_is_string(&args[0]))
        return fh_set_error(prog, "expected string value, got: %s", fh_type_to_str(prog, args[0].type));

    const char *command = fh_get_string(&args[0]);
    const int rc = system(command);
    *ret = fh_make_bool(rc == 0);
    return 0;
}

static int fn_os_getenv(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    if (check_n_args(prog, "os_getenv()", 1, n_args))
        return -1;
    if (!fh_is_string(&args[0]))
        return fh_set_error(prog, "expected string value, got: %s", fh_type_to_str(prog, args[0].type));

    const char *env = fh_get_string(&args[0]);
    const char *path = getenv(env);
    if (path) {
        *ret = fh_new_string(prog, path);
        return 0;
    }
    *ret = fh_new_null();
    return 0;
}

static int fn_os_getOS(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    UNUSED(args);
    if (check_n_args(prog, "os_getOS()", 0, n_args))
        return -1;

    *ret = fh_new_string(prog, FH_OS);
    return 0;
}

/*********** End OS functions ***********/
static int fn_getversion(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    UNUSED(args);
    FH_REQUIRE_EXACT_ARGS(prog, "getversion()", 0, n_args);

    *ret = fh_new_string(prog, FH_VERSION);
    return 0;
}

static int fn_tostring(struct fh_program *prog, struct fh_value *ret,
                       struct fh_value *args, int n_args) {
    if (check_n_args(prog, "tostring()", 1, n_args)) return -1;

    if (!fh_is_number(&args[0]))
        return fh_set_error(prog, "tostring(): expected number/integer");

    if (fh_is_integer(&args[0])) {
        printf("Converting integer to string\n");
        int needed = snprintf(NULL, 0, "%lld", (long long)args[0].data.i);
        char *buf = malloc((size_t) needed + 1);
        if (!buf) return fh_set_error(prog, "tostring(): out of memory");
        snprintf(buf, (size_t)needed + 1, "%lld", (long long)args[0].data.i);
        *ret = fh_new_string(prog, buf);
        free(buf);
        return 0;
    }

    int needed = snprintf(NULL, 0, "%g", args[0].data.num);
    char *buf = malloc((size_t) needed + 1);
    if (!buf) return fh_set_error(prog, "tostring(): out of memory");
    snprintf(buf, (size_t)needed + 1, "%g", args[0].data.num);
    *ret = fh_new_string(prog, buf);
    free(buf);
    return 0;
}


static int fn_tonumber(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    if (check_n_args(prog, "tonumber()", 1, n_args))
        return -1;

    if (!fh_is_string(&args[0]))
        return fh_set_error(prog, "tonumber(): expected string, got: %s", fh_type_to_str(prog, args[0].type));

    const char *str = GET_VAL_STRING_DATA(&args[0]);
    if (!str) {
        *ret = fh_make_null();
        return 0;
    }

    errno = 0;
    char *end = NULL;
    const double d = strtod(str, &end);

    if (end == str) {
        *ret = fh_make_null();
        return 0;
    }

    // allow trailing whitespace only
    while (*end && isspace((unsigned char) *end)) end++;

    if (*end != '\0') {
        *ret = fh_make_null();
        return 0;
    }

    if (errno == ERANGE) {
        return fh_set_error(prog, "tonumber(): number out of range");
    }

    *ret = fh_new_float(d);
    return 0;
}

static int fn_tointeger(struct fh_program *prog, struct fh_value *ret,
                        struct fh_value *args, int n_args) {
    if (check_n_args(prog, "tointeger()", 1, n_args)) return -1;

    if (!fh_is_number(&args[0]))
        return fh_set_error(prog, "tointeger(): expected number/integer");

    const int64_t x = fh_as_i64(prog, &args[0], "tointeger()");
    if (!fh_running) {
        return -1;
    }
    *ret = fh_new_integer(x);
    return 0;
}

static int fn_gc(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    (void) args;
    (void) n_args;

    fh_collect_garbage(prog);
    *ret = fh_new_null();
    return 0;
}

static int fn_gc_frequency(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    FH_REQUIRE_EXACT_ARGS(prog, "gc_frequency()", 1, n_args);

    if (!fh_is_number(&args[0]))
        return fh_set_error(prog, "gc_frequency(): expected number/integer");

    const int64_t freq = fh_as_i64(prog, &args[0], "gc_frequency()");
    if (!fh_running) return -1;
    if (freq < 0) return fh_set_error(prog, "gc_frequency(): must be >= 0");

    prog->gc_collect_at = (uint64_t) freq;
    *ret = fh_new_null();
    return 0;
}

static int fn_gc_pause(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    FH_REQUIRE_EXACT_ARGS(prog, "gc_pause()", 1, n_args);
    if (!fh_is_bool(&args[0]))
        return fh_set_error(prog, "gc_pause(): expected boolean");
    prog->gc_isPaused = fh_get_bool(&args[0]);
    *ret = fh_new_null();
    return 0;
}

static int fn_gc_info(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    UNUSED(args);
    if (check_n_args(prog, "gc_info()", 0, n_args))
        return fh_set_error(prog, "Expected 0 arguments");
    *ret = fh_new_float(0);
    return 0;
}

static int fn_type(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    if (check_n_args(prog, "type()", 1, n_args))
        return -1;

    *ret = fh_new_string(prog, fh_type_to_str(prog, args[0].type));

    return 0;
}

static int fn_docstring(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    if (check_n_args(prog, "docstring()", 1, n_args))
        return -1;

    if (args[0].type != FH_VAL_CLOSURE) {
        return fh_set_error(prog, "Only closures support docstrings");
    }

    const struct fh_closure *c = (struct fh_closure *) args[0].data.obj;

    *ret = fh_new_string(prog, c->doc_string ? GET_OBJ_STRING_DATA(c->doc_string) : "");
    return 0;
}

/**
 * has(array/map, object);
 * Searches for @object inside an array or a map in O(n) time.
 * If it's found then it returns the found object and an index to it, otherwise
 * returns 'false'.
 */
static int fn_has(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    if (check_n_args(prog, "has()", 2, n_args))
        return -1;

    int pin_state = fh_get_pin_state(prog);
    struct fh_array *ret_arr = fh_make_array(prog, true);
    if (!fh_grow_array_object(prog, ret_arr, 2))
        return fh_set_error(prog, "out of memory");

    struct fh_value new_val = fh_new_array(prog);

    const struct fh_array *arr = GET_VAL_ARRAY(&args[0]);
    if (arr) {
        for (size_t i = 0; i < arr->len; i++) {
            struct fh_value v = arr->items[i];
            if (fh_vals_are_equal(&args[1], &v)) {
                ret_arr->items[0] = v;
                ret_arr->items[1] = fh_new_integer(i);
                new_val.data.obj = ret_arr;

                *ret = new_val;
                fh_restore_pin_state(prog, pin_state);
                return 0;
            }
        }
        *ret = fh_new_bool(false);
        fh_restore_pin_state(prog, pin_state);
        return 0;
    }
    const struct fh_map *map = GET_VAL_MAP(&args[0]);
    if (map) {
        for (uint32_t i = 0; i < map->cap; i++) {
            struct fh_map_entry *e = &map->entries[i];
            if (fh_vals_are_equal(&args[1], &e->key)) {
                ret_arr->items[0] = e->val;
                ret_arr->items[1] = fh_new_integer(i);
                new_val.data.obj = ret_arr;

                *ret = new_val;
                fh_restore_pin_state(prog, pin_state);
                return 0;
            }
        }
        *ret = fh_new_bool(false);
        fh_restore_pin_state(prog, pin_state);
        return 0;
    }
    fh_restore_pin_state(prog, pin_state);
    return fh_set_error(prog, "Expected an array or a map as the second argument.");
}

static bool fh_is_truthy(const struct fh_value *v) {
    switch (v->type) {
        case FH_VAL_NULL: return false;
        case FH_VAL_BOOL: return v->data.b;
        case FH_VAL_FLOAT: return v->data.num != 0.0;
        case FH_VAL_INTEGER: return v->data.i != 0;
        default:
            return v->data.obj != NULL;
    }
}

static int fn_assert(struct fh_program *prog, struct fh_value *ret,
                     struct fh_value *args, int n_args) {
    if (n_args < 1 || n_args > 2)
        return fh_set_error(prog, "assert() expects 1 or 2 arguments");

    if (fh_is_truthy(&args[0])) {
        *ret = fh_new_bool(true);
        return 0;
    }

    // condition repr
    char cond_buf[256];
    fh_value_repr(prog, &args[0], cond_buf, sizeof(cond_buf));

    // message handling
    if (n_args == 2) {
        if (fh_is_string(&args[1])) {
            const char *msg = fh_get_string(&args[1]);
            if (msg && msg[0] != '\0') {
                return fh_set_error(prog, "assert() failed: %s (cond=%s)", msg, cond_buf);
            }
            // empty string => still show condition
            return fh_set_error(prog, "assert() failed (cond=%s)", cond_buf);
        }

        // non-string msg: include its repr too
        char msg_buf[256];
        fh_value_repr(prog, &args[1], msg_buf, sizeof(msg_buf));
        return fh_set_error(prog, "assert() failed (cond=%s, msg=%s)", cond_buf, msg_buf);
    }

    return fh_set_error(prog, "assert() failed (cond=%s)", cond_buf);
}

static int fn_error(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    (void) ret;

    if (check_n_args(prog, "error()", 1, n_args))
        return -1;

    const char *str = GET_VAL_STRING_DATA(&args[0]);
    if (!str)
        return fh_set_error(prog, "error(): argument 1 must be a string");
    return fh_set_error(prog, "%s", str);
}

static int fn_delete(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    if (check_n_args(prog, "delete()", 2, n_args))
        return -1;

    struct fh_array *arr = GET_VAL_ARRAY(&args[0]);
    if (arr) {
        if (!fh_is_number(&args[1]))
            return fh_set_error(prog, "delete(): argument 2 must be a number");
        int32_t idx32;
        if (fh_arg_int32(prog, &args[1], "delete()", 1, &idx32) < 0) return -1;
        if (idx32 < 0) return fh_set_error(prog, "delete(): array index out of bounds: %d", (int) idx32);
        const uint32_t index = (uint32_t) idx32;
        if (index >= arr->len)
            return fh_set_error(prog, "delete(): array index out of bounds: %d", index);
        *ret = arr->items[index];
        if (index + 1 < arr->len)
            memmove(arr->items + index, arr->items + index + 1, (arr->len - (index + 1)) * sizeof(struct fh_value));
        arr->len--;
        return 0;
    }
    struct fh_map *map = GET_VAL_MAP(&args[0]);
    if (map) {
        if (fh_get_map_object_value(map, &args[1], ret) < 0
            || fh_delete_map_object_entry(map, &args[1]) < 0)
            return fh_set_error(prog, "delete(): key not in map");
        return 0;
    }
    return fh_set_error(prog, "delete(): argument 1 must be an array or map, got %s and %s",
                        fh_type_to_str(prog, args[0].type), fh_type_to_str(prog, args[1].type));
}

/**
* Resets a map or an array. Doing this you won't have to reallocate an object.
* ex:
* let map = {};
* while (true) {
*  <.... some code ....>
*  map = {}; # reset map, old way
*  reset(map); # reset map, new way
* }
*/
static int fn_reset(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    if (check_n_args(prog, "reset()", 1, n_args))
        return -1;

    struct fh_map *map = GET_VAL_MAP(&args[0]);
    if (map) {
        fh_reset_map(map);
    } else {
        struct fh_array *arr = GET_VAL_ARRAY(&args[0]);
        if (!arr)
            return fh_set_error(prog, "reset(): argument 1 must be a map or array");
        fh_reset_array(arr);
    }

    *ret = fh_new_null();
    return 0;
}

static int fn_next_key(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    if (check_n_args(prog, "next_key()", 2, n_args))
        return -1;

    struct fh_map *map = GET_VAL_MAP(&args[0]);
    if (!map)
        return fh_set_error(prog, "next_key(): argument 1 must be a map");
    if (fh_next_map_object_key(map, &args[1], ret) < 0)
        return fh_set_error(prog, "next_key(): key not in map, got %s and %s",
                            fh_type_to_str(prog, args[0].type), fh_type_to_str(prog, args[1].type));
    return 0;
}

static int fn_contains_key(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    if (check_n_args(prog, "contains_key()", 2, n_args))
        return -1;

    struct fh_map *map = GET_VAL_MAP(&args[0]);
    if (!map)
        return fh_set_error(prog, "contains_key(): argument 1 must be a map");
    if (fh_get_map_object_value(map, &args[1], ret) < 0) {
        *ret = fh_make_bool(false);
        return 0;
    }
    //printf("key "); print_value(&args[1]); printf(" has value "); print_value(ret); printf("\n");
    *ret = fh_make_bool(true);

    return 0;
}

static int fn_reserve(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    if (check_n_args(prog, "reserve()", -2, n_args)) return -1;


    const bool is_array = fh_is_array(&args[0]);
    const bool is_map = fh_is_map(&args[0]);
    if (!is_array && !is_map)
        return fh_set_error(prog, "reserve(): argument 1 must be an array or map");

    if (!fh_is_number(&args[1]))
        return fh_set_error(prog, "reserve(): argument 2 (capacity) must be a number");

    int32_t cap32;
    if (fh_arg_int32(prog, &args[1], "reserve()", 1, &cap32) < 0) return -1;
    if (cap32 < 0) return fh_set_error(prog, "reserve(): invalid capacity");

    if (is_array) {
        struct fh_array *arr = GET_VAL_ARRAY(&args[0]);
        if (fh_reserve_array_capacity(prog, arr, cap32) < 0)
            return -1;
    } else {
        if (fh_alloc_map_len(&args[0], cap32) < 0)
            return -1;
    }

    *ret = args[0];
    return 0;
}

static int fn_print(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    (void) prog;

    for (int i = 0; i < n_args; i++)
        print_value(&args[i]);
    *ret = fh_make_null();
    return 0;
}


static const struct fh_vm_call_frame *fh_find_last_user_frame(const struct fh_vm *vm) {
    const int n = call_frame_stack_size(&vm->call_stack);
    for (int i = n - 1; i >= 0; --i) {
        const struct fh_vm_call_frame *f = call_frame_stack_item(&vm->call_stack, i);
        if (f && f->closure) return f; // non C-call frame
    }
    return NULL;
}

static void fh_print_src_loc_if_any(const struct fh_program *prog,
                                    const struct fh_vm_call_frame *frame) {
    if (!frame || !frame->closure) {
        putchar('\n');
        return;
    }

    const struct fh_func_def *func_def = frame->closure->func_def;

    const char *file = fh_get_symbol_name(&prog->src_file_names, func_def->code_creation_loc.file_id);

    if (!file) file = "<unknown>";

    printf(" %s:%d:%d\n",
           file,
           func_def->code_creation_loc.line,
           func_def->code_creation_loc.col);
}

static int fn_println(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    for (int i = 0; i < n_args; i++) {
        print_value(&args[i]);
    }

    const struct fh_vm_call_frame *frame = fh_find_last_user_frame(&prog->vm);
    fh_print_src_loc_if_any(prog, frame);

    *ret = fh_make_null();
    return 0;
}

static int fn_printf(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    if (n_args == 0 || !fh_is_string(&args[0]))
        goto end;

    int next_arg = 1;
    for (const char *c = fh_get_string(&args[0]); *c != '\0'; c++) {
        if (*c != '%') {
            putchar(*c);
            continue;
        }
        c++;
        if (*c == '%') {
            putchar('%');
            continue;
        }
        if (next_arg >= n_args)
            return fh_set_error(prog, "printf(): no argument supplied for '%%%c'", *c);

        switch (*c) {
            case 'd':
                if (!fh_is_integer(&args[next_arg]))
                    return fh_set_error(prog, "printf(): invalid argument type for '%%%c'", *c);
                printf("%lld", args[next_arg].data.i);
                break;

            case 'u':
            case 'x':
                if (!fh_is_integer(&args[next_arg]))
                    return fh_set_error(prog, "printf(): invalid argument type for '%%%c'", *c);
                printf((*c == 'u') ? "%llu" : "%llx", (unsigned long long) args[next_arg].data.i);
                break;

            case 'f':
            case 'g':
                if (!fh_is_float(&args[next_arg]))
                    return fh_set_error(prog, "printf(): invalid argument type for '%%%c'", *c);
                printf((*c == 'f') ? "%f" : "%g", args[next_arg].data.num);
                break;

            case 's':
                print_value(&args[next_arg]);
                break;

            default:
                return fh_set_error(prog, "printf(): invalid format specifier: '%%%c'", *c);
        }
        next_arg++;
    }

end:
    *ret = fh_make_null();
    return 0;
}

static int fn_eval(struct fh_program *prog, struct fh_value *ret, struct fh_value *args, int n_args) {
    if (check_n_args(prog, "eval()", 2, n_args))
        return -1;

    if (!fh_is_string(&args[0]) || !fh_is_string(&args[1])) {
        return fh_set_error(prog, "Expected string code and function to call from string code");
    }

    const char *code = fh_get_string(&args[0]);
    const char *fn_name = fh_get_string(&args[1]);

    struct fh_input *in = fh_open_input_string(code);

    if (!in) {
        return fh_set_error(prog, "Couldn't read input string: %s",
                            code);
    }

    struct fh_program *p = fh_new_program();
    if (fh_compile_input(p, in) < 0) {
        return fh_set_error(prog, "Couldn't compile input string: %s",
                            code);
    }

    /*
     * We don't allow passing parameters from program to the string code
     * because this could expose security breaches!
     */
    if (fh_call_function(p, fn_name, NULL, 0, ret) < 0) {
        return fh_set_error(prog, "Couldn't call function %s\n", fn_name);
    }

    // See more about it in fh.h
    if (vec_push(fh_programs_vector, p) != 0) {
        fh_free_program(p);
        return fh_set_error(prog, "eval(): out of memory");
    }
    return 0;
}

#define DEF_FN(name)  { #name, fn_##name }
const struct fh_named_c_func fh_std_c_funcs[] = {
    DEF_FN(math_md5),
    DEF_FN(math_bcrypt_gen_salt),
    DEF_FN(math_bcrypt_hashpw),

    DEF_FN(math_clamp),
    DEF_FN(math_abs),
    DEF_FN(math_acos),
    DEF_FN(math_asin),
    DEF_FN(math_atan),
    DEF_FN(math_atan2),
    DEF_FN(math_ceil),
    DEF_FN(math_cos),
    DEF_FN(math_cosh),
    DEF_FN(math_deg),
    DEF_FN(math_exp),
    DEF_FN(math_floor),
    DEF_FN(math_fmod),
    DEF_FN(math_frexp),
    DEF_FN(math_huge),
    DEF_FN(math_ldexp),
    DEF_FN(math_log),
    DEF_FN(math_log10),
    DEF_FN(math_max),
    DEF_FN(math_min),
    DEF_FN(math_modf),
    DEF_FN(math_pi),
    DEF_FN(math_flt_epsilon),
    DEF_FN(math_pow),
    DEF_FN(math_rad),
    DEF_FN(math_random),
    DEF_FN(math_randomseed),
    DEF_FN(math_sin),
    DEF_FN(math_sinh),
    DEF_FN(math_sqrt),
    DEF_FN(math_tan),
    DEF_FN(math_tanh),
    DEF_FN(math_maxval),

    DEF_FN(io_tar_open),
    DEF_FN(io_tar_read),
    DEF_FN(io_tar_list),
    DEF_FN(io_tar_write_header),
    DEF_FN(io_tar_write_data),
    DEF_FN(io_tar_write_finalize),
    DEF_FN(io_tar_close),
    DEF_FN(io_open),
    DEF_FN(io_read),
    DEF_FN(io_scan_line),
    DEF_FN(io_write),
    DEF_FN(io_close),
    DEF_FN(io_seek),
    DEF_FN(io_rename),
    DEF_FN(io_remove),
    DEF_FN(io_mkdir),
    DEF_FN(io_filetype),

    DEF_FN(string_slice),
    DEF_FN(string_split),
    DEF_FN(string_upper),
    DEF_FN(string_lower),
    DEF_FN(string_find),
    DEF_FN(string_match),
    DEF_FN(string_reverse),
    DEF_FN(string_substr),
    DEF_FN(string_char),
    DEF_FN(string_trim),
    DEF_FN(string_format),
    DEF_FN(string_join),

    DEF_FN(os_time),
    DEF_FN(os_difftime),
    DEF_FN(os_localtime),
    DEF_FN(os_command),
    DEF_FN(os_getenv),
    DEF_FN(os_getOS),

    DEF_FN(eval),
    DEF_FN(has),
    DEF_FN(getversion),
    DEF_FN(gc),
    DEF_FN(gc_info),
    DEF_FN(gc_pause),
    DEF_FN(gc_frequency),
    DEF_FN(tonumber),
    DEF_FN(tointeger),
    DEF_FN(tostring),
    DEF_FN(type),
    DEF_FN(docstring),
    DEF_FN(error),
    DEF_FN(assert),
    DEF_FN(print),
    DEF_FN(println),
    DEF_FN(printf),
    DEF_FN(reset),
    DEF_FN(next_key),
    DEF_FN(contains_key),
    DEF_FN(reserve),
    DEF_FN(delete),
};
const int fh_std_c_funcs_len = sizeof(fh_std_c_funcs) / sizeof(fh_std_c_funcs[0]);


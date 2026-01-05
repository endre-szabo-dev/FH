#include <limits.h>
#include <stdint.h>
#include <stdlib.h> /* For malloc/realloc/free */

#include "vec.h"

/* ---- helpers ---- */

static int vec_mul_overflow_(size_t a, size_t b, size_t *out) {
    if (a == 0 || b == 0) {
        *out = 0;
        return 0;
    }
    if (a > SIZE_MAX / b) return -1;
    *out = a * b;
    return 0;
}

static int vec_bytes_for_cap_(size_t memsz, size_t cap, size_t *out_bytes) {
    if (vec_mul_overflow_(memsz, cap, out_bytes) != 0) return -1;
    return 0;
}

static size_t vec_next_pow2_(size_t x) {
    if (x <= 1) return 1;
    /* round up to next power of two */
    x--;
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;
#if SIZE_MAX > 0xFFFFFFFFu
    x |= x >> 32;
#endif
    return x + 1;
}

/* ---- core ---- */

int vec_reserve_(char **data, size_t *length, size_t *capacity, size_t memsz, size_t n) {
    (void) length;

    if (n <= *capacity) return 0;

    size_t bytes;
    if (vec_bytes_for_cap_(memsz, n, &bytes) != 0) return -1;

    void *p = realloc(*data, bytes);
    if (!p) return -1;

    *data = (char *) p;
    *capacity = n;
    return 0;
}

int vec_reserve_po2_(char **data, size_t *length, size_t *capacity, size_t memsz, size_t n) {
    (void) length;

    if (n <= *capacity) return 0;

    size_t cap2 = vec_next_pow2_(n);
    /* vec_next_pow2_ can overflow to 0 in pathological cases */
    if (cap2 < n) return -1;

    return vec_reserve_(data, length, capacity, memsz, cap2);
}

int vec_expand_(char **data, size_t *length, size_t *capacity, size_t memsz) {
    /* Expand to hold one more element */
    if (*length + 1 < *length) return -1; /* overflow */
    return vec_reserve_po2_(data, length, capacity, memsz, *length + 1);
}

int vec_compact_(char **data, size_t *length, size_t *capacity, size_t memsz) {
    size_t n = *length;
    if (n == *capacity) return 0;

    if (n == 0) {
        free(*data);
        *data = NULL;
        *capacity = 0;
        return 0;
    }

    size_t bytes;
    if (vec_bytes_for_cap_(memsz, n, &bytes) != 0) return -1;

    void *p = realloc(*data, bytes);
    if (!p) return -1;

    *data = (char *) p;
    *capacity = n;
    return 0;
}

int vec_insert_(char **data, size_t *length, size_t *capacity, size_t memsz, size_t idx) {
    /* allow insert at end (idx == length) */
    if (idx > *length) return -1;

    if (vec_expand_(data, length, capacity, memsz) != 0) return -1;

    /* shift right */
    size_t move_count = (*length - idx);
    if (move_count > 0) {
        memmove(*data + (idx + 1) * memsz,
                *data + idx * memsz,
                move_count * memsz);
    }
    return 0;
}

int vec_splice_(char **data, size_t *length, size_t *capacity, size_t memsz, size_t start, size_t count) {
    (void) capacity;

    if (count == 0) return 0;
    if (start > *length) return -1;
    if (count > *length - start) return -1;

    size_t tail = *length - (start + count);
    if (tail > 0) {
        memmove(*data + start * memsz,
                *data + (start + count) * memsz,
                tail * memsz);
    }
    *length -= count;
    return 0;
}

int vec_swapsplice_(char **data, size_t *length, size_t *capacity, size_t memsz, size_t start, size_t count) {
    (void) capacity;

    if (count == 0) return 0;
    if (start > *length) return -1;
    if (count > *length - start) return -1;

    /* swap-remove: copy last 'count' elements into the hole */
    size_t end = start + count;
    size_t n = *length;

    /* If we’re removing from the end, just shrink */
    if (end == n) {
        *length -= count;
        return 0;
    }

    size_t copy_from = n - count;
    /* If regions overlap (when removing near end), use memmove */
    memmove(*data + start * memsz, *data + copy_from * memsz, count * memsz);

    *length -= count;
    return 0;
}

void vec_swap_(char **data, size_t *length, size_t *capacity, size_t memsz, size_t idx1, size_t idx2) {
    (void) length;
    (void) capacity;

    if (idx1 == idx2) return;

    char *a = *data + idx1 * memsz;
    char *b = *data + idx2 * memsz;

    /* VLA-free swap (small buffer on stack if memsz is small) */
    /* For big elements, use malloc to avoid huge stack usage */
    if (memsz <= 256) {
        unsigned char tmp[256];
        memcpy(tmp, a, memsz);
        memcpy(a, b, memsz);
        memcpy(b, tmp, memsz);
    } else {
        unsigned char *tmp = (unsigned char *) malloc(memsz);
        if (!tmp) return; /* best effort */
        memcpy(tmp, a, memsz);
        memcpy(a, b, memsz);
        memcpy(b, tmp, memsz);
        free(tmp);
    }
}

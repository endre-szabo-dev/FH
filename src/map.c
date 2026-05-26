/* map.c */

#include <string.h>
#include <stdio.h>
#include <math.h>

#include "program.h"
#include "value.h"


#define OCCUPIED(e) ((e)->key.type != FH_VAL_NULL)

static inline uint32_t next_pow2_u32(uint32_t x) {
    if (x <= 1) return 1;
    x--;
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;
    return x + 1;
}

static inline int32_t hash_i32(uint32_t x) {
    x ^= x >> 16;
    x *= 0x7feb352dU;
    x ^= x >> 15;
    x *= 0x846ca68bU;
    x ^= x >> 16;
    return x;
}

static inline int is_int32_double(const double d, int32_t *out) {
    // NaN check: only NaN is != itself
    if (d != d) return 0;

    // 2147483647.0 and -2147483648.0 are exactly representable
    if (d < -2147483648.0 || d > 2147483647.0) return 0;

    const int32_t iv = (int32_t) d;
    if ((double) iv != d) return 0;

    *out = iv;
    return 1;
}

static inline uint32_t val_hash_pow2(const struct fh_value *val, uint32_t cap) {
    uint32_t h;
    switch (val->type) {
        case FH_VAL_STRING: h = GET_VAL_STRING(val)->hash;
            break;
        case FH_VAL_BOOL: h = fh_hash(&val->data.b, sizeof(bool));
            break;
        case FH_VAL_FLOAT: {
            int32_t iv;
            if (is_int32_double(val->data.num, &iv)) h = hash_i32((uint32_t) iv);
            else h = fh_hash(&val->data.num, sizeof(double));
            break;
        }
        case FH_VAL_INTEGER: h = hash_i32((uint32_t) val->data.i);
            break;
        case FH_VAL_C_FUNC: h = fh_hash(&val->data.c_func, sizeof(fh_c_func));
            break;
        default: h = fh_hash(&val->data.obj, sizeof(void *));
            break;
    }
    return h & (cap - 1);
}

static inline uint32_t find_slot_num(const struct fh_map_entry *entries, const uint32_t cap, const double key_num) {
    uint32_t idx;

    int32_t iv;
    if (is_int32_double(key_num, &iv)) idx = hash_i32((uint32_t) iv) & (cap - 1);
    else idx = fh_hash(&key_num, sizeof(double)) & (cap - 1);

    while (OCCUPIED(&entries[idx])) {
        if (entries[idx].key.type == FH_VAL_FLOAT && entries[idx].key.data.num == key_num)
            return idx;
        idx = (idx + 1) & (cap - 1);
    }
    return idx;
}

static inline uint64_t
find_slot_integer(const struct fh_map_entry *entries, const uint32_t cap, const int64_t key_num) {
    uint32_t idx = hash_i32(key_num) & (cap - 1);

    while (OCCUPIED(&entries[idx])) {
        if (entries[idx].key.type == FH_VAL_INTEGER && entries[idx].key.data.i == key_num)
            return idx;
        idx = (idx + 1) & (cap - 1);
    }
    return idx;
}

static uint32_t find_slot_generic(struct fh_map_entry *entries, const uint32_t cap, struct fh_value *key) {
    uint32_t i = val_hash_pow2(key, cap);
    while (OCCUPIED(&entries[i]) && !fh_vals_are_equal(key, &entries[i].key))
        i = (i + 1) & (cap - 1);
    return i;
}

static int rebuild(struct fh_map *map, const uint32_t cap) {
    struct fh_map_entry *entries = calloc(cap, sizeof(*entries));
    if (!entries) return -1;

    for (uint32_t i = 0; i < map->cap; i++) {
        const struct fh_map_entry *e = &map->entries[i];
        if (!OCCUPIED(e)) continue;

        uint32_t idx = val_hash_pow2(&e->key, cap);
        while (OCCUPIED(&entries[idx])) idx = (idx + 1) & (cap - 1);
        entries[idx] = *e;
    }

    free(map->entries);
    map->entries = entries;
    map->cap = cap;
    return 0;
}

void fh_dump_map(const struct fh_map *map) {
    for (uint32_t i = 0; i < map->cap; i++) {
        struct fh_map_entry *e = &map->entries[i];
        printf("[%3u] ", i);
        if (e->key.type == FH_VAL_NULL) {
            printf("--\n");
        } else {
            fh_dump_value(&e->key);
            printf(" -> ");
            fh_dump_value(&e->val);
            printf("\n");
        }
    }
}

int fh_get_map_object_value(struct fh_map *map, struct fh_value *key, struct fh_value *val) {
    if (map->cap == 0)
        return -1;

    const uint32_t i = find_slot_generic(map->entries, map->cap, key);
    if (!OCCUPIED(&map->entries[i]))
        return -1;
    *val = map->entries[i].val;
    return 0;
}

int fh_add_map_object_entry(struct fh_program *prog, struct fh_map *map,
                            struct fh_value *key, const struct fh_value *val) {
    if (key->type == FH_VAL_NULL) {
        fh_set_error(prog, "can't insert null key in map");
        return -1;
    }

    if (map->cap == 0) {
        if (rebuild(map, 16) < 0) {
            fh_set_error(prog, "out of memory");
            return -1;
        }
    } else if (((map->len + 1) * 4) > (map->cap * 3)) {
        // load factor > 0.75
        if (rebuild(map, map->cap << 1) < 0) {
            fh_set_error(prog, "out of memory");
            return -1;
        }
    }

    uint32_t i;
    if (key->type == FH_VAL_FLOAT) {
        i = find_slot_num(map->entries, map->cap, key->data.num);
    } else if (key->type == FH_VAL_INTEGER) {
        i = find_slot_integer(map->entries, map->cap, key->data.i);
    } else {
        i = find_slot_generic(map->entries, map->cap, key);
    }

    if (OCCUPIED(&map->entries[i])) {
        map->entries[i].val = *val; // update
        return 0;
    }

    map->entries[i].key = *key;
    map->entries[i].val = *val;
    map->len++;
    return 0;
}

int fh_next_map_object_key(struct fh_map *map, struct fh_value *key, struct fh_value *next_key) {
    uint32_t next_i;
    if (key->type == FH_VAL_NULL || map->cap == 0) {
        next_i = 0;
    } else {
        next_i = find_slot_generic(map->entries, map->cap, key);
        if (OCCUPIED(&map->entries[next_i]))
            next_i++;
    }

    for (uint32_t i = next_i; i < map->cap; i++) {
        if (OCCUPIED(&map->entries[i])) {
            *next_key = map->entries[i].key;
            return 0;
        }
    }
    *next_key = fh_new_null();
    return 0;
}

int fh_delete_map_object_entry(struct fh_map *map, struct fh_value *key) {
    if (map->cap == 0)
        return -1;

    //printf("--------------------------\n");
    //printf("DELETING "); fh_dump_value(key);
    //printf("\nBEFORE:\n"); fh_dump_map(map);

    uint32_t i = find_slot_generic(map->entries, map->cap, key);
    if (!OCCUPIED(&map->entries[i]))
        return -1;
    uint32_t j = i;
    while (true) {
        map->entries[i].key.type = FH_VAL_NULL;
    start:
        j = (j + 1) & (map->cap - 1);
        if (!OCCUPIED(&map->entries[j]))
            break;
        const uint32_t k = val_hash_pow2(&map->entries[j].key, map->cap);
        if ((i < j) ? (i < k) && (k <= j) : (i < k) || (k <= j))
            goto start;
        map->entries[i] = map->entries[j];
        i = j;
    }
    map->len--;

    //printf("AFTER:\n"); fh_dump_map(map);
    //printf("--------------------------\n");
    return 0;
}

static int map_reserve_empty(struct fh_map *map, const uint32_t len_pow2_cap) {
    size_t cap_size = len_pow2_cap * sizeof(struct fh_map_entry);
    struct fh_map_entry *entries = malloc(cap_size);
    if (!entries) return -1;
    memset(entries, 0, cap_size);
    free(map->entries);
    map->entries = entries;
    map->cap = len_pow2_cap;
    return 0;
}

int fh_alloc_map_object_len(struct fh_map *map, const uint32_t len) {
    if (len == 0) {
        return 0;
    }

    if (len > UINT32_MAX / 2) return -1;

    uint32_t cap = next_pow2_u32(len * 2);
    if (cap < 16) cap = 16;

    if (map->cap == 0) return map_reserve_empty(map, cap);
    return rebuild(map, cap);
}

/* value functions */

int fh_alloc_map_len(const struct fh_value *map, const uint32_t len) {
    struct fh_map *m = GET_VAL_MAP(map);
    if (!m)
        return -1;
    return fh_alloc_map_object_len(m, len);
}

int fh_delete_map_entry(const struct fh_value *map, struct fh_value *key) {
    struct fh_map *m = GET_VAL_MAP(map);
    if (!m)
        return -1;
    return fh_delete_map_object_entry(m, key);
}

int fh_next_map_key(const struct fh_value *map, struct fh_value *key, struct fh_value *next_key) {
    struct fh_map *m = GET_VAL_MAP(map);
    if (!m)
        return -1;
    return fh_next_map_object_key(m, key, next_key);
}

int fh_get_map_value(const struct fh_value *map, struct fh_value *key, struct fh_value *val) {
    struct fh_map *m = map->data.obj;
    if (!m)
        return -1;
    return fh_get_map_object_value(m, key, val);
}

int fh_add_map_entry(struct fh_program *prog, const struct fh_value *map,
                     struct fh_value *key, struct fh_value *val) {
    struct fh_map *m = map->data.obj;
    if (!m)
        return -1;
    return fh_add_map_object_entry(prog, m, key, val);
}

void fh_reset_map(struct fh_map *map) {
    for (uint32_t i = 0; i < map->cap; i++) {
        struct fh_map_entry *e = &map->entries[i];
        e->val.type = FH_VAL_NULL;
        e->key.type = FH_VAL_NULL;
    }
    map->len = 0;
}

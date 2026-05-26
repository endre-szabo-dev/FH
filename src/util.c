/* util.c */

#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "fh_internal.h"
#include "bytecode.h"

static inline uint32_t rotl32(uint32_t x, int r) {
	return (x << r) | (x >> (32 - r));
}

static inline uint32_t read32(const void *p) {
	uint32_t v;
	// safe for unaligned access, optimizers usually turn this into a single load
	memcpy(&v, p, sizeof(v));
	return v;
}

static inline uint32_t avalanche32(uint32_t h) {
	// XXH32 avalanche
	h ^= h >> 15;
	h *= 0x85EBCA77u;
	h ^= h >> 13;
	h *= 0xC2B2AE3Du;
	h ^= h >> 16;
	return h;
}

static inline uint32_t fmix32(uint32_t h) {
	h ^= h >> 16;
	h *= 0x85EBCA6Bu;
	h ^= h >> 13;
	h *= 0xC2B2AE35u;
	h ^= h >> 16;
	return h;
}


uint32_t fh_hash(const void *data, const size_t len) {
	const uint8_t *p = (const uint8_t *) data;

	// fast path: tiny strings
	if (len <= 8) {
		uint32_t h = 0x9E3779B1u ^ (uint32_t) len;
		for (size_t i = 0; i < len; i++) h = (h * 0x85EBCA77u) ^ p[i];
		return fmix32(h);
	}

	// XXH32 primes
	const uint32_t PRIME1 = 0x9E3779B1u; // 2654435761
	const uint32_t PRIME2 = 0x85EBCA77u;
	const uint32_t PRIME3 = 0xC2B2AE3Du;
	const uint32_t PRIME4 = 0x27D4EB2Fu;
	const uint32_t PRIME5 = 0x165667B1u;

	const uint8_t *end = p + len;

	uint32_t h;

	if (len >= 16) {
		uint32_t v1 = PRIME1 + PRIME2;
		uint32_t v2 = PRIME2;
		uint32_t v3 = 0;
		uint32_t v4 = (uint32_t) (0u - PRIME1);

		const uint8_t *limit = end - 16;
		do {
			v1 = rotl32(v1 + read32(p) * PRIME2, 13) * PRIME1;
			p += 4;
			v2 = rotl32(v2 + read32(p) * PRIME2, 13) * PRIME1;
			p += 4;
			v3 = rotl32(v3 + read32(p) * PRIME2, 13) * PRIME1;
			p += 4;
			v4 = rotl32(v4 + read32(p) * PRIME2, 13) * PRIME1;
			p += 4;
		} while (p <= limit);

		h = rotl32(v1, 1) + rotl32(v2, 7) + rotl32(v3, 12) + rotl32(v4, 18);
	} else {
		h = PRIME5;
	}

	h += (uint32_t) len;

	// remaining 4-byte chunks
	while ((size_t) (end - p) >= 4) {
		h = rotl32(h + read32(p) * PRIME3, 17) * PRIME4;
		p += 4;
	}

	// remaining bytes
	while (p < end) {
		h = rotl32(h + (*p++) * PRIME5, 11) * PRIME1;
	}

	return avalanche32(h);
}

// uint32_t fh_hash(const void *data, size_t len) {
// 	// this is the hash used by ELF
// 	uint32_t high;
// 	const unsigned char *s = data;
// 	const unsigned char *end = s + len;
// 	uint32_t h = 0;
// 	while (s < end) {
// 		h = (h << 4) + *s++;
// 		if ((high = h & 0xF0000000) != 0)
// 			h ^= high >> 24;
// 		h &= ~high;
// 	}
//
// 	// this is an additional bit mix
// 	uint32_t r = h;
// 	r += r << 16;
// 	r ^= r >> 13;
// 	r += r << 4;
// 	r ^= r >> 7;
// 	r += r << 10;
// 	r ^= r >> 5;
// 	r += r << 8;
// 	r ^= r >> 16;
// 	return r;
// }

// uint32_t fh_hash2(const void *data, size_t len, size_t cap) {
// 	uint32_t hash = 0;
// 	const unsigned char *s = data;
// 	for (size_t i = 0; i < len; i++) {
// 		hash += s[i];
// 		hash *= 31;
// 	}
//
// 	if ((cap & (cap - 1)) == 0) {
// 		// cap is a power of 2
// 		return hash & (cap - 1);
// 	}
// 	return hash % cap;
// }

static inline uint32_t reduce_to_cap(const uint32_t h, const size_t cap) {
	if ((cap & (cap - 1)) == 0) {
		return h & (uint32_t) (cap - 1);
	}
	return (uint32_t) (((uint64_t) h * (uint64_t) cap) >> 32);
}

uint32_t fh_hash2(const void *data, size_t len, size_t cap) {
	if (cap == 0) return 0;
	return reduce_to_cap(fh_hash(data, len), cap);
}

void fh_dump_string(const char *str) {
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

void fh_dump_value(const struct fh_value *val) {
	switch (val->type) {
		case FH_VAL_NULL: printf("NULL");
			return;
		case FH_VAL_BOOL: printf("BOOL(%s)", (val->data.b) ? "true" : "false");
			return;
		case FH_VAL_FLOAT: printf("NUMBER(%f)", val->data.num);
			return;
		case FH_VAL_INTEGER: printf("NUMBER(%lld)", val->data.i);
			return;
		case FH_VAL_STRING: printf("STRING(");
			fh_dump_string(fh_get_string(val));
			printf(")");
			return;
		case FH_VAL_ARRAY: printf("ARRAY(len=%d)", fh_get_array_len(val));
			return;
		case FH_VAL_MAP: printf("MAP(len=%d,cap=%d)", GET_OBJ_MAP(val->data.obj)->len, GET_OBJ_MAP(val->data.obj)->cap);
			break;
		case FH_VAL_UPVAL: printf("UPVAL(");
			fh_dump_value(GET_OBJ_UPVAL(val->data.obj)->val);
			printf(")");
			return;
		case FH_VAL_CLOSURE: printf("CLOSURE(%p)", val->data.obj);
			return;
		case FH_VAL_FUNC_DEF: printf("FUNC_DEF(%p)", val->data.obj);
			return;
		case FH_VAL_C_FUNC: printf("C_FUNC");
			return;
		case FH_VAL_C_OBJ: printf("C_OBJ(%p)", val->data.obj);
			return;
	}
	printf("INVALID_VALUE(type=%d)", val->type);
}

int fh_utf8_len(char *str, const size_t str_size) {
	int len = 0;
	const uint8_t *p = (uint8_t *) str;
	const uint8_t *end = (uint8_t *) str + str_size;

	while (p < end) {
		const uint8_t c = *p++;
		if (c == 0)
			break;
		if ((c & 0x80) == 0) {
			len++;
		} else if ((c & 0xe0) == 0xc0) {
			len += 2;
			if (p >= end || (*p++ & 0xc0) != 0x80) return -1;
		} else if ((c & 0xf0) == 0xe0) {
			len += 3;
			if (p >= end || (*p++ & 0xc0) != 0x80) return -1;
			if (p >= end || (*p++ & 0xc0) != 0x80) return -1;
		} else if ((c & 0xf8) == 0xf0) {
			len += 4;
			if (p >= end || (*p++ & 0xc0) != 0x80) return -1;
			if (p >= end || (*p++ & 0xc0) != 0x80) return -1;
			if (p >= end || (*p++ & 0xc0) != 0x80) return -1;
		} else {
			return -1;
		}
	}

	return len;
}


/**
 * Check if the given string is uppercased or not.
 * @param str to be checked
 * @return -1 on error, when the given string is not totally uppercased
 * or 0 when it is.
 */
int fh_string_is_upper(char *str) {
	while (*str != '\0') {
		if (!(*str >= 'A' && *str <= 'Z'))
			return -1;
		str++;
	}
	return 0;
}


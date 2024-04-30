/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * TODO: Is this license ok?
 *
 * Copyright (c) 2024 Codasip
 *
 * based on cheri_compressed_cap_64.h, which is
 * Copyright (c) 2018-2020 Alex Richardson
 */

#define CC_FORMAT_LOWER 64r
#define CC_FORMAT_UPPER 64R

#define CC64R_CAP_SIZE    8
#define CC64R_CAP_BITS   64
#define CC64R_ADDR_WIDTH 32
#define CC64R_LEN_WIDTH  33

#define CC64R_MANTISSA_WIDTH 8
#define CC64R_MAX_EXPONENT 26
#define CC64R_CURSOR_MASK 0xFFFFFFFF

#define CC64R_MAX_ADDRESS_PLUS_ONE ((cc64r_length_t)1u << CC64R_ADDR_WIDTH)
#define CC64R_NULL_TOP    CC64R_MAX_ADDRESS_PLUS_ONE
#define CC64R_NULL_LENGTH CC64R_MAX_ADDRESS_PLUS_ONE
#define CC64R_MAX_LENGTH  CC64R_MAX_ADDRESS_PLUS_ONE
#define CC64R_MAX_TOP     CC64R_MAX_ADDRESS_PLUS_ONE
#define CC64R_MAX_ADDR    UINT32_MAX

/* Special otypes are allocated downwards from -1 */
#define CC64R_SPECIAL_OTYPE_VAL(subtract) \
    (CC64R_MAX_REPRESENTABLE_OTYPE - subtract##u)
#define CC64R_SPECIAL_OTYPE_VAL_SIGNED(subtract) (((int64_t)-1) - subtract##u)

/* Use uint64_t to represent 33 bit length */
typedef uint64_t cc64r_length_t;
typedef int64_t cc64r_offset_t;
typedef uint32_t cc64r_addr_t;
typedef int32_t cc64r_saddr_t;
#include "cheri_compressed_cap_macros.h"

/* ignore ISO C restricts enumerator values to range of 'int' */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
enum {
    _CC_FIELD(SDP, 63, 62),
    _CC_FIELD(RESERVED2, 61, 53),
    _CC_FIELD(SEALED, 52, 52),
    _CC_FIELD(RESERVED, 51, 47),
    _CC_FIELD(EBT, 46, 32),

    _CC_FIELD(INTERNAL_EXPONENT, 46, 46),
    _CC_FIELD(TOP_ENCODED, 45, 40),
    _CC_FIELD(BOTTOM_ENCODED, 39, 32),

    // Top/bottom offsets depending in INTERNAL_EXPONENT flag:
    // Without internal exponent:
    _CC_FIELD(EXP_ZERO_TOP, 45, 40),
    _CC_FIELD(EXP_ZERO_BOTTOM, 39, 32),
    // With internal exponent:
    _CC_FIELD(EXP_NONZERO_TOP, 45, 43),
    _CC_FIELD(EXPONENT_HIGH_PART, 42, 40),
    _CC_FIELD(EXP_NONZERO_BOTTOM, 39, 35),
    _CC_FIELD(EXPONENT_LOW_PART, 34, 32),

    /* The following fields are unused for the 64r format. */
    _CC_FIELD(OTYPE, 31, 32),
    _CC_FIELD(FLAGS, 31, 32),
    _CC_FIELD(UPERMS, 31, 32),
    _CC_FIELD(HWPERMS, 31, 32),
};
#pragma GCC diagnostic pop

_CC_STATIC_ASSERT_SAME(CC64R_FIELD_UPERMS_SIZE, 0);

#define CC64R_FIELD_FLAGS_USED 0
#define CC64R_FIELD_OTYPE_USED 0
#define CC64R_FIELD_HWPERMS_USED 0
#define CC64R_FIELD_UPERMS_USED 0

#define CC64R_OTYPE_BITS CC64R_FIELD_OTYPE_SIZE
#define CC64R_BOT_WIDTH CC64R_FIELD_EXP_ZERO_BOTTOM_SIZE
#define CC64R_BOT_INTERNAL_EXP_WIDTH CC64R_FIELD_EXP_NONZERO_BOTTOM_SIZE
#define CC64R_EXP_LOW_WIDTH CC64R_FIELD_EXPONENT_LOW_PART_SIZE

#define CC64R_PERM_GLOBAL (1 << 0)
#define CC64R_PERM_EXECUTE (1 << 1)
#define CC64R_PERM_LOAD (1 << 2)
#define CC64R_PERM_STORE (1 << 3)
#define CC64R_PERM_LOAD_CAP (1 << 4)
#define CC64R_PERM_STORE_CAP (1 << 5)
#define CC64R_PERM_STORE_LOCAL (1 << 6)
#define CC64R_PERM_SEAL (1 << 7)
#define CC64R_PERM_CINVOKE (1 << 8)
#define CC64R_PERM_UNSEAL (1 << 9)
#define CC64R_PERM_ACCESS_SYS_REGS (1 << 10)
#define CC64R_PERM_SETCID (1 << 11)

#define CC64R_PERMS_ALL   (0)
#define CC64R_UPERMS_ALL  (0)
#define CC64R_UPERMS_SHFT (0)
#define CC64R_MAX_UPERM   (0)

/* Unused for 64r, but referenced by cheri_compressed_cap_common.h, so they
   have to be defined. */
enum _CC_N(OTypes) {
    /* see the comment in cheri_compressed_cap_128r.h about max representable
       otype */
    CC64R_MAX_REPRESENTABLE_OTYPE = 16,
    _CC_SPECIAL_OTYPE(OTYPE_UNSEALED, 0),
    _CC_SPECIAL_OTYPE(OTYPE_SENTRY, 1),
    _CC_SPECIAL_OTYPE(OTYPE_RESERVED2, 2),
    _CC_SPECIAL_OTYPE(OTYPE_RESERVED3, 3),
    _CC_N(MIN_RESERVED_OTYPE) = _CC_N(OTYPE_RESERVED3),
    _CC_N(MAX_RESERVED_OTYPE) = _CC_N(OTYPE_UNSEALED),
};

#define CC64R_LS_SPECIAL_OTYPES(ITEM, ...) \
    ITEM(OTYPE_UNSEALED, __VA_ARGS__) \
    ITEM(OTYPE_SENTRY, __VA_ARGS__)

_CC_STATIC_ASSERT_SAME(CC64R_MANTISSA_WIDTH, CC64R_FIELD_EXP_ZERO_BOTTOM_SIZE);

#include "cheri_compressed_cap_common.h"

// Sanity-check mask is the expected NULL encoding
_CC_STATIC_ASSERT_SAME(CC64R_NULL_XOR_MASK, UINT32_C(0x04302));

#define CC64R_FIELD(name, last, start) _CC_FIELD(name, last, start)
#define CC64R_ENCODE_FIELD(value, name) _CC_ENCODE_FIELD(value, name)
#define CC64R_EXTRACT_FIELD(value, name) _CC_EXTRACT_FIELD(value, name)
#define CC64R_ENCODE_EBT_FIELD(value, name) _CC_ENCODE_EBT_FIELD(value, name)

#undef CC_FORMAT_LOWER
#undef CC_FORMAT_UPPER

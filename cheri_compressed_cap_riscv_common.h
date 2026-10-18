// SPDX-License-Identifier: BSD-2-Clause

static inline _cc_addr_t _cc_N(get_reserved)(const _cc_cap_t* cap) {
    _cc_addr_t reserved = cap->cr_pesbt & (_CC_N(FIELD_RESERVED0_MASK64) | _CC_N(FIELD_RESERVED1_MASK64));
    if (cap->cr_lvbits == 0) {
        reserved |= cap->cr_pesbt & _CC_N(FIELD_LEVEL_MASK64);
    }
    return reserved;
}
static inline uint32_t _cc_N(get_level)(const _cc_cap_t* cap) {
    // With lvbits==0 we always report global.
    return cap->cr_lvbits == 0 ? 1 : _CC_EXTRACT_FIELD(cap->cr_pesbt, LEVEL);
}
static inline void _cc_N(update_level)(_cc_cap_t* cap, uint8_t level) {
    _cc_api_requirement(level <= _CC_N(MAX_LEVEL_VALUE), "invalid level");
    if (cap->cr_lvbits == 0) {
        _cc_api_requirement(level == 1, "cannot change level when levels are reserved");
        return;
    }
    cap->cr_pesbt = _CC_DEPOSIT_FIELD(cap->cr_pesbt, level, LEVEL);
}

static inline bool _cc_N(bounds_malformed)(_cc_bounds_bits bounds) {
    // The spec defines this check as checking for E < 0, but since we store it as an unsigned number, we compare it to
    // the maximum exponent instead.
    bool malformedLSB = bounds.E > _CC_MAX_EXPONENT;
#if _CC_N(USES_LEN_MSB) != 0
    // For MXLEN==32, we also report invalid bounds for IE && E == 0
    malformedLSB = malformedLSB || (bounds.E == 0);
#endif
    bool malformedMSB = (bounds.E == _CC_MAX_EXPONENT && bounds.B != 0) ||
                        (bounds.E == _CC_MAX_EXPONENT - 1 && (bounds.B & (1u << (_CC_MANTISSA_WIDTH - 1))) != 0);
    return bounds.IE && (malformedLSB || malformedMSB);
}

static inline bool _cc_N(compute_base_top_special_cases)(_cc_bounds_bits bounds, _cc_addr_t* base_out,
                                                         _cc_length_t* top_out, bool* valid) {
    if (_cc_N(bounds_malformed)(bounds)) {
        *base_out = 0;
        *top_out = 0;
        *valid = false;
        return true;
    }
    return false;
}

// Check that there is no XOR mask for this encoding format (i.e. NULL encodes to all-zeroes in memory).
_CC_STATIC_ASSERT_SAME(_CC_N(MEM_XOR_MASK), UINT64_C(0));
enum { _CC_N(PERMS_RESERVED_ONES) = _CC_BITMASK64_RANGE(6 + _CC_N(FIELD_SDP_SIZE), 15) | _CC_BITMASK64_RANGE(19, 23) };

static inline _cc_addr_t _cc_N(decode_ap_m)(const _cc_cap_t* cap);

static inline bool _cc_N(has_valid_permissions_encoding)(const _cc_cap_t* cap) {
    return _CC_EXTRACT_FIELD(cap->cr_pesbt, AP_M) == 0 || _cc_N(decode_ap_m)(cap) != 0;
}

static inline bool _cc_N(has_all_perms)(_cc_addr_t perms, _cc_addr_t required) {
    return (perms & required) == required;
}

static inline _cc_addr_t _cc_N(legalize_permissions)(const _cc_cap_t* cap, _cc_addr_t perms) {
    _cc_api_requirement((perms & (_CC_N(PERMS_MASK) | _CC_N(PERMS_RESERVED_ONES))) == perms, "invalid permissions");
    unsigned level_bits = cap->cr_lvbits;
    _cc_api_requirement(level_bits <= _CC_N(MAX_LEVEL_BITS), "Invalid number of level bits");
    // C requires R or W (base-1).
    if (!(perms & (_CC_N(PERM_READ) | _CC_N(PERM_WRITE))))
        perms &= ~_CC_N(PERM_CAPABILITY);
#if _CC_ADDR_WIDTH == 32
    // C requires R (RV32-base-1, supersedes base-1) and X requires R (RV32-base-2).
    if (!(perms & _CC_N(PERM_READ)))
        perms &= ~(_CC_N(PERM_CAPABILITY) | _CC_N(PERM_EXECUTE));
    // W requires not(C) or LM (RV32-base-3).
    if ((perms & _CC_N(PERM_CAPABILITY)) && !(perms & _CC_N(PERM_LOAD_MUTABLE)))
        perms &= ~_CC_N(PERM_WRITE);
    // X requires W or C (RV32-base-4).
    if (!(perms & (_CC_N(PERM_WRITE) | _CC_N(PERM_CAPABILITY))))
        perms &= ~_CC_N(PERM_EXECUTE);
#endif
    // LM requires C and R (base-2; on RV32 C already requires R, matching RV32-base-5).
    if (!_cc_N(has_all_perms)(perms, _CC_N(PERM_CAPABILITY) | _CC_N(PERM_READ)))
        perms &= ~_CC_N(PERM_LOAD_MUTABLE);
    if (level_bits > 0) {
#if _CC_ADDR_WIDTH == 32
        // LM requires W or EL (LG) (RV32-l1-1).
        if (!(perms & (_CC_N(PERM_WRITE) | _CC_N(PERM_ELEVATE_LEVEL))))
            perms &= ~_CC_N(PERM_LOAD_MUTABLE);
#endif
        // EL (LG) requires C and R (Zylevels1-1).
        if (!_cc_N(has_all_perms)(perms, _CC_N(PERM_CAPABILITY) | _CC_N(PERM_READ)))
            perms &= ~_CC_N(PERM_ELEVATE_LEVEL);
#if _CC_ADDR_WIDTH == 32
        // EL (LG) requires LM (RV32-l1-2, supersedes Zylevels1-1).
        if (!(perms & _CC_N(PERM_LOAD_MUTABLE)))
            perms &= ~_CC_N(PERM_ELEVATE_LEVEL);
#endif
#ifndef CC_IS_RVY093
        // SL requires C and W (Zylevels1-2).
        if (!_cc_N(has_all_perms)(perms, _CC_N(PERM_CAPABILITY) | _CC_N(PERM_WRITE)))
            perms &= ~_CC_N(PERM_STORE_LEVEL);
#else
        // SL requires C (prior to v0.9.6 / riscv/riscv-cheri#631, SL did not require W).
        if (!(perms & _CC_N(PERM_CAPABILITY)))
            perms &= ~_CC_N(PERM_STORE_LEVEL);
#endif
#if _CC_ADDR_WIDTH == 32
#ifndef CC_IS_RVY093
        // SL requires LM and W (RV32-l1-3, supersedes Zylevels1-2).
        if (!_cc_N(has_all_perms)(perms, _CC_N(PERM_LOAD_MUTABLE) | _CC_N(PERM_WRITE)))
            perms &= ~_CC_N(PERM_STORE_LEVEL);
#else
        // SL requires LM and (W or X) (prior to v0.9.6 / riscv/riscv-cheri#742, Q1 executable
        // read-only capabilities also granted SL).
        if (!(perms & _CC_N(PERM_LOAD_MUTABLE)) || !(perms & (_CC_N(PERM_WRITE) | _CC_N(PERM_EXECUTE))))
            perms &= ~_CC_N(PERM_STORE_LEVEL);
#endif
#endif
    }
#if _CC_ADDR_WIDTH == 32
    // X requires all or none of the capability permissions in x_cap_perms (RV32-l1-4 / RV32-base-6).
    _cc_addr_t x_cap_perms = _CC_N(PERM_CAPABILITY) | _CC_N(PERM_LOAD_MUTABLE);
    if (level_bits > 0) {
#ifndef CC_IS_RVY093
        // For RV32-l1-4, X requires either all of (C, LM, EL, and SL if W is set) or none of (C, LM, EL, SL).
        // Note: SL is already cleared above when W is not set.
        x_cap_perms |= _CC_N(PERM_ELEVATE_LEVEL) | ((perms & _CC_N(PERM_WRITE)) ? _CC_N(PERM_STORE_LEVEL) : 0);
#else
        x_cap_perms |= _CC_N(PERM_ELEVATE_LEVEL) | _CC_N(PERM_STORE_LEVEL);
#endif
    }
    if ((perms & x_cap_perms) != 0 && !_cc_N(has_all_perms)(perms, x_cap_perms))
        perms &= ~_CC_N(PERM_EXECUTE);
    // ASR requires W, C, and X (RV32-base-7, supersedes base-3; X is checked below).
    if (!_cc_N(has_all_perms)(perms, _CC_N(PERM_WRITE) | _CC_N(PERM_CAPABILITY)))
        perms &= ~_CC_N(PERM_ACCESS_SYS_REGS);
#endif
    // ASR requires X (base-3).
    if (!(perms & _CC_N(PERM_EXECUTE)))
        perms &= ~_CC_N(PERM_ACCESS_SYS_REGS);
    return perms;
}

static inline _cc_addr_t _cc_N(get_all_permissions)(const _cc_cap_t* cap) {
    _cc_addr_t res = _cc_N(decode_ap_m)(cap);
    if (cap->cr_lvbits > 0) {
        if (_CC_EXTRACT_FIELD(cap->cr_pesbt, LEVEL))
            res |= _CC_N(PERM_LEVEL);
    } else {
        // Levels extension not supported -> treat as reserved one-bits.
        res |= _CC_N(PERM_ELEVATE_LEVEL) | _CC_N(PERM_STORE_LEVEL) | _CC_N(PERM_LEVEL);
    }
    res |= _CC_EXTRACT_FIELD(cap->cr_pesbt, SDP) << _CC_N(UPERMS_SHFT); // Add the software permissions
    res |= _CC_N(PERMS_RESERVED_ONES);                                  // Finally include the hardcoded one-bits
    return res;
}

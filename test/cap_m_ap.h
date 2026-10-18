#pragma once

#define CAP_AP_C _CC_N(PERM_CAPABILITY)
#define CAP_AP_W _CC_N(PERM_WRITE)
#define CAP_AP_R _CC_N(PERM_READ)
#define CAP_AP_X _CC_N(PERM_EXECUTE)
#define CAP_AP_ASR _CC_N(PERM_ACCESS_SYS_REGS)
#define CAP_AP_LM _CC_N(PERM_LOAD_MUTABLE)
#define CAP_AP_EL _CC_N(PERM_ELEVATE_LEVEL)
#define CAP_AP_SL _CC_N(PERM_STORE_LEVEL)

#define LVB_0 0
#define LVB_1 1

static inline _cc_addr_t compute_supported_permissions(unsigned level_bits) {
    _cc_addr_t supported_permissions = CAP_AP_C | CAP_AP_W | CAP_AP_R | CAP_AP_X | CAP_AP_ASR | CAP_AP_LM;
    if (level_bits > 0)
        supported_permissions |= CAP_AP_EL | CAP_AP_SL;
    return supported_permissions;
}

static void testCompression(unsigned level_bits, _cc_mode mode, _cc_addr_t permissions, _cc_addr_t expected_encoding,
                            bool valid_permissions_set, bool valid_mode = true) {
    // ensure we didn't request unsupported perms:
    const _cc_addr_t supported_permissions = compute_supported_permissions(level_bits);
    REQUIRE(level_bits <= 1);
    _cc_cap_t cap = TestAPICC::make_null_derived_cap(0);
    cap.cr_lvbits = level_bits;
    CHECK(_CC_EXTRACT_FIELD(cap.cr_pesbt, AP_M) == 0);
    CHECK(_CC_EXTRACT_FIELD(cap.cr_pesbt, SDP) == 0);
    CHECK(cap.has_valid_permissions_encoding());
    CHECK((cap.legalize_permissions(permissions) == permissions) == valid_permissions_set);
    CHECK(_cc_N(set_permissions)(&cap, permissions) == valid_permissions_set);
    CHECK(cap.has_valid_permissions_encoding());
    const bool has_x = cap.has_permissions(_CC_N(PERM_EXECUTE));
    CHECK(_cc_N(set_execution_mode)(&cap, mode) == has_x);
    CHECK(cap.has_valid_permissions_encoding());
    if (valid_permissions_set) {
        CHECK(cap.has_permissions(permissions));
    } else {
        CHECK((cap.all_permissions() & supported_permissions) == 0); // Invalid permissions should report 0
    }
    if (!valid_mode) {
        CHECK(_cc_N(get_execution_mode)(&cap) != mode);
    }
    CHECK(_CC_EXTRACT_FIELD(cap.cr_pesbt, AP_M) == expected_encoding);
    CHECK(_CC_EXTRACT_FIELD(cap.cr_pesbt, SDP) == 0);
}

static void testDecompression(unsigned level_bits, _cc_addr_t ap_m_encoding, _cc_mode expected_mode,
                              _cc_addr_t expected_permissions) {
    // ensure we didn't request unsupported perms:
    const _cc_addr_t supported_permissions = compute_supported_permissions(level_bits);
    REQUIRE((expected_permissions & supported_permissions) == expected_permissions);
    REQUIRE(level_bits <= 1);
    const bool valid_encoding = ap_m_encoding == 0 || expected_permissions != 0;
    _cc_cap_t cap = TestAPICC::make_null_derived_cap(0);
    cap.cr_lvbits = level_bits;
    CHECK(_CC_EXTRACT_FIELD(cap.cr_pesbt, AP_M) == 0);
    CHECK(_CC_EXTRACT_FIELD(cap.cr_pesbt, SDP) == 0);
    cap.cr_pesbt = _CC_DEPOSIT_FIELD(cap.cr_pesbt, ap_m_encoding, AP_M);
    CHECK(cap.has_valid_permissions_encoding() == valid_encoding);
    CHECK(_cc_N(has_valid_permissions_encoding)(&cap) == valid_encoding);
    CHECK(cap.legalize_permissions(cap.all_permissions()) == cap.all_permissions());
    CHECK(cap.has_permissions(expected_permissions));
    CHECK((cap.all_permissions() & supported_permissions) == expected_permissions); // ignore reserved-one bits
    CHECK(_cc_N(get_execution_mode)(&cap) == expected_mode);
    CHECK(_CC_EXTRACT_FIELD(cap.cr_pesbt, AP_M) == ap_m_encoding);
    CHECK(cap.software_permissions() == 0); // should not have been set
}

TEST_CASE("Exhaustive AP_M validity and roundtrip", "[perms]") {
    for (unsigned lvbits : {LVB_0, LVB_1}) {
        const _cc_addr_t supported_perms = compute_supported_permissions(lvbits);
        unsigned valid_count = 0;
        for (_cc_addr_t ap_m = 0; ap_m <= _CC_N(FIELD_AP_M_MAX_VALUE); ++ap_m) {
            _cc_cap_t cap = TestAPICC::make_null_derived_cap(0, lvbits);
            cap.cr_pesbt = _CC_DEPOSIT_FIELD(cap.cr_pesbt, ap_m, AP_M);
            CAPTURE(lvbits, ap_m);
            if (cap.has_valid_permissions_encoding()) {
                valid_count++;
                if (ap_m != 0) {
                    CHECK((cap.all_permissions() & supported_perms) != 0);
                }
                _cc_cap_t reencoded = TestAPICC::make_null_derived_cap(0, lvbits);
                CHECK(_cc_N(set_permissions)(&reencoded, cap.all_permissions()));
                const _cc_mode mode = _cc_N(get_execution_mode)(&cap);
                if (cap.has_permissions(_CC_N(PERM_EXECUTE))) {
                    CHECK(_cc_N(set_execution_mode)(&reencoded, mode));
                } else {
                    CHECK(mode == _CC_N(MODE_CAP));
                }
                CHECK(_CC_EXTRACT_FIELD(reencoded.cr_pesbt, AP_M) == ap_m);
            } else {
                CHECK((cap.all_permissions() & supported_perms) == 0);
            }
        }
#if _CC_N(CAP_BITS) == 64
        // RV32Y 5-bit AP_M has 4 valid encodings in Q0, 8 in Q1, and in Q2/Q3 either 1+2 = 3
        // (lvbits == 0) or 3+3 = 6 (lvbits == 1) in both v0.9.3 and v0.9.9 (v0.9.6 /
        // riscv/riscv-cheri#742 dropped implicit SL from Q1 "Execute + Data & Cap RO" entries 2/3,
        // but the encodings remain valid).
        CHECK(valid_count == (lvbits == 0 ? 15u : 18u));
#elif !defined(TEST_CC_IS_RVY093)
        // RV64Y 9-bit AP_M is the product of 5 valid (X, ASR, M) combinations and valid
        // (R, W, C, LM, EL, SL) combinations:
        // - lvbits == 0 (EL=0, SL=0): 4 (C=0) + 5 (C=1) = 9 combinations -> 5 * 9 = 45.
        // - lvbits == 1 (SL requires C && W since v0.9.6 / riscv/riscv-cheri#631):
        //   4 (C=0) + 2 (C=1, R=0, W=1) + 4 (C=1, R=1, W=0) + 8 (C=1, R=1, W=1) = 18 -> 5 * 18 = 90.
        CHECK(valid_count == (lvbits == 0 ? 45u : 90u));
#else
        // Prior to v0.9.6 (riscv/riscv-cheri#631), SL only required C (not C && W), allowing 4
        // additional (LM, EL) combinations when C=1, R=1, W=0, SL=1 (22 total -> 5 * 22 = 110).
        CHECK(valid_count == (lvbits == 0 ? 45u : 110u));
#endif
    }
}

TEST_CASE("Exhaustive permissions legalization", "[perms]") {
    static constexpr _cc_addr_t arch_perm_bits[] = {
        CAP_AP_C, CAP_AP_W, CAP_AP_R, CAP_AP_X, CAP_AP_ASR, CAP_AP_LM, CAP_AP_EL, CAP_AP_SL,
    };
    for (unsigned lvbits : {LVB_0, LVB_1}) {
        const _cc_addr_t supported_perms = compute_supported_permissions(lvbits);
        const _cc_cap_t cap = TestAPICC::make_null_derived_cap(0, lvbits);

        std::vector<_cc_addr_t> valid_perm_sets;
        for (_cc_addr_t ap_m = 0; ap_m <= _CC_N(FIELD_AP_M_MAX_VALUE); ++ap_m) {
            _cc_cap_t tmp = TestAPICC::make_null_derived_cap(0, lvbits);
            tmp.cr_pesbt = _CC_DEPOSIT_FIELD(tmp.cr_pesbt, ap_m, AP_M);
            if (tmp.has_valid_permissions_encoding()) {
                valid_perm_sets.push_back(tmp.all_permissions() & supported_perms);
            }
        }

        for (unsigned mask = 0; mask < (1u << array_lengthof(arch_perm_bits)); ++mask) {
            _cc_addr_t perms = 0;
            for (size_t i = 0; i < array_lengthof(arch_perm_bits); ++i) {
                if (mask & (1u << i))
                    perms |= arch_perm_bits[i];
            }
            const _cc_addr_t arch_perms = perms & supported_perms;
            const _cc_addr_t legalized = cap.legalize_permissions(perms);
            const _cc_addr_t legalized_arch = cap.legalize_permissions(arch_perms);
            CAPTURE(lvbits, perms, arch_perms, legalized, legalized_arch);

            CHECK(_cc_N(legalize_permissions)(&cap, perms) == legalized);
            CHECK(CompressedCapCC::legalize_permissions(cap, perms) == legalized);

            // Non-architectural permission bits (including EL/SL when lvbits == 0) are untouched.
            const _cc_addr_t extra_bits = _CC_N(PERM_SW_ALL) | _CC_N(PERM_LEVEL) | _CC_N(PERMS_RESERVED_ONES);
            CHECK(cap.legalize_permissions(perms | extra_bits) == (legalized | extra_bits));
            CHECK((legalized & ~supported_perms) == (perms & ~supported_perms));
            CHECK((legalized & supported_perms) == legalized_arch);

            // Legalized permissions must be a subset of the requested architectural permissions
            // and must be a fixed point of legalize_permissions().
            CHECK((legalized_arch & arch_perms) == legalized_arch);
            CHECK(cap.legalize_permissions(legalized_arch) == legalized_arch);

            // set_permissions() succeeds on arch_perms iff arch_perms is already legal, and always
            // succeeds on legalized_arch.
            _cc_cap_t direct_cap = TestAPICC::make_null_derived_cap(0, lvbits);
            CHECK(_cc_N(set_permissions)(&direct_cap, arch_perms) == (legalized_arch == arch_perms));
            _cc_cap_t legalized_cap = TestAPICC::make_null_derived_cap(0, lvbits);
            CHECK(_cc_N(set_permissions)(&legalized_cap, legalized_arch));
            CHECK((legalized_cap.all_permissions() & supported_perms) == legalized_arch);

            // No valid permission set that is a subset of arch_perms may strictly contain legalized_arch.
            for (_cc_addr_t valid_p : valid_perm_sets) {
                if ((valid_p & arch_perms) == valid_p) {
                    CHECK(!((valid_p & legalized_arch) == legalized_arch && valid_p != legalized_arch));
                }
            }

            if (lvbits == LVB_1) {
#if defined(TEST_CC_IS_RVY093)
                CHECK(legalized == TestAPICC::sail_legalize_arch_perms(perms));
#elif _CC_N(CAP_BITS) == 128
                // In v0.9.6+ (riscv/riscv-cheri#631), Zylevels1-2 requires C && W for SL (the
                // checked-in Sail C code was generated from v0.9.3 where SL only required C).
                CHECK(legalized == (TestAPICC::sail_legalize_arch_perms(perms) &
                                    ((perms & CAP_AP_W) ? ~(_cc_addr_t)0 : ~CAP_AP_SL)));
#else
                // In v0.9.6+ (riscv/riscv-cheri#742), RV32-l1-3 and RV32-l1-4 dropped SL from
                // Q1 read-only execute encodings (when W == 0).
                if ((perms & CAP_AP_W) != 0) {
                    CHECK(legalized == TestAPICC::sail_legalize_arch_perms(perms));
                } else {
                    CHECK(legalized == (TestAPICC::sail_legalize_arch_perms(perms | CAP_AP_SL) & ~CAP_AP_SL));
                }
#endif
            }
        }
    }
}

#define TEST_CASE_M_AP_COMP(_cr_lvbits, _cr_m, _cr_arch_perm, _cr_ap_m)                                                \
    TEST_CASE(#_cr_lvbits "-" #_cr_arch_perm "-" #_cr_m " compress", "[compress]") {                                   \
        testCompression(_cr_lvbits, (_cc_mode)_cr_m, _cr_arch_perm, _cr_ap_m, true);                                   \
    }

#define TEST_CASE_M_AP_COMP_INVALID(_cr_lvbits, _cr_m, _cr_arch_perm, _cr_ap_m)                                        \
    TEST_CASE(#_cr_lvbits "-" #_cr_arch_perm "-" #_cr_m " invalid compress", "[compress]") {                           \
        testCompression(_cr_lvbits, (_cc_mode)_cr_m, _cr_arch_perm, _cr_ap_m, false);                                  \
    }
#define TEST_CASE_M_AP_COMP_INVALID_MODE(_cr_lvbits, _cr_m, _cr_arch_perm, _cr_ap_m)                                   \
    TEST_CASE(#_cr_lvbits "-" #_cr_arch_perm "-" #_cr_m " invalid mode compress", "[compress]") {                      \
        testCompression(_cr_lvbits, (_cc_mode)_cr_m, _cr_arch_perm, _cr_ap_m, true, false);                            \
    }

#define TEST_CASE_M_AP_DECOMP(_cr_lvbits, _cr_ap_m, _cr_m, _cr_arch_perm)                                              \
    TEST_CASE(#_cr_lvbits "-" #_cr_ap_m " decompress", "[decompress]") {                                               \
        testDecompression(_cr_lvbits, _cr_ap_m, (_cc_mode)_cr_m, _cr_arch_perm);                                       \
    }

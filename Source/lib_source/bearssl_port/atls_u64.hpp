/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * atls_u64.hpp - C++ 64-bit integer for BearSSL on SAS/C (AmigaOS 3.2)
 *
 * BearSSL expects uint64_t arithmetic.  SAS/C has no native 64-bit scalar;
 * this class wraps the Amiga hi/lo ULONG pair and overloads operators so
 * vendored BearSSL sources compile as C++ without per-file patches.
 *
 * 32x32 multiplies may use utility.library/UMult64 when ATLS_U64_USE_UMULT64
 * is defined (SAS/C UTILITYLIBRARY).  All other ops are inline 32-bit math.
 *
 * Compile every translation unit that includes bearssl_types.h with sc
 * CXXSRC=<source-file> (see smakefile).
 */

#ifndef ATLS_U64_HPP
#define ATLS_U64_HPP

#ifndef EXEC_TYPES_H
#include <exec/types.h>
#endif

/*
 * SAS/C UTILITYLIBRARY (SCOPTIONS) exposes UMult64; enable the fast path when
 * the compiler provides atls_umult64_pair() from atls_u64.cpp.
 */
#if defined(UTILITYLIBRARY) || defined(__UTILITYLIBRARY__)
#define ATLS_U64_USE_UMULT64 1
#endif

class AtlsU64
{
    ULONG hi_;
    ULONG lo_;

    static AtlsU64 mul32_pair(ULONG a, ULONG b);

public:
    AtlsU64(void) : hi_(0UL), lo_(0UL) {}
    AtlsU64(int v) : hi_(0UL), lo_((ULONG)v) {}
    AtlsU64(unsigned int v) : hi_(0UL), lo_((ULONG)v) {}
    AtlsU64(long v) : hi_(0UL), lo_((ULONG)v) {}
    AtlsU64(unsigned long v) : hi_(0UL), lo_((ULONG)v) {}

    static AtlsU64 from_parts(ULONG hi, ULONG lo)
    {
        AtlsU64 v;
        v.hi_ = hi;
        v.lo_ = lo;
        return v;
    }

    ULONG hi(void) const { return hi_; }
    ULONG lo(void) const { return lo_; }

    AtlsU64 &operator=(unsigned long v)
    {
        hi_ = 0UL;
        lo_ = v;
        return *this;
    }

    AtlsU64 &operator+=(unsigned long v)
    {
        ULONG nlo;
        nlo = lo_ + v;
        if (nlo < lo_) {
            hi_++;
        }
        lo_ = nlo;
        return *this;
    }

    AtlsU64 &operator+=(const AtlsU64 &o)
    {
        ULONG oldlo;
        oldlo = lo_;
        lo_ += o.lo_;
        hi_ += o.hi_;
        if (lo_ < oldlo) {
            hi_++;
        }
        return *this;
    }

    AtlsU64 &operator-=(unsigned long v)
    {
        ULONG nlo;
        nlo = lo_ - v;
        if (nlo > lo_) {
            hi_--;
        }
        lo_ = nlo;
        return *this;
    }

    AtlsU64 &operator-=(const AtlsU64 &o)
    {
        ULONG oldlo;
        oldlo = lo_;
        lo_ -= o.lo_;
        hi_ -= o.hi_;
        if (lo_ > oldlo) {
            hi_--;
        }
        return *this;
    }

    AtlsU64 operator+(const AtlsU64 &o) const
    {
        AtlsU64 r(*this);
        r += o;
        return r;
    }

    AtlsU64 operator-(const AtlsU64 &o) const
    {
        AtlsU64 r(*this);
        r -= o;
        return r;
    }

    AtlsU64 operator-(unsigned long v) const
    {
        AtlsU64 r(*this);
        r -= v;
        return r;
    }

    AtlsU64 operator<<(int shift) const
    {
        AtlsU64 r;
        if (shift <= 0) {
            return *this;
        }
        if (shift >= 64) {
            return r;
        }
        if (shift >= 32) {
            r.hi_ = lo_ << (shift - 32);
            r.lo_ = 0UL;
        } else {
            r.hi_ = (hi_ << shift) | (lo_ >> (32 - shift));
            r.lo_ = lo_ << shift;
        }
        return r;
    }

    AtlsU64 operator>>(int shift) const
    {
        AtlsU64 r;
        if (shift <= 0) {
            return *this;
        }
        if (shift >= 64) {
            return r;
        }
        if (shift >= 32) {
            r.lo_ = hi_ >> (shift - 32);
            r.hi_ = 0UL;
        } else {
            r.lo_ = (lo_ >> shift) | (hi_ << (32 - shift));
            r.hi_ = hi_ >> shift;
        }
        return r;
    }

    AtlsU64 operator&(const AtlsU64 &o) const
    {
        return from_parts(hi_ & o.hi_, lo_ & o.lo_);
    }

    AtlsU64 operator|(const AtlsU64 &o) const
    {
        return from_parts(hi_ | o.hi_, lo_ | o.lo_);
    }

    AtlsU64 operator~() const
    {
        return from_parts(~hi_, ~lo_);
    }

    AtlsU64 operator*(const AtlsU64 &o) const
    {
        AtlsU64 r;
        ULONG a0;
        ULONG a1;
        ULONG b0;
        ULONG b1;
        ULONG p0;
        ULONG p1;
        ULONG p2;
        ULONG p3;
        ULONG mid;
        ULONG mid2;

        if (hi_ == 0UL && o.hi_ == 0UL) {
            return mul32_pair(lo_, o.lo_);
        }

        a0 = lo_ & 0xFFFFUL;
        a1 = lo_ >> 16;
        b0 = o.lo_ & 0xFFFFUL;
        b1 = o.lo_ >> 16;
        p0 = a0 * b0;
        p1 = a0 * b1;
        p2 = a1 * b0;
        p3 = a1 * b1;
        mid = p1 + p2 + (p0 >> 16);
        mid2 = (p0 & 0xFFFFUL) | (mid << 16);
        r.lo_ = mid2;
        r.hi_ = p3 + (mid >> 16);
        r.hi_ += lo_ * o.hi_;
        r.hi_ += hi_ * o.lo_;
        r.hi_ += hi_ * o.hi_;
        return r;
    }

    AtlsU64 operator++(int)
    {
        AtlsU64 t(*this);
        *this += 1UL;
        return t;
    }

    AtlsU64 &operator++(void)
    {
        *this += 1UL;
        return *this;
    }

    operator unsigned long(void) const { return lo_; }
    operator long(void) const { return (long)lo_; }
    operator unsigned int(void) const { return (unsigned int)lo_; }
    operator int(void) const { return (int)lo_; }
};

inline AtlsU64 operator*(unsigned long a, const AtlsU64 &b)
{
    AtlsU64 aa(a);
    return aa * b;
}

inline AtlsU64 operator*(const AtlsU64 &a, unsigned long b)
{
    AtlsU64 bb(b);
    return a * bb;
}

inline AtlsU64 operator+(const AtlsU64 &a, unsigned long b)
{
    AtlsU64 r(a);
    r += b;
    return r;
}

inline AtlsU64 operator&(const AtlsU64 &a, unsigned long b)
{
    AtlsU64 bb(b);
    return a & bb;
}

typedef AtlsU64 AtlsS64;

typedef char atls_u64_size_ok[(sizeof(AtlsU64) == 8) ? 1 : -1];

#endif /* ATLS_U64_HPP */

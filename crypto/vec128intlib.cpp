// The following two header files must be included in the same directory as this
// file. These can be obtained from the IBM developerWorks website at:
// https://www.ibm.com/developerworks/community/groups/community/powerveclib/

#include "vec128intlib.h"

// Vector Integer Operations
// Preliminary testing
//
// Load
__m128i _mm_load_si128 (__m128i const* address)
{
    return vec_load1q (address);
}

__m128i _mm_loadu_si128 (__m128i const* address)
{
    return vec_loadu1q (address);
}

__m128i _mm_loadl_epi64 (__m128i const* address)
{
    return vec_loadlower1sd (address);
}

// Set
__m128i _mm_setzero_si128 ()
{
    return vec_zero1q ();
}

__m128i _mm_set1_epi8 (char scalar)
{
    return vec_splat16sb (scalar);
}

__m128i _mm_set1_epi16 (short scalar)
{
    return vec_splat8sh (scalar);
}

__m128i _mm_set1_epi32 (int scalar)
{
    return vec_splat4sw (scalar);
}

__m128i _mm_set1_epi64 (__m64 scalar)
{
    return vec_splat2sd (scalar);
}

__m128i _mm_set_epi8 (char c15, char c14, char c13, char c12, char c11, char c10, char c9, char c8, char c7, char c6, char c5, char c4, char c3, char c2, char c1, char c0)
{
    return vec_set16sb (c15, c14, c13, c12, c11, c10, c9, c8, c7, c6, c5, c4, c3, c2, c1, c0);
}

__m128i _mm_set_epi16 (short s7, short s6, short s5, short s4, short s3, short s2, short s1, short s0)
{
    return vec_set8sh (s7, s6, s5, s4, s3, s2, s1, s0);
}

__m128i _mm_set_epi32 (int i3, int i2, int i1, int i0)
{
    return vec_set4sw (i3, i2, i1, i0);
}

__m128i _mm_set_epi64 (__m64 l1, __m64 l0)
{
    return vec_set2sd (l1, l0);
}
__m128i _mm_set_epi64x (__m64 l1, __m64 l0)
{
    return vec_set2sd (l1, l0);
}

__m128i _mm_setr_epi8 (char c15, char c14, char c13, char c12, char c11, char c10, char c9, char c8, char c7, char c6, char c5, char c4, char c3, char c2, char c1, char c0)
{
    return vec_setreverse16sb (c15, c14, c13, c12, c11, c10, c9, c8, c7, c6, c5, c4, c3, c2, c1, c0);
}

__m128i _mm_setr_epi16 (short s7, short s6, short s5, short s4, short s3, short s2, short s1, short s0)
{
    return vec_setreverse8sh (s7, s6, s5, s4, s3, s2, s1, s0);
}

__m128i _mm_setr_epi32 (int i3, int i2, int i1, int i0)
{
    return vec_setreverse4sw (i3, i2, i1, i0);
}

__m128i _mm_setr_epi64 (__m64 l1, __m64 l0)
{
    return vec_setreverse2sd (l1, l0);
}

__m128i _mm_movpi64_epi64 (__m128i v)
{
    return vec_Zerouppersd (v);
}

// Store
void _mm_store_si128 (__m128i* address, __m128i v)
{
    return vec_store1q (address, v);
}

void _mm_storeu_si128 (__m128i* to, __m128i from)
{
    return vec_storeu1q (to, from);
}

void _mm_storel_epi64 (__m128i* to, __m128i from)
{
    return vec_storelower1sdof2sd (to, from);
}

// Insert
// Additional Altivec commands to be ported - WIP
__m128i _mm_insert_epi16 (__m128i v, int scalar, intlit3 element_from_right)
{
    return vec_insert8sh (v, scalar, element_from_right);
}

// Extract
// Additional Altivec commands to be ported - WIP
int _mm_extract_epi16 (__m128i v, int element_from_right)
{
    return vec_extract8sh (v, element_from_right);
}

int _mm_movemask_epi8 (__m128i v)
{
    return vec_extractupperbit16sb (v);
}

// Convert integer to integer
// Additional SSE2 commands to be ported - WIP
__m128i _mm_packs_epi16 (__m128i left, __m128i right)
{
    return vec_packs8hto16sb (left, right);
}

__m128i _mm_packs_epi32 (__m128i left, __m128i right)
{
    return vec_packs4wto8sh (left, right);
}

// Convert floating-point to integer
// Addtional SSE2 commands to be ported - WIP
__m128i _mm_cvttps_epi32 (__m128 a)
{
    return vec_converttruncating4spto4sw (a);
}

__m128i _mm_cvtps_epi32 (__m128 from)
{
    return vec_convert4spto4sw (from);
}

__m128i _mm_cvttpd_epi32 (__m128d from)
{
    return vec_Convert2dpto2sw (from);
}

// Arithmetic
// Additional Altivec and SSE2 commands to be ported - WIP
__m128i _mm_add_epi8 (__m128i left, __m128i right)
{
    return vec_add16sb (left, right);
}

__m128i _mm_add_epi16 (__m128i left, __m128i right)
{
    return vec_add8sh (left, right);
}

__m128i _mm_add_epi32 (__m128i left, __m128i right)
{
    return vec_add4sw (left, right);
}

#ifdef __POWER8__
__m128i _mm_add_epi64 (__m128i left, __m128i right)
{
    return vec_add2sd (left, right);
}
#endif

__m128i _mm_adds_epi8 (__m128i left, __m128i right)
{
    return vec_addsaturating16sb (left, right);
}

__m128i _mm_adds_epu8 (__m128i left, __m128i right)
{
    return vec_addsaturating16ub (left, right);
}

__m128i _mm_adds_epi16 (__m128i left, __m128i right)
{
    return vec_addsaturating8sh (left, right);
}

__m128i _mm_adds_epu16 (__m128i left, __m128i right)
{
    return vec_addsaturating8uh (left, right);
}

__m128i _mm_sub_epi8 (__m128i left, __m128i right)
{
    return vec_subtract16sb (left, right);
}

__m128i _mm_sub_epi16 (__m128i left, __m128i right)
{
    return vec_subtract8sh (left, right);
}

__m128i _mm_sub_epi32 (__m128i left, __m128i right)
{
    return vec_subtract4sw (left, right);
}

#ifdef __POWER8__
__m128i _mm_sub_epi64 (__m128i left, __m128i right)
{
    return vec_subtract2sd (left, right);
}
#endif

__m128i _mm_subs_epi8 (__m128i left, __m128i right)
{
    return vec_subtractsaturating16sb (left, right);
}

__m128i _mm_subs_epu8 (__m128i left, __m128i right)
{
    return vec_subtractsaturating16ub (left, right);
}

__m128i _mm_subs_epi16 (__m128i left, __m128i right)
{
    return vec_subtractsaturating8sh (left, right);
}

__m128i _mm_subs_epu16 (__m128i left, __m128i right)
{
    return vec_subtractsaturating8uh (left, right);
}

__m128i _mm_mul_epu32 (__m128i left, __m128i right)
{
    return vec_multiplylower2uwto2ud (left, right);
}

__m128i _mm_madd_epi16 (__m128i left, __m128i right)
{
    return vec_multiply8sh (left, right);
}

__m128i _mm_avg_epu8 (__m128i left, __m128i right)
{
    return vec_average16ub (left, right);
}

__m128i _mm_avg_epu16 (__m128i left, __m128i right)
{
    return vec_average8uh (left, right);
}

__m128i _mm_max_epi16 (__m128i left, __m128i right)
{
    return vec_max8sh (left, right);
}

__m128i _mm_max_epu8 (__m128i left, __m128i right)
{
    return vec_max16ub (left, right);
}

__m128i _mm_min_epu8 (__m128i left, __m128i right)
{
    return vec_min16ub (left, right);
}

__m128i _mm_min_epi16 (__m128i left, __m128i right)
{
    return vec_min8sh (left, right);
}

// Boolean
__m128i _mm_and_si128 (__m128i left, __m128i right)
{
    return vec_bitand1q (left, right);
}

__m128i _mm_andnotsi128 (__m128i left, __m128i right)
{
    return vec_bitandnotleft1q (left, right);
}

__m128i _mm_or_si128 (__m128i left, __m128i right)
{
    return vec_bitor1q (left, right);
}

__m128i _mm_xor_si128 (__m128i left, __m128i right)
{
    return vec_bitxor1q (left, right);
}

// Unpack
__m128i _mm_unpackhi_epi8 (__m128i left, __m128i right)
{
    return vec_unpackhigh8sb (left, right);
}

__m128i _mm_unpackhi_epi16 (__m128i left, __m128i right)
{
    return vec_unpackhigh4sh (left, right);
}

__m128i _mm_unpacklo_epi8 (__m128i left, __m128i right)
{
    return vec_unpacklow8sb (left, right);
}

__m128i _mm_unpacklo_epi16 (__m128i left, __m128i right)
{
    return vec_unpacklow4sh (left, right);
}

__m128i _mm_unpacklo_epi32 (__m128i left, __m128i right)
{
    return vec_unpacklow2sw (left, right);
}

__m128i _mm_unpackhi_epi32 (__m128i left, __m128i right)
{
    return vec_unpackhigh2sw (left, right);
}

__m128i _mm_unpacklo_epi64 (__m128i left, __m128i right)
{
    return vec_unpacklow1sd (left, right);
}

__m128i _mm_unpackhi_epi64 (__m128i left, __m128i right)
{
    return vec_unpackhigh1sd (left, right);
}

// Shift
// Additional Altivec and SSE2 commands to be ported - WIP
#ifdef __BIG_ENDIAN__
__m128i _mm_sll_epi16 (__m128i v, __m128i count)
{
    return vec_shiftright8sh (v, count);
}

__m128i _mm_sll_epi32 (__m128i v, __m128i count)
{
    return vec_shiftright4sw (v, count);
}

#ifdef __POWER8__
__m128i _mm_sll_epi64 (__m128i v, __m128i count)
{
    return vec_shiftright2sd (v, count);
}
#endif

__m128i _mm_slli_epi16 (__m128i v, int count)
{
    return vec_shiftrightimmediate8sh (v, count);
}

__m128i _mm_slli_epi32 (__m128i v, int count)
{
    return vec_shiftrightimmediate4sw (v, count);
}

__m128i _mm_slli_si128 (__m128i v, int bytecount)
{
    return vec_shiftrightbytes1q (v, bytecount);
}

__m128i _mm_srl_epi16 (__m128i v, __m128i count)
{
    return vec_shiftleft8sh (v, count);
}

__m128i _mm_srl_epi32 (__m128i v, __m128i count)
{
    return vec_shiftleft4sw (v, count);
}

#ifdef __POWER8__
__m128i _mm_srl_epi64 (__m128i v, __m128i count)
{
    return vec_shiftleft2sd (v, count);
}
#endif

__m128i _mm_srli_epi16 (__m128i v, int count)
{
    return vec_shiftleftimmediate8sh (v, count);
}

__m128i _mm_srli_epi32 (__m128i v, int count)
{
    return vec_shiftleftimmediate4sw (v, count);
}

__m128i _mm_srli_epi64 (__m128i v, int count)
{
    return vec_shiftleftimmediate2sd (v, count);
}

__m128i _mm_srli_si128 (__m128i v, int bytecount)
{
    return vec_shiftleftbytes1q (v, bytecount);
}

#elif __LITTLE_ENDIAN__
__m128i _mm_sll_epi16 (__m128i v, __m128i count)
{
    return vec_shiftleft8sh (v, count);
}

__m128i _mm_sll_epi32 (__m128i v, __m128i count)
{
    return vec_shiftleft4sw (v, count);
}

__m128i _mm_sll_epi64 (__m128i v, __m128i count)
{
    return vec_shiftleft2sd (v, count);
}

/*__m128i _mm_slli_epi16 (__m128i v, __m128i count)
{
    return vec_shiftimmediateleft8sh (v, count);
}

__m128i _mm_slli_epi32 (__m128i v, __m128i count)
{
    return vec_shiftimmediateleft4sw (v, count);
}

__m128i _mm_slli_epi64 (__m128i v, __m128i count)
{
    return vec_shiftimmediateleft2sd (v, count);
}*/

__m128i _mm_slli_si128 (__m128i v, intlit8 bytecount)
{
    return vec_shiftleftbytes1q (v, bytecount);
}

/*__m128i _mm_srl_epi16 (__m128i v, __m128i count)
{
    return vec_shiftright8sh (v, count);
}

__m128i _mm_srl_epi32 (__m128i v, __m128i count)
{
    return vec_shiftright4sw (v, count);
}*/

__m128i _mm_srl_epi64 (__m128i v, __m128i count)
{
    return vec_shiftright2sd (v, count);
}

/*__m128i _mm_srli_epi16 (__m128i v, __m128i count)
{
    return vec_shiftimmediateright8sh (v, count);
}

__m128i _mm_srli_epi32 (__m128i v, __m128i count)
{
    return vec_shiftimmediateright4sw (v, count);
}*/

__m128i _mm_srli_si128 (__m128i v, intlit8 bytecount)
{
    return vec_shiftrightbytes1q (v, bytecount);
}
#endif

// Permute
// Additional Altivec and SSE2 commands to be added - WIP
__m128i _mm_shufflelo_epi16 (__m128i v, intlit8 element_selectors)
{
    return vec_permutelower4sh (v, element_selectors);
}

__m128i _mm_shuffle_epi32 (__m128i v, intlit8 element_selectors)
{
    return vec_permute4sw (v, element_selectors);
}

// Compare
__m128i _mm_cmpeq_epi8 (__m128i left, __m128i right)
{
    return vec_compareeq16sb (left, right);
}

__m128i _mm_cmpeq_epi16 (__m128i left, __m128i right)
{
    return vec_compareeq8sh (left, right);
}

__m128i _mm_cmpeq_epi32 (__m128i left, __m128i right)
{
    return vec_compare4sw (left, right);
}

__m128i _mm_cmplt_epi8 (__m128i left, __m128i right)
{
    return vec_comparelt16sb (left, right);
}

__m128i _mm_cmplt_epi16 (__m128i left, __m128i right)
{
    return vec_comparelt8sh (left, right);
}

__m128i _mm_cmplt_epi32 (__m128i left, __m128i right)
{
    return vec_comparelt4sw (left, right);
}

__m128i _mm_cmpgt_epi8 (__m128i left, __m128i right)
{
    return vec_comparegt16sb (left, right);
}

__m128i _mm_cmpgt_epi16 (__m128i left, __m128i right)
{
    return vec_comparegt8sh (left, right);
}

__m128i _mm_cmpgt_epi32 (__m128i left, __m128i right)
{
    return vec_comparegt4sw (left, right);
}

// Cast
__m128i _mm_castps_si128 (__m128 v)
{
    return vec_cast4spto1q (v);
}

__m128i _mm_castpd_si128 (__m128d v)
{
    return vec_Cast2dpto4sw (v);
}

long long _mm_cvtsi128_si64 (__m128i v)
{
  return vec_extractlowerw(v);
}

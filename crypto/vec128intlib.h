// The following two header files must be included in the same directory as this
// file. These can be obtained from the IBM developerWorks website at:
// https://www.ibm.com/developerworks/community/groups/community/powerveclib/

#ifndef VEC128INTLIB_H
#define VEC128INTLIB_H
#include "vec128int.h"

// Vector Integer Operations
// Preliminary testing
//
// Load
__m128i _mm_load_si128 (__m128i const* address);

__m128i _mm_loadu_si128 (__m128i const* address);

__m128i _mm_loadl_epi64 (__m128i const* address);

// Set
__m128i _mm_setzero_si128 ();

__m128i _mm_set1_epi8 (char scalar);

__m128i _mm_set1_epi16 (short scalar);

__m128i _mm_set1_epi32 (int scalar);

__m128i _mm_set1_epi64 (__m64 scalar);

__m128i _mm_set_epi8 (char c15, char c14, char c13, char c12, char c11, char c10, char c9, char c8, char c7, char c6, char c5, char c4, char c3, char c2, char c1, char c0);

__m128i _mm_set_epi16 (short s7, short s6, short s5, short s4, short s3, short s2, short s1, short s0);

__m128i _mm_set_epi32 (int i3, int i2, int i1, int i0);

__m128i _mm_set_epi64 (__m64 l1, __m64 l0);
__m128i _mm_set_epi64x (__m64 l1, __m64 l0);

__m128i _mm_setr_epi8 (char c15, char c14, char c13, char c12, char c11, char c10, char c9, char c8, char c7, char c6, char c5, char c4, char c3, char c2, char c1, char c0);

__m128i _mm_setr_epi16 (short s7, short s6, short s5, short s4, short s3, short s2, short s1, short s0);

__m128i _mm_setr_epi32 (int i3, int i2, int i1, int i0);

__m128i _mm_setr_epi64 (__m64 l1, __m64 l0);

__m128i _mm_movpi64_epi64 (__m128i v);

// Store
void _mm_store_si128 (__m128i* address, __m128i v);

void _mm_storeu_si128 (__m128i* to, __m128i from);

void _mm_storel_epi64 (__m128i* to, __m128i from);

// Insert
// Additional Altivec commands to be ported - WIP
__m128i _mm_insert_epi16 (__m128i v, int scalar, intlit3 element_from_right);

// Extract
// Additional Altivec commands to be ported - WIP
int _mm_extract_epi16 (__m128i v, int element_from_right);

int _mm_movemask_epi8 (__m128i v);

// Convert integer to integer
// Additional SSE2 commands to be ported - WIP
__m128i _mm_packs_epi16 (__m128i left, __m128i right);

__m128i _mm_packs_epi32 (__m128i left, __m128i right);

// Convert floating-point to integer
// Addtional SSE2 commands to be ported - WIP
__m128i _mm_cvttps_epi32 (__m128 a);

__m128i _mm_cvtps_epi32 (__m128 from);

__m128i _mm_cvttpd_epi32 (__m128d from);

// Arithmetic
// Additional Altivec and SSE2 commands to be ported - WIP
__m128i _mm_add_epi8 (__m128i left, __m128i right);

__m128i _mm_add_epi16 (__m128i left, __m128i right);

__m128i _mm_add_epi32 (__m128i left, __m128i right);

#ifdef __POWER8__
__m128i _mm_add_epi64 (__m128i left, __m128i right);
#endif

__m128i _mm_adds_epi8 (__m128i left, __m128i right);

__m128i _mm_adds_epu8 (__m128i left, __m128i right);

__m128i _mm_adds_epi16 (__m128i left, __m128i right);

__m128i _mm_adds_epu16 (__m128i left, __m128i right);

__m128i _mm_sub_epi8 (__m128i left, __m128i right);

__m128i _mm_sub_epi16 (__m128i left, __m128i right);

__m128i _mm_sub_epi32 (__m128i left, __m128i right);

#ifdef __POWER8__
__m128i _mm_sub_epi64 (__m128i left, __m128i right);
#endif

__m128i _mm_subs_epi8 (__m128i left, __m128i right);

__m128i _mm_subs_epu8 (__m128i left, __m128i right);

__m128i _mm_subs_epi16 (__m128i left, __m128i right);

__m128i _mm_subs_epu16 (__m128i left, __m128i right);

__m128i _mm_mul_epu32 (__m128i left, __m128i right);

__m128i _mm_madd_epi16 (__m128i left, __m128i right);

__m128i _mm_avg_epu8 (__m128i left, __m128i right);

__m128i _mm_avg_epu16 (__m128i left, __m128i right);

__m128i _mm_max_epi16 (__m128i left, __m128i right);

__m128i _mm_max_epu8 (__m128i left, __m128i right);

__m128i _mm_min_epu8 (__m128i left, __m128i right);

__m128i _mm_min_epi16 (__m128i left, __m128i right);

// Boolean
__m128i _mm_and_si128 (__m128i left, __m128i right);

__m128i _mm_andnotsi128 (__m128i left, __m128i right);

__m128i _mm_or_si128 (__m128i left, __m128i right);

__m128i _mm_xor_si128 (__m128i left, __m128i right);

// Unpack
__m128i _mm_unpackhi_epi8 (__m128i left, __m128i right);

__m128i _mm_unpackhi_epi16 (__m128i left, __m128i right);

__m128i _mm_unpacklo_epi8 (__m128i left, __m128i right);

__m128i _mm_unpacklo_epi16 (__m128i left, __m128i right);

__m128i _mm_unpacklo_epi32 (__m128i left, __m128i right);

__m128i _mm_unpackhi_epi32 (__m128i left, __m128i right);

__m128i _mm_unpacklo_epi64 (__m128i left, __m128i right);

__m128i _mm_unpackhi_epi64 (__m128i left, __m128i right);

// Shift
// Additional Altivec and SSE2 commands to be ported - WIP
#ifdef __BIG_ENDIAN__
__m128i _mm_sll_epi16 (__m128i v, __m128i count);

__m128i _mm_sll_epi32 (__m128i v, __m128i count);

#ifdef __POWER8__
__m128i _mm_sll_epi64 (__m128i v, __m128i count);
#endif

__m128i _mm_slli_epi16 (__m128i v, int count);

__m128i _mm_slli_epi32 (__m128i v, int count);

__m128i _mm_slli_si128 (__m128i v, int bytecount);

__m128i _mm_srl_epi16 (__m128i v, __m128i count);

__m128i _mm_srl_epi32 (__m128i v, __m128i count);

#ifdef __POWER8__
__m128i _mm_srl_epi64 (__m128i v, __m128i count);
#endif

__m128i _mm_srli_epi16 (__m128i v, int count);

__m128i _mm_srli_epi32 (__m128i v, int count);

__m128i _mm_srli_epi64 (__m128i v, int count);

__m128i _mm_srli_si128 (__m128i v, int bytecount);

#elif __LITTLE_ENDIAN__
__m128i _mm_sll_epi16 (__m128i v, __m128i count);

__m128i _mm_sll_epi32 (__m128i v, __m128i count);

__m128i _mm_sll_epi64 (__m128i v, __m128i count);

__m128i _mm_slli_epi16 (__m128i v, __m128i count);

__m128i _mm_slli_epi32 (__m128i v, __m128i count);

__m128i _mm_slli_epi64 (__m128i v, __m128i count);

__m128i _mm_slli_si128 (__m128i v, intlit8 bytecount);;

__m128i _mm_srl_epi16 (__m128i v, __m128i count);

__m128i _mm_srl_epi32 (__m128i v, __m128i count);

__m128i _mm_srl_epi64 (__m128i v, __m128i count);

__m128i _mm_srli_epi16 (__m128i v, __m128i count);

__m128i _mm_srli_epi32 (__m128i v, __m128i count);

__m128i _mm_srli_si128 (__m128i v, intlit8 bytecount);

#endif

// Permute
// Additional Altivec and SSE2 commands to be added - WIP
__m128i _mm_shufflelo_epi16 (__m128i v, intlit8 element_selectors);

__m128i _mm_shuffle_epi32 (__m128i v, intlit8 element_selectors);

// Compare
__m128i _mm_cmpeq_epi8 (__m128i left, __m128i right);

__m128i _mm_cmpeq_epi16 (__m128i left, __m128i right);

__m128i _mm_cmpeq_epi32 (__m128i left, __m128i right);

__m128i _mm_cmplt_epi8 (__m128i left, __m128i right);

__m128i _mm_cmplt_epi16 (__m128i left, __m128i right);

__m128i _mm_cmplt_epi32 (__m128i left, __m128i right);

__m128i _mm_cmpgt_epi8 (__m128i left, __m128i right);

__m128i _mm_cmpgt_epi16 (__m128i left, __m128i right);

__m128i _mm_cmpgt_epi32 (__m128i left, __m128i right);

// Cast
__m128i _mm_castps_si128 (__m128 v);

__m128i _mm_castpd_si128 (__m128d v);


// Extract
long long _mm_cvtsi128_si64(__m128i v);
#endif // VEC128INTLIB_H

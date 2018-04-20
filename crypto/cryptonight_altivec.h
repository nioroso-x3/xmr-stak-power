/*
  * This program is free software: you can redistribute it and/or modify
  * it under the terms of the GNU General Public License as published by
  * the Free Software Foundation, either version 3 of the License, or
  * any later version.
  *
  * This program is distributed in the hope that it will be useful,
  * but WITHOUT ANY WARRANTY; without even the implied warranty of
  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  * GNU General Public License for more details.
  *
  * You should have received a copy of the GNU General Public License
  * along with this program.  If not, see <http://www.gnu.org/licenses/>.
  *
  */
#pragma once

#include "cryptonight.h"
#include <memory.h>
#include <stdio.h>
#include <altivec.h>
#undef vector
#undef pixel
#undef bool

typedef __vector unsigned long long __m128ll;
typedef __vector unsigned char __m128i;
static inline void _umul128(uint64_t a, uint64_t b, uint64_t* hi,uint64_t *lo)
{
  asm(
  "mulld  %0, %1, %2" : 
  "=r" (*lo) : 
  "r" (a), 
  "r" (b)); 
  asm(
  "mulhdu %0, %1, %2" : 
  "=r" (*hi) : 
  "r" (a), 
  "r" (b));
   
  //unsigned __int128 r = (unsigned __int128)a * (unsigned __int128)b;
  //*hi = r >> 64;
  //return (uint64_t)r;
}

extern "C"
{
 void keccak(const uint8_t *in, int inlen, uint8_t *md, int mdlen);
 void keccakf(uint64_t st[25], int rounds);
 extern void(*const extra_hashes[4])(const void *, size_t, char *);

 __m128i soft_aeskeygenassist(__m128i key, uint8_t rcon);
 __m128i soft_aeskeygenassist_be(__m128i key, uint8_t rcon);

}

inline void cryptonight_monero_tweak(uint64_t* mem_out, __m128i tmp)
{
  uint64_t* t = (uint64_t*)&tmp;
  mem_out[0] = t[0];
  uint8_t x = t[1] >> 24;
  x = (((x >> 3) & 6) | (x & 1)) << 1;
  mem_out[1] = t[1] ^ ((((uint16_t)0x7531 >> x) & 0x3) << 28);
}
// This will shift and xor tmp1 into itself as 4 32-bit vals such as
// sl_xor(a0 a1 a2 a3) = a0 (a1^a0) (a2^a1^a0) (a3^a2^a1^a0)
static inline __m128i sl_xor(__m128i tmp1)
{
  __m128i tmp4;
  tmp4 = vec_slo(tmp1, (__m128i){0x20});
  tmp1 = vec_xor(tmp1, tmp4);
  tmp4 = vec_slo(tmp4, (__m128i){0x20});
  tmp1 = vec_xor(tmp1, tmp4);
  tmp4 = vec_slo(tmp4, (__m128i){0x20});
  tmp1 = vec_xor(tmp1, tmp4);
  return tmp1;
}

// This will shift and xor tmp1 into itself as 4 32-bit vals such as
// sl_xor(a3 a2 a1 a0) =   (a3^a2^a1^a0) (a2^a1^a0) (a1^a0) a0 
static inline __m128i sl_xor_be(__m128i tmp1)
{
  __m128i tmp4;
  tmp4 = vec_sro(tmp1, (__m128i){0x20});
  tmp1 = vec_xor(tmp1, tmp4);
  tmp4 = vec_sro(tmp4, (__m128i){0x20});
  tmp1 = vec_xor(tmp1, tmp4);
  tmp4 = vec_sro(tmp4, (__m128i){0x20});
  tmp1 = vec_xor(tmp1, tmp4);
  return tmp1;
}


static inline __m128i v_rev(const __m128i& tmp1)
{
  return(vec_perm(tmp1,tmp1,(__m128i){ 0xf,0xe,0xd,0xc,0xb,0xa,0x9,0x8,0x7,0x6,0x5,0x4,0x3,0x2,0x1,0x0 })); 
}


static inline __m128i _mm_aesenc_si128(__m128i in, __m128i key)
{
  return v_rev(__builtin_crypto_vcipher(v_rev(in),v_rev(key)));
}

static inline __m128i _mm_aesenc_si128_beIN(__m128i in, __m128i key)
{
  return v_rev(__builtin_crypto_vcipher(in,v_rev(key)));
}

static inline __m128i _mm_aesenc_si128_beK(__m128i in, __m128i key)
{
  return v_rev(__builtin_crypto_vcipher(v_rev(in),key));
}
static inline __m128i _mm_aesenc_si128_be(__m128i in, __m128i key)
{
  return __builtin_crypto_vcipher(in,key);
}


template<uint8_t rcon>
static inline void aes_genkey_sub(__m128i* xout0, __m128i* xout2)
{
 __m128i xout1 = soft_aeskeygenassist(*xout2, rcon);
  xout1 = vec_perm(xout1,xout1,(__m128i){0xc,0xd,0xe,0xf, 0xc,0xd,0xe,0xf, 0xc,0xd,0xe,0xf, 0xc,0xd,0xe,0xf}); 
  *xout0 = sl_xor(*xout0);
 *xout0 = vec_xor(*xout0, xout1);
 xout1 = soft_aeskeygenassist(*xout0, 0x00);
  xout1 = vec_perm(xout1,xout1,(__m128i){0x8,0x9,0xa,0xb, 0x8,0x9,0xa,0xb, 0x8,0x9,0xa,0xb, 0x8,0x9,0xa,0xb});
  *xout2 = sl_xor(*xout2);
 *xout2 = vec_xor(*xout2, xout1);
}

template<uint8_t rcon>
static inline void aes_genkey_sub_be(__m128i* xout0, __m128i* xout2)
{
 __m128i xout1 = soft_aeskeygenassist_be(*xout2, rcon);
  xout1 = vec_perm(xout1,xout1,(__m128i){0x0,0x1,0x2,0x3, 0x0,0x1,0x2,0x3, 0x0,0x1,0x2,0x3, 0x0,0x1,0x2,0x3}); 
  *xout0 = sl_xor_be(*xout0);
 *xout0 = vec_xor(*xout0, xout1);
 xout1 = soft_aeskeygenassist_be(*xout0, 0x00);
  xout1 = vec_perm(xout1,xout1,(__m128i){0x4,0x5,0x6,0x7, 0x4,0x5,0x6,0x7, 0x4,0x5,0x6,0x7, 0x4,0x5,0x6,0x7});
  *xout2 = sl_xor_be(*xout2);
 *xout2 = vec_xor(*xout2, xout1);
}


static inline void aes_genkey(const __m128i* memory, __m128i* k0, __m128i* k1, __m128i* k2, __m128i* k3,
 __m128i* k4, __m128i* k5, __m128i* k6, __m128i* k7, __m128i* k8, __m128i* k9)
{
  __m128i xout0, xout2;

  xout0 = vec_ld(0,memory);
  xout2 = vec_ld(16,memory);
  *k0 = xout0;
  *k1 = xout2;
  aes_genkey_sub<0x01>(&xout0, &xout2);
  *k2 = xout0;
  *k3 = xout2;
  
  aes_genkey_sub<0x02>(&xout0, &xout2);
  *k4 = xout0;
  *k5 = xout2;

  aes_genkey_sub<0x04>(&xout0, &xout2);
  *k6 = xout0;
  *k7 = xout2;

  aes_genkey_sub<0x08>(&xout0, &xout2);
  *k8 = xout0;
  *k9 = xout2;
}

static inline void aes_genkey_be(const __m128i* memory, __m128i* k0, __m128i* k1, __m128i* k2, __m128i* k3,
 __m128i* k4, __m128i* k5, __m128i* k6, __m128i* k7, __m128i* k8, __m128i* k9)
{
 __m128i xout0, xout2;

  xout0 = v_rev(vec_ld(0,memory));
  xout2 = v_rev(vec_ld(16,memory));
  *k0 = xout0;
  *k1 = xout2;
 
  aes_genkey_sub_be<0x01>(&xout0, &xout2);
  *k2 = xout0;
  *k3 = xout2;

  aes_genkey_sub_be<0x02>(&xout0, &xout2);
  *k4 = xout0;
  *k5 = xout2;

  aes_genkey_sub_be<0x04>(&xout0, &xout2);
  *k6 = xout0;
  *k7 = xout2;

  aes_genkey_sub_be<0x08>(&xout0, &xout2);
  *k8 = xout0;
  *k9 = xout2;
}

static inline void aes_round(__m128i key, __m128i* x0, __m128i* x1, __m128i* x2, __m128i* x3, __m128i* x4, __m128i* x5, __m128i* x6, __m128i* x7)
{
 *x0 = _mm_aesenc_si128(*x0, key);
 *x1 = _mm_aesenc_si128(*x1, key);
 *x2 = _mm_aesenc_si128(*x2, key);
 *x3 = _mm_aesenc_si128(*x3, key);
 *x4 = _mm_aesenc_si128(*x4, key);
 *x5 = _mm_aesenc_si128(*x5, key);
 *x6 = _mm_aesenc_si128(*x6, key);
 *x7 = _mm_aesenc_si128(*x7, key);

}
static inline void aes_round_be(__m128i key, __m128i* x0, __m128i* x1, __m128i* x2, __m128i* x3, __m128i* x4, __m128i* x5, __m128i* x6, __m128i* x7)
{
 *x0 = _mm_aesenc_si128_be(*x0, key);
 *x1 = _mm_aesenc_si128_be(*x1, key);
 *x2 = _mm_aesenc_si128_be(*x2, key);
 *x3 = _mm_aesenc_si128_be(*x3, key);
 *x4 = _mm_aesenc_si128_be(*x4, key);
 *x5 = _mm_aesenc_si128_be(*x5, key);
 *x6 = _mm_aesenc_si128_be(*x6, key);
 *x7 = _mm_aesenc_si128_be(*x7, key);

}

template<size_t MEM>
void cn_explode_scratchpad(const __m128i* input, __m128i* output)
{
 // This is more than we have registers, compiler will assign 2 keys on the stack
  __m128i xin0, xin1, xin2, xin3, xin4, xin5, xin6, xin7;
  __m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9;

  aes_genkey(input, &k0, &k1, &k2, &k3, &k4, &k5, &k6, &k7, &k8, &k9);

  xin0 = vec_ld(64,input);
  xin1 = vec_ld(80,input);
  xin2 = vec_ld(96,input);
  xin3 = vec_ld(112,input);
  xin4 = vec_ld(128,input);
  xin5 = vec_ld(144,input);
  xin6 = vec_ld(160,input);
  xin7 = vec_ld(176,input);
  for (size_t i = 0; i < MEM / sizeof(__m128i); i += 8)
  {
    aes_round(k0, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
    aes_round(k1, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
    aes_round(k2, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
    aes_round(k3, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
    aes_round(k4, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
    aes_round(k5, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
    aes_round(k6, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
    aes_round(k7, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
    aes_round(k8, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
    aes_round(k9, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
 
    vec_st(xin0,i*16,output);
    vec_st(xin1,(i+1)*16,output);
    vec_st(xin2,(i+2)*16,output);
    vec_st(xin3,(i+3)*16,output);
    vec_st(xin4,(i+4)*16,output);
    vec_st(xin5,(i+5)*16,output);
    vec_st(xin6,(i+6)*16,output);
    vec_st(xin7,(i+7)*16,output);
  }
}

template<size_t MEM>
void cn_explode_scratchpad_be(const __m128i* input, __m128i* output)
{
  // This is more than we have registers, compiler will assign 2 keys on the stack
  __m128i xin0, xin1, xin2, xin3, xin4, xin5, xin6, xin7;
  __m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9;

  aes_genkey_be(input, &k0, &k1, &k2, &k3, &k4, &k5, &k6, &k7, &k8, &k9);

  xin0 = vec_ld(64,input);
  xin1 = vec_ld(80,input);
  xin2 = vec_ld(96,input);
  xin3 = vec_ld(112,input);
  xin4 = vec_ld(128,input);
  xin5 = vec_ld(144,input);
  xin6 = vec_ld(160,input);
  xin7 = vec_ld(176,input);
  xin0 = v_rev(xin0);
  xin1 = v_rev(xin1);
  xin2 = v_rev(xin2);
  xin3 = v_rev(xin3);
  xin4 = v_rev(xin4);
  xin5 = v_rev(xin5);
  xin6 = v_rev(xin6);
  xin7 = v_rev(xin7);

  for (size_t i = 0; i < MEM / sizeof(__m128i); i += 8)
  {
    aes_round_be(k0, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
    aes_round_be(k1, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
    aes_round_be(k2, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
    aes_round_be(k3, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
    aes_round_be(k4, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
    aes_round_be(k5, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
    aes_round_be(k6, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
    aes_round_be(k7, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
    aes_round_be(k8, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
    aes_round_be(k9, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
 
    vec_st(v_rev(xin0),i*16,output);
    vec_st(v_rev(xin1),(i+1)*16,output);
    vec_st(v_rev(xin2),(i+2)*16,output);
    vec_st(v_rev(xin3),(i+3)*16,output);
    vec_st(v_rev(xin4),(i+4)*16,output);
    vec_st(v_rev(xin5),(i+5)*16,output);
    vec_st(v_rev(xin6),(i+6)*16,output);
    vec_st(v_rev(xin7),(i+7)*16,output);
  }
}

template<size_t MEM>
void cn_implode_scratchpad_be(const __m128i* input, __m128i* output)
{
  // This is more than we have registers, compiler will assign 2 keys on the stack
  __m128i xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7;
  __m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9;

  aes_genkey_be(output + 2, &k0, &k1, &k2, &k3, &k4, &k5, &k6, &k7, &k8, &k9);

  xout0 = vec_ld(64,output);
  xout1 = vec_ld(80,output);
  xout2 = vec_ld(96,output);
  xout3 = vec_ld(112,output);
  xout4 = vec_ld(128,output);
  xout5 = vec_ld(144,output);
  xout6 = vec_ld(160,output);
  xout7 = vec_ld(176,output);
  xout0 = v_rev(xout0);
  xout1 = v_rev(xout1);
  xout2 = v_rev(xout2);
  xout3 = v_rev(xout3);
  xout4 = v_rev(xout4);
  xout5 = v_rev(xout5);
  xout6 = v_rev(xout6);
  xout7 = v_rev(xout7);


  for (size_t i = 0; i < MEM / sizeof(__m128i); i += 8)
  {
    xout0 = vec_xor(v_rev(vec_ld(i*16,input)), xout0);
    xout1 = vec_xor(v_rev(vec_ld((i+1)*16,input)), xout1);
    xout2 = vec_xor(v_rev(vec_ld((i+2)*16,input)), xout2);
    xout3 = vec_xor(v_rev(vec_ld((i+3)*16,input)), xout3);
    xout4 = vec_xor(v_rev(vec_ld((i+4)*16,input)), xout4);
    xout5 = vec_xor(v_rev(vec_ld((i+5)*16,input)), xout5);
    xout6 = vec_xor(v_rev(vec_ld((i+6)*16,input)), xout6);
    xout7 = vec_xor(v_rev(vec_ld((i+7)*16,input)), xout7);

    aes_round_be(k0, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
    aes_round_be(k1, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
    aes_round_be(k2, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
    aes_round_be(k3, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
    aes_round_be(k4, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
    aes_round_be(k5, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
    aes_round_be(k6, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
    aes_round_be(k7, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
    aes_round_be(k8, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
    aes_round_be(k9, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
  }
  vec_st(v_rev(xout0),64,output);
  vec_st(v_rev(xout1),80,output);
  vec_st(v_rev(xout2),96,output);
  vec_st(v_rev(xout3),112,output);
  vec_st(v_rev(xout4),128,output);
  vec_st(v_rev(xout5),144,output);
  vec_st(v_rev(xout6),160,output);
  vec_st(v_rev(xout7),176,output);
}
template<size_t MEM>
void cn_implode_scratchpad(const __m128i* input, __m128i* output)
{
  // This is more than we have registers, compiler will assign 2 keys on the stack
  __m128i xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7;
  __m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9;

  aes_genkey(output + 2, &k0, &k1, &k2, &k3, &k4, &k5, &k6, &k7, &k8, &k9);

  xout0 = vec_ld(64,output);
  xout1 = vec_ld(80,output);
  xout2 = vec_ld(96,output);
  xout3 = vec_ld(112,output);
  xout4 = vec_ld(128,output);
  xout5 = vec_ld(144,output);
  xout6 = vec_ld(160,output);
  xout7 = vec_ld(176,output);

  for (size_t i = 0; i < MEM / sizeof(__m128i); i += 8)
  {
    xout0 = vec_xor(vec_ld(i*16,input), xout0);
    xout1 = vec_xor(vec_ld((i+1)*16,input), xout1);
    xout2 = vec_xor(vec_ld((i+2)*16,input), xout2);
    xout3 = vec_xor(vec_ld((i+3)*16,input), xout3);
    xout4 = vec_xor(vec_ld((i+4)*16,input), xout4);
    xout5 = vec_xor(vec_ld((i+5)*16,input), xout5);
    xout6 = vec_xor(vec_ld((i+6)*16,input), xout6);
    xout7 = vec_xor(vec_ld((i+7)*16,input), xout7);

    aes_round(k0, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
    aes_round(k1, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
    aes_round(k2, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
    aes_round(k3, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
    aes_round(k4, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
    aes_round(k5, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
    aes_round(k6, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
    aes_round(k7, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
    aes_round(k8, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
    aes_round(k9, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
  }
  vec_st(xout0,64,output);
  vec_st(xout1,80,output);
  vec_st(xout2,96,output);
  vec_st(xout3,112,output);
  vec_st(xout4,128,output);
  vec_st(xout5,144,output);
  vec_st(xout6,160,output);
  vec_st(xout7,176,output);
}

template<size_t ITERATIONS, size_t MEM, bool SOFT_AES, bool PREFETCH>
void cryptonight_hash(const void* input, size_t len, void* output, cryptonight_ctx* ctx0)
{
  keccak((const uint8_t *)input, len, ctx0->hash_state, 200);
  uint64_t monero_const = *reinterpret_cast<const uint64_t*>(reinterpret_cast<const uint8_t*>(input) + 35);
  monero_const ^= *(reinterpret_cast<const uint64_t*>(ctx0->hash_state) + 24);
  // Optim - 99% time boundary
  if(PREFETCH) cn_explode_scratchpad_be<MEM>((__m128i*)ctx0->hash_state, (__m128i*)ctx0->long_state);
  else cn_explode_scratchpad<MEM>((__m128i*)ctx0->hash_state, (__m128i*)ctx0->long_state);

  uint8_t* l0 = ctx0->long_state;
  uint64_t* h0 = (uint64_t*)ctx0->hash_state;

  uint64_t al0 = h0[0] ^ h0[4];
  uint64_t ah0 = h0[1] ^ h0[5];
  __m128i bx0 = (__m128ll){h0[2] ^ h0[6],h0[3] ^ h0[7]};

  uint64_t idx0 = al0;

  // Optim - 90% time boundary
  for(size_t i = 0; i < ITERATIONS; i++)
  {
    __m128i cx = vec_vsx_ld(0,(__m128i*)&l0[al0 & 0x1FFFF0]);
    cx = _mm_aesenc_si128(cx, (__m128ll){al0, ah0});

    cryptonight_monero_tweak((uint64_t*)&l0[idx0 & 0x1FFFF0], vec_xor(bx0, cx));

    idx0 = ((uint64_t*)&cx)[0];
    bx0 = cx;

    uint64_t hi, lo, cl, ch;
    cl = ((uint64_t*)&l0[idx0 & 0x1FFFF0])[0];
    ch = ((uint64_t*)&l0[idx0 & 0x1FFFF0])[1];

    _umul128(idx0, cl, &hi,&lo);

    al0 += hi;
    ((uint64_t*)&l0[idx0 & 0x1FFFF0])[0] = al0;
    al0 ^= cl;
    ah0 += lo;
    ((uint64_t*)&l0[idx0 & 0x1FFFF0])[1] = ah0 ^ monero_const;
    ah0 ^= ch;
    idx0 = al0;
  }
  // Optim - 90% time boundary
  if(PREFETCH) cn_implode_scratchpad_be<MEM>((__m128i*)ctx0->long_state, (__m128i*)ctx0->hash_state);
  else cn_implode_scratchpad<MEM>((__m128i*)ctx0->long_state, (__m128i*)ctx0->hash_state);

  // Optim - 99% time boundary
  keccakf((uint64_t*)ctx0->hash_state, 24);
  extra_hashes[ctx0->hash_state[0] & 3](ctx0->hash_state, 200, (char*)output);
}

// This lovely creation will do 2 cn hashes at a time. We have plenty of space on silicon
// to fit temporary vars for two contexts. Function will read len*2 from input and write 64 bytes to output
// We are still limited by L3 cache, so doubling will only work with CPUs where we have more than 2MB to core (Xeons)
template<size_t ITERATIONS, size_t MEM, bool SOFT_AES, bool PREFETCH>
void cryptonight_double_hash(const void* input, size_t len, void* output, cryptonight_ctx* __restrict ctx0, cryptonight_ctx* __restrict ctx1)
{
  keccak((const uint8_t *)input, len, ctx0->hash_state, 200);
  keccak((const uint8_t *)input+len, len, ctx1->hash_state, 200);
  uint64_t monero_const_0 = *reinterpret_cast<const uint64_t*>(reinterpret_cast<const uint8_t*>(input) + 35);
  monero_const_0 ^= *(reinterpret_cast<const uint64_t*>(ctx0->hash_state) + 24);
  uint64_t monero_const_1 = *reinterpret_cast<const uint64_t*>(reinterpret_cast<const uint8_t*>(input) +len+ 35);
  monero_const_1 ^= *(reinterpret_cast<const uint64_t*>(ctx1->hash_state) + 24);

  // Optim - 99% time boundary
  if(PREFETCH){
    cn_explode_scratchpad_be<MEM>((__m128i*)ctx0->hash_state, (__m128i*)ctx0->long_state);
    cn_explode_scratchpad_be<MEM>((__m128i*)ctx1->hash_state, (__m128i*)ctx1->long_state);
  }else{
    cn_explode_scratchpad<MEM>((__m128i*)ctx0->hash_state, (__m128i*)ctx0->long_state);
    cn_explode_scratchpad<MEM>((__m128i*)ctx1->hash_state, (__m128i*)ctx1->long_state);
  }
  uint8_t* l0 = ctx0->long_state;
  uint64_t* h0 = (uint64_t*)ctx0->hash_state;
  uint8_t* l1 = ctx1->long_state;
  uint64_t* h1 = (uint64_t*)ctx1->hash_state;

  uint64_t axl0 = h0[0] ^ h0[4];
  uint64_t axh0 = h0[1] ^ h0[5];
  __m128i bx0 = (__m128ll){h0[2] ^ h0[6],h0[3] ^ h0[7]};
  uint64_t axl1 = h1[0] ^ h1[4];
  uint64_t axh1 = h1[1] ^ h1[5];
  __m128i bx1 = (__m128ll){h1[2] ^ h1[6],h1[3] ^ h1[7]} ;

  uint64_t idx0 = axl0;
  uint64_t idx1 = axl1;

 // Optim - 90% time boundary
  for (size_t i = 0; i < ITERATIONS; i++)
  {
    __m128i cx;
    cx = vec_vsx_ld(0,(__m128i *)&l0[idx0 & 0x1FFFF0]);
    cx = _mm_aesenc_si128(cx, (__m128ll){axl0,axh0});
    cryptonight_monero_tweak((uint64_t*)&l0[idx0 & 0x1FFFF0], vec_xor(bx0, cx));    
    idx0 = ((uint64_t*)&cx)[0];
    bx0 = cx;

    cx = vec_vsx_ld(0,(__m128i *)&l1[idx1 & 0x1FFFF0]);
    cx = _mm_aesenc_si128(cx, (__m128ll){axl1, axh1});
    cryptonight_monero_tweak((uint64_t*)&l1[idx1 & 0x1FFFF0], vec_xor(bx1, cx));
    idx1 = ((uint64_t*)&cx)[0];
    bx1 = cx;


    uint64_t hi, lo, cl, ch;
    cl = ((uint64_t*)&l0[idx0 & 0x1FFFF0])[0];
    ch = ((uint64_t*)&l0[idx0 & 0x1FFFF0])[1];

    _umul128(idx0, cl, &hi,&lo);

    axl0 += hi;
    axh0 += lo;
    ((uint64_t*)&l0[idx0 & 0x1FFFF0])[0] = axl0;
    ((uint64_t*)&l0[idx0 & 0x1FFFF0])[1] = axh0 ^ monero_const_0;
    axh0 ^= ch;
    axl0 ^= cl;
    idx0 = axl0;


    cl = ((uint64_t*)&l1[idx1 & 0x1FFFF0])[0];
    ch = ((uint64_t*)&l1[idx1 & 0x1FFFF0])[1];

    _umul128(idx1, cl, &hi,&lo);

    axl1 += hi;
    axh1 += lo;
    ((uint64_t*)&l1[idx1 & 0x1FFFF0])[0] = axl1;
    ((uint64_t*)&l1[idx1 & 0x1FFFF0])[1] = axh1 ^ monero_const_1;
    axh1 ^= ch;
    axl1 ^= cl;
    idx1 = axl1;
  }

 // Optim - 90% time boundary
  if(PREFETCH){
    cn_implode_scratchpad_be<MEM>((__m128i*)ctx0->long_state, (__m128i*)ctx0->hash_state);
    cn_implode_scratchpad_be<MEM>((__m128i*)ctx1->long_state, (__m128i*)ctx1->hash_state);
  }else{
    cn_implode_scratchpad<MEM>((__m128i*)ctx0->long_state, (__m128i*)ctx0->hash_state);
    cn_implode_scratchpad<MEM>((__m128i*)ctx1->long_state, (__m128i*)ctx1->hash_state);
  }
 // Optim - 99% time boundary

  keccakf((uint64_t*)ctx0->hash_state, 24);
  extra_hashes[ctx0->hash_state[0] & 3](ctx0->hash_state, 200, (char*)output);
  keccakf((uint64_t*)ctx1->hash_state, 24);
  extra_hashes[ctx1->hash_state[0] & 3](ctx1->hash_state, 200, (char*)output + 32);
}

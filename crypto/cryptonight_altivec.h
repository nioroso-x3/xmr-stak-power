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
static inline uint64_t _umul128(uint64_t a, uint64_t b, uint64_t* hi)
{
	unsigned __int128 r = (unsigned __int128)a * (unsigned __int128)b;
	*hi = r >> 64;
	return (uint64_t)r;
}

#if !defined(_LP64) && !defined(_WIN64)
#error You are trying to do a 32-bit build. This will all end in tears. I know it.
#endif

extern "C"
{
	void keccak(const uint8_t *in, int inlen, uint8_t *md, int mdlen);
	void keccakf(uint64_t st[25], int rounds);
	extern void(*const extra_hashes[4])(const void *, size_t, char *);

	__m128i soft_aesenc(__m128i in, __m128i key);
	__m128i soft_aeskeygenassist(__m128i key, uint8_t rcon);
}

// This will shift and xor tmp1 into itself as 4 32-bit vals such as
// sl_xor(a0 a1 a2 a3) = a0 (a1^a0) (a2^a1^a0) (a3^a2^a1^a0)
static inline __m128i sl_xor(__m128i tmp1)
{
	__m128i tmp4;
/*tmp4 = _mm_slli_si128(tmp1, 0x04);
	tmp1 = vec_xor(tmp1, tmp4);
	tmp4 = _mm_slli_si128(tmp4, 0x04);
	tmp1 = vec_xor(tmp1, tmp4);
	tmp4 = _mm_slli_si128(tmp4, 0x04);
	tmp1 = vec_xor(tmp1, tmp4);*/
	tmp4 = vec_slo(tmp1, (__m128i){0x20});
	tmp1 = vec_xor(tmp1, tmp4);
	tmp4 = vec_slo(tmp4, (__m128i){0x20});
	tmp1 = vec_xor(tmp1, tmp4);
	tmp4 = vec_slo(tmp4, (__m128i){0x20});
	tmp1 = vec_xor(tmp1, tmp4);

  return tmp1;
//  int* t = (int*)&tmp1;
//  return vec_set4sw(t[0],t[1]^t[0],t[2]^t[1]^t[0],t[3]^t[2]^t[1]^t[0]);
}

static inline __m128i v_rev(const __m128i& tmp1)
{
  return(vec_perm(tmp1,(__m128i){0},(__m128i){ 0xf,0xe,0xd,0xc,0xb,0xa,0x9,0x8,0x7,0x6,0x5,0x4,0x3,0x2,0x1,0x0 })); 
}


static inline __m128i _mm_aesenc_si128(__m128i in, __m128i key)
{
  //this thing works as big endian even though we are in little endian mode?
  //to skip this should we switch the endianness of the entire code base?

/*  __m128i t;
  uint8_t* in_ = (uint8_t*)&in;
  uint8_t* key_ = (uint8_t*)&key;
  uint8_t* t_ = (uint8_t*)&t;
  t = soft_aesenc(in,key);
  printf("    in: ");
  for(int i = 0; i < 16; ++i) printf("%02x ",in_[i]); printf("\n");
  printf("   key: ");
  for(int i = 0; i < 16; ++i) printf("%02x ",key_[i]); printf("\n");
  printf("  soft: ");
  for(int i = 0; i < 16; ++i) printf("%02x ",t_[i]); printf("\n");
  t =  __builtin_crypto_vcipher(v_rev(in),v_rev(key));
  printf("f_hard: ");
  for(int i = 0; i < 16; ++i) printf("%02x ",t_[i]); printf("\n");
  t= v_rev(t);
  printf("r_hard: ");
  for(int i = 0; i < 16; ++i) printf("%02x ",t_[i]); printf("\n");*/
 
  return v_rev(__builtin_crypto_vcipher(v_rev(in),v_rev(key)));
}


template<uint8_t rcon>
static inline void aes_genkey_sub(__m128i* xout0, __m128i* xout2)
{
	__m128i xout1 = soft_aeskeygenassist(*xout2, rcon);
  xout1 = vec_perm(xout1,xout1,(__m128i){0xc,0xd,0xe,0xf,0xc,0xd,0xe,0xf,0xc,0xd,0xe,0xf,0xc,0xd,0xe,0xf}); 
  *xout0 = sl_xor(*xout0);
	*xout0 = vec_xor(*xout0, xout1);
	xout1 = soft_aeskeygenassist(*xout0, 0x00);
  xout1 = vec_perm(xout1,xout1,(__m128i){0x8,0x9,0xa,0xb,0x8,0x9,0xa,0xb,0x8,0x9,0xa,0xb,0x8,0x9,0xa,0xb});
  *xout2 = sl_xor(*xout2);
	*xout2 = vec_xor(*xout2, xout1);
}

static inline void soft_aes_genkey_sub(__m128i* xout0, __m128i* xout2, uint8_t rcon)
{
	__m128i xout1 = soft_aeskeygenassist(*xout2, rcon);
  xout1 = vec_perm(xout1,xout1,(__m128i){0xc,0xd,0xe,0xf,0xc,0xd,0xe,0xf,0xc,0xd,0xe,0xf,0xc,0xd,0xe,0xf}); 
  *xout0 = sl_xor(*xout0);
	*xout0 = vec_xor(*xout0, xout1);
	xout1 = soft_aeskeygenassist(*xout0, 0x00);
  xout1 = vec_perm(xout1,xout1,(__m128i){0x8,0x9,0xa,0xb,0x8,0x9,0xa,0xb,0x8,0x9,0xa,0xb,0x8,0x9,0xa,0xb});
	*xout2 = sl_xor(*xout2);
	*xout2 = vec_xor(*xout2, xout1);
}

template<bool SOFT_AES>
static inline void aes_genkey(const __m128i* memory, __m128i* k0, __m128i* k1, __m128i* k2, __m128i* k3,
	__m128i* k4, __m128i* k5, __m128i* k6, __m128i* k7, __m128i* k8, __m128i* k9)
{
	__m128i xout0, xout2;

	xout0 = vec_ld(0,memory);
	xout2 = vec_ld(16,memory);
	*k0 = xout0;
	*k1 = xout2;

	if(SOFT_AES)
		soft_aes_genkey_sub(&xout0, &xout2, 0x01);
	else
		aes_genkey_sub<0x01>(&xout0, &xout2);
	*k2 = xout0;
	*k3 = xout2;

	if(SOFT_AES)
		soft_aes_genkey_sub(&xout0, &xout2, 0x02);
	else
		aes_genkey_sub<0x02>(&xout0, &xout2);
	*k4 = xout0;
	*k5 = xout2;

	if(SOFT_AES)
		soft_aes_genkey_sub(&xout0, &xout2, 0x04);
	else
		aes_genkey_sub<0x04>(&xout0, &xout2);
	*k6 = xout0;
	*k7 = xout2;

	if(SOFT_AES)
		soft_aes_genkey_sub(&xout0, &xout2, 0x08);
	else
		aes_genkey_sub<0x08>(&xout0, &xout2);
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

static inline void soft_aes_round(__m128i key, __m128i* x0, __m128i* x1, __m128i* x2, __m128i* x3, __m128i* x4, __m128i* x5, __m128i* x6, __m128i* x7)
{
	*x0 = soft_aesenc(*x0, key);
	*x1 = soft_aesenc(*x1, key);
	*x2 = soft_aesenc(*x2, key);
	*x3 = soft_aesenc(*x3, key);
	*x4 = soft_aesenc(*x4, key);
	*x5 = soft_aesenc(*x5, key);
	*x6 = soft_aesenc(*x6, key);
	*x7 = soft_aesenc(*x7, key);
}

template<size_t MEM, bool SOFT_AES, bool PREFETCH>
void cn_explode_scratchpad(const __m128i* input, __m128i* output)
{
	// This is more than we have registers, compiler will assign 2 keys on the stack
	__m128i xin0, xin1, xin2, xin3, xin4, xin5, xin6, xin7;
	__m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9;

	aes_genkey<SOFT_AES>(input, &k0, &k1, &k2, &k3, &k4, &k5, &k6, &k7, &k8, &k9);

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
		if(SOFT_AES)
		{
			soft_aes_round(k0, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			soft_aes_round(k1, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			soft_aes_round(k2, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			soft_aes_round(k3, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			soft_aes_round(k4, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			soft_aes_round(k5, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			soft_aes_round(k6, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			soft_aes_round(k7, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			soft_aes_round(k8, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			soft_aes_round(k9, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
		}
		else
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
		}

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

template<size_t MEM, bool SOFT_AES, bool PREFETCH>
void cn_implode_scratchpad(const __m128i* input, __m128i* output)
{
	// This is more than we have registers, compiler will assign 2 keys on the stack
	__m128i xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7;
	__m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9;

	aes_genkey<SOFT_AES>(output + 2, &k0, &k1, &k2, &k3, &k4, &k5, &k6, &k7, &k8, &k9);

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

		if(SOFT_AES)
		{
			soft_aes_round(k0, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			soft_aes_round(k1, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			soft_aes_round(k2, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			soft_aes_round(k3, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			soft_aes_round(k4, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			soft_aes_round(k5, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			soft_aes_round(k6, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			soft_aes_round(k7, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			soft_aes_round(k8, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			soft_aes_round(k9, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
		}
		else
		{
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

	// Optim - 99% time boundary
	cn_explode_scratchpad<MEM, SOFT_AES, PREFETCH>((__m128i*)ctx0->hash_state, (__m128i*)ctx0->long_state);

	uint8_t* l0 = ctx0->long_state;
	uint64_t* h0 = (uint64_t*)ctx0->hash_state;

	uint64_t al0 = h0[0] ^ h0[4];
	uint64_t ah0 = h0[1] ^ h0[5];
	__m128i bx0 = (__m128ll){h0[2] ^ h0[6],h0[3] ^ h0[7]};

	uint64_t idx0 = h0[0] ^ h0[4];

	// Optim - 90% time boundary
	for(size_t i = 0; i < ITERATIONS; i++)
	{
		__m128i cx;
		cx = vec_ld(0,(__m128i *)&l0[idx0 & 0x1FFFF0]);

		if(SOFT_AES)
			cx = soft_aesenc(cx, (__m128ll){al0, ah0});
		else
			cx = _mm_aesenc_si128(cx, (__m128ll){al0, ah0});

		vec_st(vec_xor(bx0, cx),0,(__m128i *)&l0[idx0 & 0x1FFFF0]);
		idx0 = ((uint64_t*)&cx)[0];
		bx0 = cx;

		uint64_t hi, lo, cl, ch;
		cl = ((uint64_t*)&l0[idx0 & 0x1FFFF0])[0];
		ch = ((uint64_t*)&l0[idx0 & 0x1FFFF0])[1];

		lo = _umul128(idx0, cl, &hi);

		al0 += hi;
		ah0 += lo;
		((uint64_t*)&l0[idx0 & 0x1FFFF0])[0] = al0;
		((uint64_t*)&l0[idx0 & 0x1FFFF0])[1] = ah0;
		ah0 ^= ch;
		al0 ^= cl;
		idx0 = al0;
	}
	// Optim - 90% time boundary
	cn_implode_scratchpad<MEM, SOFT_AES, PREFETCH>((__m128i*)ctx0->long_state, (__m128i*)ctx0->hash_state);
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

	// Optim - 99% time boundary
	cn_explode_scratchpad<MEM, SOFT_AES, PREFETCH>((__m128i*)ctx0->hash_state, (__m128i*)ctx0->long_state);
	cn_explode_scratchpad<MEM, SOFT_AES, PREFETCH>((__m128i*)ctx1->hash_state, (__m128i*)ctx1->long_state);

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

	uint64_t idx0 = h0[0] ^ h0[4];
	uint64_t idx1 = h1[0] ^ h1[4];

	// Optim - 90% time boundary
	for (size_t i = 0; i < ITERATIONS; i++)
	{
		__m128i cx;
		cx = vec_ld(0,(__m128i *)&l0[idx0 & 0x1FFFF0]);

		if(SOFT_AES)
			cx = soft_aesenc(cx,(__m128ll){ axl0,axh0});
		else
			cx = _mm_aesenc_si128(cx, (__m128ll){axl0,axh0});

		vec_st(vec_xor(bx0, cx),0,(__m128i *)&l0[idx0 & 0x1FFFF0]);
		idx0 = ((uint64_t*)&cx)[0];
		bx0 = cx;


		cx = vec_ld(0,(__m128i *)&l1[idx1 & 0x1FFFF0]);

		if(SOFT_AES)
			cx = soft_aesenc(cx, (__m128ll){axl1,axh1});
		else
			cx = _mm_aesenc_si128(cx, (__m128ll){axl1, axh1});

		vec_st(vec_xor(bx1, cx),0,(__m128i *)&l1[idx1 & 0x1FFFF0]);
		idx1 = ((uint64_t*)&cx)[0];
		bx1 = cx;


		uint64_t hi, lo, cl, ch;
		cl = ((uint64_t*)&l0[idx0 & 0x1FFFF0])[0];
		ch = ((uint64_t*)&l0[idx0 & 0x1FFFF0])[1];

		lo = _umul128(idx0, cl, &hi);

		axl0 += hi;
		axh0 += lo;
		((uint64_t*)&l0[idx0 & 0x1FFFF0])[0] = axl0;
		((uint64_t*)&l0[idx0 & 0x1FFFF0])[1] = axh0;
		axh0 ^= ch;
		axl0 ^= cl;
		idx0 = axl0;


		cl = ((uint64_t*)&l1[idx1 & 0x1FFFF0])[0];
		ch = ((uint64_t*)&l1[idx1 & 0x1FFFF0])[1];

		lo = _umul128(idx1, cl, &hi);

		axl1 += hi;
		axh1 += lo;
		((uint64_t*)&l1[idx1 & 0x1FFFF0])[0] = axl1;
		((uint64_t*)&l1[idx1 & 0x1FFFF0])[1] = axh1;
		axh1 ^= ch;
		axl1 ^= cl;
		idx1 = axl1;

	}

	// Optim - 90% time boundary
	cn_implode_scratchpad<MEM, SOFT_AES, PREFETCH>((__m128i*)ctx0->long_state, (__m128i*)ctx0->hash_state);
	cn_implode_scratchpad<MEM, SOFT_AES, PREFETCH>((__m128i*)ctx1->long_state, (__m128i*)ctx1->hash_state);

	// Optim - 99% time boundary

	keccakf((uint64_t*)ctx0->hash_state, 24);
	extra_hashes[ctx0->hash_state[0] & 3](ctx0->hash_state, 200, (char*)output);
	keccakf((uint64_t*)ctx1->hash_state, 24);
	extra_hashes[ctx1->hash_state[0] & 3](ctx1->hash_state, 200, (char*)output + 32);
}

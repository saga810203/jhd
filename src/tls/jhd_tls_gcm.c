#include <jhd_config.h>
#include <jhd_log.h>
#include <tls/jhd_tls_config.h>
#include <tls/jhd_tls_cipher_internal.h>
#include <tls/jhd_tls_gcm.h>

#include <string.h>

#include <tls/jhd_tls_aesni.h>


/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_UINT32_BE
#define GET_UINT32_BE(n,b,i)                            \
{                                                       \
    (n) = ( (uint32_t) (b)[(i)    ] << 24 )             \
        | ( (uint32_t) (b)[(i) + 1] << 16 )             \
        | ( (uint32_t) (b)[(i) + 2] <<  8 )             \
        | ( (uint32_t) (b)[(i) + 3]       );            \
}
#endif

#ifndef PUT_UINT32_BE
#define PUT_UINT32_BE(n,b,i)                            \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
#endif

typedef   void (*gcm_mult_pt)(jhd_tls_gcm_context *ctx, const unsigned char x[16], unsigned char output[16]) ;



/*
 * Precompute small multiples of H, that is set
 *      HH[i] || HL[i] = H times i,
 * where i is seen as a field element as in [MGV], ie high-order bits
 * correspond to low powers of P. The result is stored in the same way, that
 * is the high-order bit of HH corresponds to P^0 and the low-order bit of HL
 * corresponds to P^127.
 */
static void gcm_gen_table(jhd_tls_gcm_context *ctx) {
	int i, j;
	uint64_t hi, lo;
	uint64_t vl, vh;
	unsigned char h[16];

	mem_zero_16(h);


	ctx->cipher_ctx.cipher_info->base->ecb_encrypt_func(ctx->cipher_ctx.cipher_ctx,h, h);
	/* pack h as two 64-bits ints, big-endian */
	GET_UINT32_BE(hi, h, 0);
	GET_UINT32_BE(lo, h, 4);
	vh = (uint64_t) hi << 32 | lo;

	GET_UINT32_BE(hi, h, 8);
	GET_UINT32_BE(lo, h, 12);
	vl = (uint64_t) hi << 32 | lo;

	/* 8 = 1000 corresponds to 1 in GF(2^128) */
	ctx->HL[8] = vl;
	ctx->HH[8] = vh;

	if (aesni_support_clmul)
		return;


	/* 0 corresponds to 0 in GF(2^128) */
	ctx->HH[0] = 0;
	ctx->HL[0] = 0;

	for (i = 4; i > 0; i >>= 1) {
		uint32_t T = (vl & 1) * 0xe1000000U;
		vl = (vh << 63) | (vl >> 1);
		vh = (vh >> 1) ^ ((uint64_t) T << 32);

		ctx->HL[i] = vl;
		ctx->HH[i] = vh;
	}

	for (i = 2; i <= 8; i *= 2) {
		uint64_t *HiL = ctx->HL + i, *HiH = ctx->HH + i;
		vh = *HiH;
		vl = *HiL;
		for (j = 1; j < i; j++) {
			HiH[j] = vh ^ ctx->HH[j];
			HiL[j] = vl ^ ctx->HL[j];
		}
	}
}


void jhd_tls_gcm_setkey_enc(jhd_tls_gcm_context *gcm_ctx, const unsigned char *key, unsigned int keybits) {
	jhd_tls_cipher_context_t *ctx = &gcm_ctx->cipher_ctx;
	ctx->cipher_info->base->setkey_enc_func(ctx->cipher_ctx,key,keybits);
	gcm_gen_table(gcm_ctx);
}
void jhd_tls_gcm_setkey_dec(jhd_tls_gcm_context *gcm_ctx, const unsigned char *key, unsigned int keybits) {
	jhd_tls_cipher_context_t *ctx = &gcm_ctx->cipher_ctx;
	ctx->cipher_info->base->setkey_enc_func(ctx->cipher_ctx,key,keybits);
	gcm_gen_table(gcm_ctx);
}

/*
 * Shoup's method for multiplication use this table with
 *      last4[x] = x times P^128
 * where x and last4[x] are seen as elements of GF(2^128) as in [MGV]
 */
static const uint64_t last4[16] = { 0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0, 0xe100, 0xfd20, 0xd940, 0xc560, 0x9180, 0x8da0, 0xa9c0,
        0xb5e0 };


static void gcm_mult_with_aesni(jhd_tls_gcm_context *ctx, const unsigned char x[16], unsigned char output[16]) {
	unsigned char h[16];
	PUT_UINT32_BE(ctx->HH[8] >> 32, h, 0);
	PUT_UINT32_BE(ctx->HH[8], h, 4);
	PUT_UINT32_BE(ctx->HL[8] >> 32, h, 8);
	PUT_UINT32_BE(ctx->HL[8], h, 12);
	jhd_tls_aesni_gcm_mult(output, x, h);
}

static void gcm_mult_without_aesni(jhd_tls_gcm_context *ctx, const unsigned char x[16], unsigned char output[16]) {
	int i = 0;
	unsigned char lo, hi, rem;
	uint64_t zh, zl;
	lo = x[15] & 0xf;
	zh = ctx->HH[lo];
	zl = ctx->HL[lo];
	for (i = 15; i >= 0; i--) {
		lo = x[i] & 0xf;
		hi = x[i] >> 4;
		if (i != 15) {
			rem = (unsigned char) zl & 0xf;
			zl = (zh << 60) | (zl >> 4);
			zh = (zh >> 4);
			zh ^= (uint64_t) last4[rem] << 48;
			zh ^= ctx->HH[lo];
			zl ^= ctx->HL[lo];

		}
		rem = (unsigned char) zl & 0xf;
		zl = (zh << 60) | (zl >> 4);
		zh = (zh >> 4);
		zh ^= (uint64_t) last4[rem] << 48;
		zh ^= ctx->HH[hi];
		zl ^= ctx->HL[hi];
	}
	PUT_UINT32_BE(zh >> 32, output, 0);
	PUT_UINT32_BE(zh, output, 4);
	PUT_UINT32_BE(zl >> 32, output, 8);
	PUT_UINT32_BE(zl, output, 12);
}


/*
 * Sets output to x times H using the precomputed tables.
 * x and output are seen as elements of GF(2^128) as in [MGV].
 */
static void gcm_mult_auto_select(jhd_tls_gcm_context *ctx, const unsigned char x[16], unsigned char output[16]) {
	int i = 0;
	unsigned char lo, hi, rem;
	uint64_t zh, zl;

	if (aesni_support_clmul) {
		unsigned char h[16];

		PUT_UINT32_BE(ctx->HH[8] >> 32, h, 0);
		PUT_UINT32_BE(ctx->HH[8], h, 4);
		PUT_UINT32_BE(ctx->HL[8] >> 32, h, 8);
		PUT_UINT32_BE(ctx->HL[8], h, 12);

		jhd_tls_aesni_gcm_mult(output, x, h);
		return;
	}

	lo = x[15] & 0xf;

	zh = ctx->HH[lo];
	zl = ctx->HL[lo];

	for (i = 15; i >= 0; i--) {
		lo = x[i] & 0xf;
		hi = x[i] >> 4;

		if (i != 15) {
			rem = (unsigned char) zl & 0xf;
			zl = (zh << 60) | (zl >> 4);
			zh = (zh >> 4);
			zh ^= (uint64_t) last4[rem] << 48;
			zh ^= ctx->HH[lo];
			zl ^= ctx->HL[lo];

		}

		rem = (unsigned char) zl & 0xf;
		zl = (zh << 60) | (zl >> 4);
		zh = (zh >> 4);
		zh ^= (uint64_t) last4[rem] << 48;
		zh ^= ctx->HH[hi];
		zl ^= ctx->HL[hi];
	}

	PUT_UINT32_BE(zh >> 32, output, 0);
	PUT_UINT32_BE(zh, output, 4);
	PUT_UINT32_BE(zl >> 32, output, 8);
	PUT_UINT32_BE(zl, output, 12);
}



static gcm_mult_pt gcm_mult = gcm_mult_auto_select;

void jhd_tls_gcm_encrypt( jhd_tls_gcm_context *gcm_ctx,const unsigned char *fixed_iv,const unsigned char *ctr,const unsigned char *add,unsigned char *tag, uint16_t length, const unsigned char *input, unsigned char *output){
	jhd_tls_cipher_context_t *ctx ;
	jhd_tls_cipher_ecb_encrypt_pt ecb_func;
	unsigned char *p;
	unsigned char tmp_buf[16];
	unsigned char base_ectr[16];          /*!< The first ECTR for tag. */
	unsigned char y[16];                  /*!< The Y working value. */
	unsigned char buf[16];                /*!< The buf working value. */
	size_t i;
	uint64_t orig_len = ( length ) * 8;

	ctx = &gcm_ctx->cipher_ctx;
	ecb_func =ctx->cipher_info->base->ecb_encrypt_func;
	log_assert(16 == jhd_tls_cipher_get_block_size(ctx));
	//start
	p=y;
	memcpy_4(p,fixed_iv);
	p+=4;
	memcpy_8(p,ctr);
	p+=8;
	*((uint32_t*)(p)) = (uint32_t)(1<<24);
	ecb_func((void*)(ctx->cipher_ctx), y, base_ectr);
	p = buf;
	memcpy_8(p,add);
	p+=8;
	memcpy_4(p,8+add);
	p+=4;
	*((uint32_t*)(p)) = add[12];
	gcm_mult(gcm_ctx, buf,buf);
	//update
	p = (unsigned char*)input;
	while (length > 0) {
		for (i = 16; i > 12;){
			--i;
			if (++y[i] != 0){
				break;
			}
		}
		ecb_func(ctx->cipher_ctx,/* gcm_ctx->*/y,tmp_buf);
		if(length>=16){
			p128_xor(output,tmp_buf,p);

			p128_eq_xor(buf,output);

			gcm_mult(gcm_ctx, buf,buf);
			length -= 16;
			p += 16;
			output += 16;
		}else{
			for (i = 0; i < length; i++) {
				output[i] = tmp_buf[i] ^ p[i];
				buf[i] ^= output[i];
			}
			gcm_mult(gcm_ctx, buf, buf);
			length = 0;
		}
	}
	memcpy_16(tag,base_ectr);


	mem_zero_4(tmp_buf);
	PUT_UINT32_BE((13*8), tmp_buf, 4);
	mem_zero_4(8+tmp_buf);
	PUT_UINT32_BE((orig_len), tmp_buf, 12);
	p128_eq_xor(buf,tmp_buf);
	gcm_mult(gcm_ctx,buf, buf);
	p128_eq_xor(tag,buf);
}


void jhd_tls_gcm_decrypt( jhd_tls_gcm_context *gcm_ctx,const unsigned char *fixed_iv,const unsigned char *ctr,const unsigned char *add,unsigned char *tag, uint16_t length, const unsigned char *input, unsigned char *output){
	jhd_tls_cipher_context_t *ctx ;
	jhd_tls_cipher_ecb_encrypt_pt ecb_func;
	unsigned char *p;
	unsigned char tmp_buf[16];
	unsigned char base_ectr[16];          /*!< The first ECTR for tag. */
	unsigned char y[16];                  /*!< The Y working value. */
	unsigned char buf[16];                /*!< The buf working value. */
	size_t i;
	uint64_t orig_len = ( length ) * 8;

	ctx = &gcm_ctx->cipher_ctx;
	ecb_func = ctx->cipher_info->base->ecb_encrypt_func;
	log_assert(16 == jhd_tls_cipher_get_block_size(ctx));
	//start
	p=y;
	memcpy_4(p,fixed_iv);
	p+=4;
	memcpy_8(p,ctr);
	p+=8;
	*((uint32_t*)(p)) = (uint32_t)(1<<24);

	ecb_func(ctx->cipher_ctx, y, base_ectr);
	p = buf;
	memcpy_8(p,add);
	p+=8;
	memcpy_4(p,8+add);
	p+=4;
	*((uint32_t*)(p)) = add[12];
	gcm_mult(gcm_ctx, buf, buf);
	//update
	p = (unsigned char*)input;
	while (length > 0) {

		for (i = 16; i > 12;){
			--i;
			if (++y[i] != 0){
				break;
			}
		}
		ecb_func(ctx->cipher_ctx, y,tmp_buf);
		if(length >= 16){
			p128_eq_xor(buf,p);
			p128_xor(output,tmp_buf,p);

			gcm_mult(gcm_ctx, buf, buf);
			length -= 16;
			p += 16;
			output += 16;
		}else{
			for (i = 0; i < length; i++) {
				buf[i] ^= p[i];
				output[i] = tmp_buf[i] ^ p[i];
			}
			gcm_mult(gcm_ctx, buf, buf);
			length = 0;
		}
	}
	memcpy_16(tag,base_ectr);

	*((uint32_t*)(tmp_buf))= 0;
	PUT_UINT32_BE((13*8), tmp_buf, 4);
	*((uint32_t*)(8+tmp_buf))= 0;
	PUT_UINT32_BE((orig_len), tmp_buf, 12);
	p128_eq_xor(buf,tmp_buf);

	gcm_mult(gcm_ctx, buf, buf);
	p128_eq_xor(tag,buf);
}


void jhd_tls_gcm_init_with_aesni(){
	if(aesni_support_clmul){
		gcm_mult = gcm_mult_with_aesni;
	}else{
		gcm_mult = gcm_mult_without_aesni;
	}
}




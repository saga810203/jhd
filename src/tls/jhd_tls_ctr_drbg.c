#include <jhd_time.h>
#include <tls/jhd_tls_config.h>
#include <tls/jhd_tls_cipher_internal.h>
#include <tls/jhd_tls_ctr_drbg.h>

#include <string.h>
#include <stdio.h>

jhd_tls_ctr_drbg_context s_g_jhd_tls_ctr_drbg;

/*
 * Non-public function wrapped by jhd_tls_ctr_drbg_seed(). Necessary to allow
 * NIST tests to succeed (which require known length fixed entropy)
 */
void jhd_tls_ctr_drbg_seed(jhd_tls_ctr_drbg_context *ctx){
	unsigned char key[32];
	jhd_tls_platform_zeroize(key,32);
	jhd_tls_platform_zeroize(&ctx->aes_ctx,sizeof(jhd_tls_aes_context));
	ctx->reseed_interval = 10000;
	aes_info.setkey_enc_func(&ctx->aes_ctx,key,256);
	jhd_tls_ctr_drbg_reseed(ctx);
}
#if !defined(JHD_TLS_INLINE)
void jhd_tls_ctr_drbg_init(jhd_tls_ctr_drbg_context *ctx){
	memset(ctx,0,sizeof(jhd_tls_ctr_drbg_context));
}
#endif

static unsigned char s_g_ctr_drbg_key[32] ={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31};
static void block_cipher_df(unsigned char output[48],const unsigned char data[48]){
	unsigned char buf[96];
	unsigned char tmp[48];

	unsigned char chain[16];
	unsigned char *p,*iv;
	jhd_tls_aes_context aes_ctx;

	int j;
	size_t buf_len,use_len;


	jhd_tls_platform_zeroize(buf,96);
	jhd_tls_platform_zeroize(&aes_ctx,sizeof(jhd_tls_aes_context));

	/*
	 * Construct IV (16 bytes) and S in buffer
	 * IV = Counter (in 32-bits) padded to 16 with zeroes
	 * S = Length input string (in 32-bits) || Length of output (in 32-bits) ||
	 *     data || 0x80
	 *     (Total is padded to a multiple of 16-bytes with zeroes)
	 */
	p = buf + 16;

	*((uint32_t*)(p)) = 48 << 24;

	p += 7;
	*p++ = 48;

	memcpy_16(p,data);
	memcpy_16(p+8,data+8);
	memcpy_16(p+16,data+16);
	p[48] = 0x80;

	buf_len = 16 + 8 + 48 + 1;


	aes_info.setkey_enc_func(&aes_ctx,s_g_ctr_drbg_key,256);

	/*
	 * Reduce data to JHD_TLS_CTR_DRBG_SEEDLEN bytes of data
	 */
	for(j = 0;j < 48;j += 16){
		p = buf;
		mem_zero_16(chain);
		use_len = buf_len;

		while(use_len > 0){
			p128_eq_xor(chain,p);
			p128_eq_xor(chain+8,p+8);
			p += 16;
			use_len -= (use_len >= 16)?	16:use_len;
			aes_info.ecb_encrypt_func(&aes_ctx,chain,chain);
		}
		memcpy_16(tmp+j,chain);
		buf[3]++;
	}
	aes_info.setkey_enc_func(&aes_ctx,tmp,256);
	iv = tmp + 32;
	p = output;

	aes_info.ecb_encrypt_func(&aes_ctx,iv,iv);
	memcpy_16(p,iv);
	p += 16;
	aes_info.ecb_encrypt_func(&aes_ctx,iv,iv);
	memcpy_16(p,iv);
	p += 16;
	aes_info.ecb_encrypt_func(&aes_ctx,iv,iv);
	memcpy_16(p,iv);
}

static void ctr_drbg_update_internal(jhd_tls_ctr_drbg_context *ctx,const unsigned char data[48]){
	unsigned char tmp[48];
	unsigned char *p = tmp;
	int i;
	*((uint64_t*)(tmp))=0;
	*((uint64_t*)(tmp+8))=0;
	*((uint64_t*)(tmp+16))=0;
	*((uint64_t*)(tmp+24))=0;
	*((uint64_t*)(tmp+32))=0;
	*((uint64_t*)(tmp+40))=0;


	for(i = 16;i > 0;){
		--i;
		if(++ctx->counter[i] != 0){
			break;
		}
	}
	aes_info.ecb_encrypt_func(&ctx->aes_ctx,ctx->counter,p);
	p += 16;
	for(i = 16;i > 0;){
		--i;
		if(++ctx->counter[i] != 0){
			break;
		}
	}
	aes_info.ecb_encrypt_func(&ctx->aes_ctx,ctx->counter,p);
	p += 16;
	for(i = 16;i > 0;){
		--i;
		if(++ctx->counter[i] != 0){
			break;
		}
	}
	aes_info.ecb_encrypt_func(&ctx->aes_ctx,ctx->counter,p);
	p += 16;

	p128_eq_xor(tmp,data);
	p128_eq_xor(tmp+8,data+8);
	p128_eq_xor(tmp+16,data+16);
	aes_info.setkey_enc_func(&ctx->aes_ctx,tmp,256);
	memcpy_16(ctx->counter,tmp + 32);
}

void jhd_tls_ctr_drbg_reseed(jhd_tls_ctr_drbg_context *ctx){
	unsigned char tmp[48];
	uint64_t process_random_key;
	jhd_tls_entropy_context entropy;
	process_random_key = jhd_current_msec + ((uint64_t)jhd_pid);
	jhd_tls_entropy_init(&entropy);
	*((uint64_t*)(tmp))=0;
	*((uint64_t*)(tmp+8))=0;
	*((uint64_t*)(tmp+16))=0;
	*((uint64_t*)(tmp+24))=0;
	*((uint64_t*)(tmp+32))=0;
	*((uint64_t*)(tmp+40))=0;
	jhd_tls_entropy_init(&entropy);

	jhd_tls_entropy_func(&entropy,tmp,48);

	*((uint64_t*)tmp) = process_random_key;

	block_cipher_df(tmp,tmp);
	ctr_drbg_update_internal(ctx,tmp);
	ctx->reseed_counter = 1;

}

static void jhd_tls_ctr_drbg_random_with_add(void *p_rng,unsigned char *output,size_t output_len){
	jhd_tls_ctr_drbg_context *ctx = (jhd_tls_ctr_drbg_context *)p_rng;
	unsigned char add_input[48];
	unsigned char *p = output;
	unsigned char tmp[16];
	int i;
	if(ctx->reseed_counter > ctx->reseed_interval || ctx->prediction_resistance){
		jhd_tls_ctr_drbg_reseed(ctx);
	}

	while(output_len > 0){
		/*
		 * Increase counter
		 */
		for(i = 16;i > 0;i--){
			if(++ctx->counter[i - 1] != 0)
				break;
		}
		aes_info.ecb_encrypt_func(&ctx->aes_ctx,ctx->counter,tmp);
		if(output_len >=16){
			memcpy_16(p,tmp);
			output_len -= 16;
			p+=16;
		}else{
			memcpy(p,tmp,output_len);
			break;
		}
	}
	ctr_drbg_update_internal(ctx,add_input);
	ctx->reseed_counter++;
}

void jhd_tls_ctr_drbg_random(void *p_rng,unsigned char *output,size_t output_len){
	log_assert(output_len <=1024);
	jhd_tls_ctr_drbg_random_with_add((jhd_tls_ctr_drbg_context *)p_rng,output,output_len);

}

void jhd_tls_random_init(){
	jhd_tls_ctr_drbg_init(&s_g_jhd_tls_ctr_drbg);
	jhd_tls_ctr_drbg_seed(&s_g_jhd_tls_ctr_drbg);
}

#if !defined(JHD_TLS_INLINE)
void jhd_tls_random32_with_time(unsigned char *p){
	p[0] = (unsigned char)(jhd_cache_time >> 24);
	p[1] = (unsigned char)(jhd_cache_time >> 16);
	p[2] = (unsigned char)(jhd_cache_time >> 8);
	p[3] = (unsigned char)(jhd_cache_time);
	jhd_tls_ctr_drbg_random((void*)&s_g_jhd_tls_ctr_drbg,&(p[4]),28);
}
void jhd_tls_random(unsigned char* p,size_t len){
	log_assert(len <=1024);
	jhd_tls_ctr_drbg_random_with_add(&s_g_jhd_tls_ctr_drbg,p,len);
}
#endif


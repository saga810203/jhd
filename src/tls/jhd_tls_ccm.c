#include <jhd_config.h>
#include <jhd_log.h>
#include <tls/jhd_tls_config.h>
#include <tls/jhd_tls_ccm.h>
#include <string.h>
#include <tls/jhd_tls_platform.h>

void jhd_tls_ccm_setkey(jhd_tls_ccm_context *ccm_ctx,const unsigned char *key,unsigned int keybits){
	jhd_tls_cipher_context_t *ctx = &ccm_ctx->cipher_ctx;
	log_assert(keybits == ctx->cipher_info->key_bitlen);
	ctx->cipher_info->base->setkey_enc_func(ctx->cipher_ctx,key,keybits);
}

#define CCM_UPDATE_CBC_MAC_BEGIN   memcpy_16(tag,b);ecb_func(ctx->cipher_ctx, tag, tag);

#define CCM_UPDATE_CBC_MAC   p128_eq_xor(tag,b);ecb_func(ctx->cipher_ctx, tag, tag);


#define CCM_CTR_CRYPT_16(dst, src)  ecb_func(ctx->cipher_ctx, tmp_ctr, b);p128_xor(dst,src,b);


#define CCM_CTR_CRYPT(dst, src)  ecb_func(ctx->cipher_ctx, tmp_ctr, b); for(i = 0 ; i < length;++i){dst[i] = src[i] ^ b[i];}

void jhd_tls_ccm_encrypt( jhd_tls_ccm_context *ccm_ctx,const unsigned char *fixed_iv,const unsigned char *ctr,const unsigned char *add,unsigned char *tag, uint16_t length, const unsigned char *input, unsigned char *output){
	    jhd_tls_cipher_context_t *ctx ;
		unsigned char i;
		unsigned char b[16];
		unsigned char tmp_ctr[16];
		jhd_tls_cipher_ecb_encrypt_pt ecb_func;
		ctx= &ccm_ctx->cipher_ctx;
		ecb_func = ctx->cipher_info->base->ecb_encrypt_func;


		b[0] = (1 << 6) |(((16 - 2)/2) << 3) | 2;
		memcpy_4(b+1,fixed_iv);
		memcpy_8(b+5,ctr);

		b[13]=0;
		b[14]=(unsigned char)(length >> 8);
		b[15]=(unsigned char)(length);

		CCM_UPDATE_CBC_MAC_BEGIN

		b[0] = 0;
		b[1] = 13;
		memcpy_8(b+2,add);
		memcpy_4(b+10,add+8);
		b[14] = add[12];
		b[15] = 0;

		CCM_UPDATE_CBC_MAC

		tmp_ctr[0] = 0x02;
		memcpy_4(tmp_ctr+1,fixed_iv);
		memcpy_8(tmp_ctr+5,ctr);
		tmp_ctr[13] = 0;
		tmp_ctr[14] = 0;
		tmp_ctr[15] = 1;


		while (length > 0) {
			if(length >= 16){
				memcpy_16(b,input);
				CCM_UPDATE_CBC_MAC
				CCM_CTR_CRYPT_16(output,input);
				output += 16;
				input += 16;
				length -= 16;
			}else{
				mem_zero_16(b);
				memcpy(b, input, length);
				CCM_UPDATE_CBC_MAC
				CCM_CTR_CRYPT(output,input);
				break;
			}
			if(++tmp_ctr[15] == 0){
				if(++tmp_ctr[14] == 0){
					++tmp_ctr[13];
				}
			}

		}
		tmp_ctr[15]= 0;
		tmp_ctr[14]= 0;
		tmp_ctr[13]= 0;
		CCM_CTR_CRYPT_16(tag,tag);
}

void jhd_tls_ccm_decrypt( jhd_tls_ccm_context *ccm_ctx,const unsigned char *fixed_iv,const unsigned char *ctr,const unsigned char *add,unsigned char *tag, uint16_t length, const unsigned char *input, unsigned char *output){
    jhd_tls_cipher_context_t *ctx ;
	unsigned char i;
	unsigned char b[16];
	unsigned char tmp_ctr[16];

	jhd_tls_cipher_ecb_encrypt_pt ecb_func;
	ctx= &ccm_ctx->cipher_ctx;
	ecb_func = ctx->cipher_info->base->ecb_encrypt_func;

	b[0] = (1 << 6) |(((16 - 2)/2) << 3) | 2;
	memcpy_4(b+1,fixed_iv);
	memcpy_8(b+5,ctr);
	b[13]=(unsigned char)(0);
	b[14]=(unsigned char)(length>>8);
	b[15]=(unsigned char)length;

	CCM_UPDATE_CBC_MAC_BEGIN

	b[0] = 0;
	b[1] = 13;
	memcpy_8(b+2,add);
	memcpy_4(b+10,add+8);
	b[14] = add[12];
	b[15] = 0;

	CCM_UPDATE_CBC_MAC

	tmp_ctr[0] = 0x02;
	memcpy_4(tmp_ctr+1,fixed_iv);
	memcpy_8(tmp_ctr+5,ctr);
	tmp_ctr[13] = 0;
	tmp_ctr[14] = 0;
	tmp_ctr[15] = 1;


	while (length > 0) {
		if(length >= 16){
			CCM_CTR_CRYPT_16(output,input)
			memcpy_16(b,output);
			CCM_UPDATE_CBC_MAC
			output += 16;
			input += 16;
			length -= 16;
		}else{

			CCM_CTR_CRYPT(output,input)
			mem_zero_16(b);
			memcpy(b, output, length);
			CCM_UPDATE_CBC_MAC
			break;
		}
		if(++tmp_ctr[15] == 0){
			if(++tmp_ctr[14] == 0){
				++tmp_ctr[13];
			}
		}
	}
	tmp_ctr[15]= 0;
	tmp_ctr[14]= 0;
	tmp_ctr[13]= 0;
	CCM_CTR_CRYPT_16(tag,tag)
}



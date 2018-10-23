#include <jhd_config.h>
#include <jhd_log.h>
#include <tls/jhd_tls_config.h>

#include <tls/jhd_tls_md.h>
#include <tls/jhd_tls_md_internal.h>
#include <tls/jhd_tls_sha512.h>

#include <tls/jhd_tls_platform.h>

#include <string.h>

/*
 * Reminder: update profiles in x509_crt.c when adding a new hash!
 */

#if !defined(JHD_TLS_INLINE)


void jhd_tls_md_starts(jhd_tls_md_info_t *md_info,void *md_ctx) {
	md_info->starts_func(md_ctx);
}
void jhd_tls_md_update(jhd_tls_md_info_t *md_info,void *md_ctx, const unsigned char *input, size_t ilen) {
	md_info->update_func(md_ctx, input, ilen);
}

void jhd_tls_md_finish(jhd_tls_md_info_t *md_info,void *md_ctx, unsigned char *output) {
	md_info->finish_func(md_ctx, output);
}

void jhd_tls_md(const jhd_tls_md_info_t *md_info, const unsigned char *input, size_t ilen, unsigned char *output) {
	(md_info->digest_func(input, ilen, output));
}
void jhd_tls_md_process(jhd_tls_md_info_t *md_info,void *md_ctx, const unsigned char *data) {

	md_info->process_func(md_ctx, data);
}

uint8_t jhd_tls_md_get_size(const jhd_tls_md_info_t *md_info) {
	return md_info->size;
}
const char *jhd_tls_md_get_name(const jhd_tls_md_info_t *md_info) {
	if (md_info == NULL)
		return ( NULL);

	return md_info->name;
}



#endif






void jhd_tls_md_hmac(const jhd_tls_md_info_t *md_info, const unsigned char *key, size_t keylen, const unsigned char *input, size_t ilen, unsigned char *output) {
	unsigned char ctx[sizeof(jhd_tls_sha512_context)];
	unsigned char hmac_ctx[256];
	unsigned char tmp[64];
	jhd_tls_md_hmac_init(md_info,key,keylen,hmac_ctx);
	jhd_tls_md_hmac_starts(md_info,ctx,hmac_ctx);
	jhd_tls_md_hmac_update(md_info,ctx,input,ilen);
	jhd_tls_md_hmac_finish(md_info,ctx,hmac_ctx,output,tmp);
}

void jhd_tls_md_test_finish(jhd_tls_md_info_t *md_info,void *ctx){
	unsigned char tmp_val[128];
	unsigned char tmp_ctx[256];

	unsigned char tmp_title[128];
	sprintf(tmp_title,"%s:md==>",md_info->name);
	memcpy(tmp_ctx,ctx,md_info->ctx_size);
	md_info->finish_func(tmp_ctx,tmp_val);
	log_buf_debug(tmp_title,tmp_val,md_info->size);
}


void jhd_tls_md_hmac_init(const jhd_tls_md_info_t *md_info,const unsigned char *key, size_t keylen,unsigned char *hmac_ctx){
	unsigned char sum[JHD_TLS_MD_MAX_SIZE];
	unsigned char *ipad, *opad;
	unsigned char md_ctx[256];
	size_t i;
	log_assert(md_info->ctx_size<=256);

		if (keylen > md_info->block_size) {
			md_info->starts_func(md_ctx);
			md_info->update_func(md_ctx, key, keylen);
			md_info->finish_func(md_ctx, sum);
			keylen = md_info->size;
			key = sum;
		}

		ipad = (unsigned char *) hmac_ctx;
		opad = (unsigned char *) hmac_ctx + md_info->block_size;

		log_assert(md_info->block_size==64 || md_info->block_size == 128);

		*((uint64_t*) ipad) = 0x3636363636363636ULL;
		ipad += 8;
		*((uint64_t*) opad) = 0x5C5C5C5C5C5C5C5CULL;
		opad += 8;
		*((uint64_t*) ipad) = 0x3636363636363636ULL;
		ipad += 8;
		*((uint64_t*) opad) = 0x5C5C5C5C5C5C5C5CULL;
		opad += 8;
		*((uint64_t*) ipad) = 0x3636363636363636ULL;
		ipad += 8;
		*((uint64_t*) opad) = 0x5C5C5C5C5C5C5C5CULL;
		opad += 8;
		*((uint64_t*) ipad) = 0x3636363636363636ULL;
		ipad += 8;
		*((uint64_t*) opad) = 0x5C5C5C5C5C5C5C5CULL;
		opad += 8;
		*((uint64_t*) ipad) = 0x3636363636363636ULL;
		ipad += 8;
		*((uint64_t*) opad) = 0x5C5C5C5C5C5C5C5CULL;
		opad += 8;
		*((uint64_t*) ipad) = 0x3636363636363636ULL;
		ipad += 8;
		*((uint64_t*) opad) = 0x5C5C5C5C5C5C5C5CULL;
		opad += 8;
		*((uint64_t*) ipad) = 0x3636363636363636ULL;
		ipad += 8;
		*((uint64_t*) opad) = 0x5C5C5C5C5C5C5C5CULL;
		opad += 8;
		*((uint64_t*) ipad) = 0x3636363636363636ULL;
		*((uint64_t*) opad) = 0x5C5C5C5C5C5C5C5CULL;
		if( md_info->block_size == 64){
			opad-=56;
			ipad-=56;
		}else{
			opad += 8;
			ipad += 8;
			*((uint64_t*) ipad) = 0x3636363636363636ULL;
			ipad += 8;
			*((uint64_t*) opad) = 0x5C5C5C5C5C5C5C5CULL;
			opad += 8;
			*((uint64_t*) ipad) = 0x3636363636363636ULL;
			ipad += 8;
			*((uint64_t*) opad) = 0x5C5C5C5C5C5C5C5CULL;
			opad += 8;
			*((uint64_t*) ipad) = 0x3636363636363636ULL;
			ipad += 8;
			*((uint64_t*) opad) = 0x5C5C5C5C5C5C5C5CULL;
			opad += 8;
			*((uint64_t*) ipad) = 0x3636363636363636ULL;
			ipad += 8;
			*((uint64_t*) opad) = 0x5C5C5C5C5C5C5C5CULL;
			opad += 8;
			*((uint64_t*) ipad) = 0x3636363636363636ULL;
			ipad += 8;
			*((uint64_t*) opad) = 0x5C5C5C5C5C5C5C5CULL;
			opad += 8;
			*((uint64_t*) ipad) = 0x3636363636363636ULL;
			ipad += 8;
			*((uint64_t*) opad) = 0x5C5C5C5C5C5C5C5CULL;
			opad += 8;
			*((uint64_t*) ipad) = 0x3636363636363636ULL;
			ipad += 8;
			*((uint64_t*) opad) = 0x5C5C5C5C5C5C5C5CULL;
			opad += 8;
			*((uint64_t*) ipad) = 0x3636363636363636ULL;
			*((uint64_t*) opad) = 0x5C5C5C5C5C5C5C5CULL;
			opad-=120;
			ipad-=120;
		}
		for (i = 0; i < keylen; i++) {
			ipad[i] = (unsigned char) (ipad[i] ^ key[i]);
			opad[i] = (unsigned char) (opad[i] ^ key[i]);
		}
}

#if !defined(JHD_TLS_INLINE)
void jhd_tls_md_hmac_starts(const jhd_tls_md_info_t *md_info,void *md_ctx,unsigned char *hmac_ctx){
	md_info->starts_func(md_ctx);
	md_info->update_func(md_ctx, hmac_ctx,md_info->block_size);
}
void jhd_tls_md_hmac_update(const jhd_tls_md_info_t *md_info,void *md_ctx,const unsigned char *input, size_t ilen){
	md_info->update_func(md_ctx, input, ilen);
}
void jhd_tls_md_hmac_finish(const jhd_tls_md_info_t *md_info,void *md_ctx,unsigned char *hmac_ctx,unsigned char *output,unsigned char *temp){
	md_info->finish_func(md_ctx, temp);
	md_info->starts_func(md_ctx);
	md_info->update_func(md_ctx, hmac_ctx + md_info->block_size,md_info->block_size);
	md_info->update_func(md_ctx, temp,md_info->size);
	md_info->finish_func(md_ctx, output);
}
#endif



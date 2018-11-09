
#include <tls/jhd_tls_config.h>
#include <jhd_config.h>
#include <jhd_log.h>
#include <tls/jhd_tls_platform.h>

#include <tls/jhd_tls_ssl.h>
#include <tls/jhd_tls_ssl_internal.h>

#include <string.h>
#include <tls/jhd_tls_oid.h>
#include <tls/jhd_tls_md_internal.h>
#include <tls/jhd_tls_pk_internal.h>
#include <tls/jhd_tls_x509_crt.h>
#include <tls/jhd_tls_gcm.h>
#include <tls/jhd_tls_ccm.h>

/*
 * Convert max_fragment_length codes to length.
 * RFC 6066 says:
 *    enum{
 *        2^9(1), 2^10(2), 2^11(3), 2^12(4), (255)
 *    } MaxFragmentLength;
 * and we add 0 -> extension unused
 */
static unsigned int mfl_code_to_length[JHD_TLS_SSL_MAX_FRAG_LEN_INVALID] = {
JHD_TLS_SSL_MAX_CONTENT_LEN, /* JHD_TLS_SSL_MAX_FRAG_LEN_NONE */
512, /* JHD_TLS_SSL_MAX_FRAG_LEN_512  */
1024, /* JHD_TLS_SSL_MAX_FRAG_LEN_1024 */
2048, /* JHD_TLS_SSL_MAX_FRAG_LEN_2048 */
4096, /* JHD_TLS_SSL_MAX_FRAG_LEN_4096 */
};



void jhd_tls_tls1_prf(const unsigned char *secret, size_t slen, const char *label, const unsigned char *random, size_t rlen, unsigned char *dstbuf, size_t dlen) {
	size_t nb, hs;
	size_t i, j, k;
	const unsigned char *S1, *S2;
	unsigned char tmp[128],md_ctx[128],hmac_ctx[128],hmac_tmp[64];
	unsigned char h_i[20];

	hs = (slen + 1) / 2;
	S1 = secret;
	S2 = secret + slen - hs;

	nb = strlen(label);
	memcpy(tmp + 20, label, nb);
	memcpy(tmp + 20 + nb, random, rlen);
	nb += rlen;


	jhd_tls_md_hmac_init(&jhd_tls_md5_info,S1,hs,hmac_ctx);
	jhd_tls_md_hmac_starts(&jhd_tls_md5_info,md_ctx,hmac_ctx);

	jhd_tls_md_hmac_update(&jhd_tls_md5_info,md_ctx,tmp + 20, nb);
	jhd_tls_md_hmac_finish(&jhd_tls_md5_info,md_ctx,hmac_ctx, 4 + tmp,hmac_tmp);

	for (i = 0; i < dlen; i += 16) {
		jhd_tls_md_hmac_starts(&jhd_tls_md5_info,md_ctx,hmac_ctx);
		jhd_tls_md_hmac_update(&jhd_tls_md5_info,md_ctx,4 + tmp, 16 + nb);
		jhd_tls_md_hmac_finish(&jhd_tls_md5_info,md_ctx,hmac_ctx, h_i,hmac_tmp);

		jhd_tls_md_hmac_starts(&jhd_tls_md5_info,md_ctx,hmac_ctx);
		jhd_tls_md_hmac_update(&jhd_tls_md5_info,md_ctx,4 + tmp, 16 );
		jhd_tls_md_hmac_finish(&jhd_tls_md5_info,md_ctx,hmac_ctx, 4 + tmp,hmac_tmp);
		k = (i + 16 > dlen) ? dlen % 16 : 16;
		for (j = 0; j < k; j++){
			dstbuf[i + j] = h_i[j];
		}
	}


	/*
	 * XOR out with P_sha1(secret,label+random)[0..dlen]
	 */
	jhd_tls_md_hmac_init(&jhd_tls_sha1_info,S2,hs,hmac_ctx);
	jhd_tls_md_hmac_starts(&jhd_tls_sha1_info,md_ctx,hmac_ctx);
	jhd_tls_md_hmac_update(&jhd_tls_sha1_info,md_ctx,tmp+20 ,nb);
	jhd_tls_md_hmac_finish(&jhd_tls_sha1_info,md_ctx,hmac_ctx,  tmp,hmac_tmp);
	for (i = 0; i < dlen; i += 20) {
		jhd_tls_md_hmac_starts(&jhd_tls_sha1_info,md_ctx,hmac_ctx);
		jhd_tls_md_hmac_update(&jhd_tls_sha1_info,md_ctx,tmp , 20+nb);
		jhd_tls_md_hmac_finish(&jhd_tls_sha1_info,md_ctx,hmac_ctx,  h_i,hmac_tmp);

		jhd_tls_md_hmac_starts(&jhd_tls_sha1_info,md_ctx,hmac_ctx);
		jhd_tls_md_hmac_update(&jhd_tls_sha1_info,md_ctx,tmp, 20);
		jhd_tls_md_hmac_finish(&jhd_tls_sha1_info,md_ctx,hmac_ctx,  tmp,hmac_tmp);

		k = (i + 20 > dlen) ? dlen % 20 : 20;

		for (j = 0; j < k; j++){
			dstbuf[i + j] = (unsigned char) (dstbuf[i + j] ^ h_i[j]);
		}
	}
}

static void tls_prf_generic(const jhd_tls_md_info_t *md_info, const unsigned char *secret, size_t slen, const char *label, const unsigned char *random,
        size_t rlen, unsigned char *dstbuf, size_t dlen) {
	size_t nb;
	size_t i, j, k, md_len;
	unsigned char tmp[128];
	unsigned char h_i[JHD_TLS_MD_MAX_SIZE];

	unsigned char md_ctx[sizeof(jhd_tls_sha512_context)];
	unsigned char hmac_ctx[256],md_tmp[64];
	md_len = md_info->size;
	nb = strlen(label);
	memcpy(tmp + md_len, label, nb);
	memcpy(tmp + md_len + nb, random, rlen);
	nb += rlen;

	jhd_tls_md_hmac_init(md_info,secret,slen,hmac_ctx);
	jhd_tls_md_hmac_starts(md_info,md_ctx,hmac_ctx);
	jhd_tls_md_hmac_update(md_info,md_ctx, tmp + md_len, nb);
	jhd_tls_md_hmac_finish(md_info,md_ctx,hmac_ctx, tmp,md_tmp);

	for (i = 0; i < dlen; i += md_len) {
		jhd_tls_md_hmac_starts(md_info,md_ctx,hmac_ctx);
		jhd_tls_md_hmac_update(md_info,md_ctx, tmp, md_len + nb);
		jhd_tls_md_hmac_finish(md_info,md_ctx,hmac_ctx, h_i,md_tmp);

		jhd_tls_md_hmac_starts(md_info,md_ctx,hmac_ctx);
		jhd_tls_md_hmac_update(md_info,md_ctx,tmp, md_len);
		jhd_tls_md_hmac_finish(md_info,md_ctx,hmac_ctx, tmp,md_tmp);
		k = (i + md_len > dlen) ? dlen % md_len : md_len;
		for (j = 0; j < k; j++){
			dstbuf[i + j] = h_i[j];
		}
	}
}

static void tls_prf_sha256(const unsigned char *secret, size_t slen, const char *label, const unsigned char *random, size_t rlen, unsigned char *dstbuf,
        size_t dlen) {
	tls_prf_generic(&jhd_tls_sha256_info, secret, slen, label, random, rlen, dstbuf, dlen);
}

static void tls_prf_sha384(const unsigned char *secret, size_t slen, const char *label, const unsigned char *random, size_t rlen, unsigned char *dstbuf,
        size_t dlen) {
	tls_prf_generic(&jhd_tls_sha384_info, secret, slen, label, random, rlen, dstbuf, dlen);
}

static void ssl_update_checksum_start(jhd_tls_ssl_context *, const unsigned char *, size_t);

static void ssl_update_checksum_md5sha1(jhd_tls_ssl_context *, const unsigned char *, size_t);

static void ssl_calc_verify_tls(jhd_tls_ssl_context *, unsigned char *);
static void ssl_calc_finished_tls(jhd_tls_ssl_context *, unsigned char *, int);

static void ssl_update_checksum_sha256(jhd_tls_ssl_context *, const unsigned char *, size_t);
static void ssl_calc_verify_tls_sha256(jhd_tls_ssl_context *, unsigned char *);
static void ssl_calc_finished_tls_sha256(jhd_tls_ssl_context *, unsigned char *, int);

static void ssl_update_checksum_sha384(jhd_tls_ssl_context *, const unsigned char *, size_t);
static void ssl_calc_verify_tls_sha384(jhd_tls_ssl_context *, unsigned char *);
static void ssl_calc_finished_tls_sha384(jhd_tls_ssl_context *, unsigned char *, int);

void jhd_tls_ssl_derive_keys(jhd_tls_ssl_context *ssl) {
	unsigned char tmp[64];
	unsigned char keyblk[256];
	unsigned char *key1;
	unsigned char *key2;
	unsigned int  keylen;

	size_t mac_key_len;
	const jhd_tls_ssl_ciphersuite_t * ciphersuite_info;
	const jhd_tls_cipher_info_t *cipher_info;
	const jhd_tls_md_info_t *md_info;

	jhd_tls_ssl_handshake_params *handshake = ssl->handshake;

	log_notice("%s", ( "=> derive keys" ));
	ciphersuite_info =ssl->handshake->ciphersuite_info;
	cipher_info = jhd_tls_cipher_info_from_type(ciphersuite_info->cipher);
	md_info = ssl->handshake->ciphersuite_info->md_info;
	log_assert(ssl->minor_ver >=JHD_TLS_SSL_MINOR_VERSION_1 &&  ssl->minor_ver <= JHD_TLS_SSL_MINOR_VERSION_3);
	if (ssl->minor_ver < JHD_TLS_SSL_MINOR_VERSION_3) {
		handshake->tls_prf = jhd_tls_tls1_prf;
		handshake->calc_verify = ssl_calc_verify_tls;
		handshake->calc_finished = ssl_calc_finished_tls;
	} else	if (ciphersuite_info->md_info == &jhd_tls_sha384_info) {
		handshake->tls_prf = tls_prf_sha384;
		handshake->calc_verify = ssl_calc_verify_tls_sha384;
		handshake->calc_finished = ssl_calc_finished_tls_sha384;
	} else{
		handshake->tls_prf = tls_prf_sha256;
		handshake->calc_verify = ssl_calc_verify_tls_sha256;
		handshake->calc_finished = ssl_calc_finished_tls_sha256;
	}
	log_buf_debug("premaster secret", handshake->premaster,handshake->pmslen );
	if (ssl->handshake->extended_ms == JHD_TLS_SSL_EXTENDED_MS_ENABLED) {
		unsigned char session_hash[48];
		size_t hash_len;
		log_debug("using extended master secret");
		ssl->handshake->calc_verify(ssl, session_hash);
		hash_len =(ssl->minor_ver == JHD_TLS_SSL_MINOR_VERSION_3)?((ciphersuite_info->md_info == &jhd_tls_sha384_info)?48:32):36;
		log_buf_debug("session_hash",session_hash,hash_len);
		handshake->tls_prf(handshake->premaster, handshake->pmslen, "extended master secret", session_hash, hash_len, ssl->handshake->master, 48);
	} else {
		 handshake->tls_prf(handshake->premaster, handshake->pmslen, "master secret", handshake->randbytes, 64, ssl->handshake->master, 48);
	}
	log_buf_debug("ssl->master==>",ssl->handshake->master,48);

	jhd_tls_platform_zeroize(handshake->premaster, sizeof(handshake->premaster));

	//memcpy(tmp, handshake->randbytes, 64);
	memcpy_64(tmp,handshake->randbytes);
	//memcpy(handshake->randbytes, tmp + 32, 32);
	memcpy_32(handshake->randbytes, tmp + 32);
//	memcpy(handshake->randbytes + 32, tmp, 32);
	memcpy_32(handshake->randbytes + 32, tmp);
	handshake->tls_prf(ssl->handshake->master, 48, "key expansion", handshake->randbytes, 64, keyblk, 256);
	log_buf_debug("keyblk==>",keyblk,256);


	keylen = cipher_info->key_bitlen / 8;

	if (cipher_info->mode == JHD_TLS_MODE_GCM ) {
		ssl->maclen = 0;
		mac_key_len = 0;

		/* Minimum length is expicit IV + tag */
		ssl->minlen = 8 +16;
		ssl->maxlen = 8+16 +(16*1024);
		ssl->decrypt_func = jhd_tls_ssl_gcm_decrypt_buf;
		ssl->encrypt_func = jhd_tls_ssl_gcm_encrypt_buf;

	}else if(cipher_info->mode == JHD_TLS_MODE_CCM){
		ssl->maclen = 0;
			mac_key_len = 0;
			ssl->minlen = 8 +16;
			ssl->maxlen = 8+16 +(16*1024);
			ssl->decrypt_func = jhd_tls_ssl_ccm_decrypt_buf;
			ssl->encrypt_func = jhd_tls_ssl_ccm_encrypt_buf;
	} else {
		log_assert(cipher_info->mode == JHD_TLS_MODE_CBC);
		mac_key_len = jhd_tls_md_get_size(md_info);
		ssl->maclen =(ssl->handshake->trunc_hmac == JHD_TLS_SSL_TRUNC_HMAC_ENABLED)?(JHD_TLS_SSL_TRUNCATED_HMAC_LEN): mac_key_len;
		if (ssl->handshake->encrypt_then_mac == JHD_TLS_SSL_ETM_ENABLED) {
			ssl->minlen = ssl->maclen + cipher_info->block_size;
			log_assert((16*1024) % cipher_info->block_size ==0 );
			ssl->maxlen = ssl->maclen + (16*1024)+ cipher_info->block_size;
		} else {
			ssl->minlen = ssl->maclen + cipher_info->block_size - ssl->maclen % cipher_info->block_size;
			log_assert((16*1024) % cipher_info->block_size ==0 );
			ssl->maxlen = ssl->minlen+ (16*1024);

		}
		if (ssl->minor_ver >= JHD_TLS_SSL_MINOR_VERSION_2) {
			ssl->minlen += cipher_info->block_size;
			ssl->maxlen += cipher_info->block_size;
			if(ssl->handshake->encrypt_then_mac == JHD_TLS_SSL_ETM_ENABLED){
				ssl->encrypt_func = jhd_tls_ssl_cbc_with_etm_gteq_tls11_encrypt_buf;
				ssl->decrypt_func = jhd_tls_ssl_cbc_with_etm_gteq_tls11_decrypt_buf;
			}else{
				ssl->encrypt_func = jhd_tls_ssl_cbc_without_etm_gteq_tls11_encrypt_buf;
				ssl->decrypt_func = jhd_tls_ssl_cbc_without_etm_gteq_tls11_decrypt_buf;
			}
		}else{
			if(ssl->handshake->encrypt_then_mac == JHD_TLS_SSL_ETM_ENABLED){
				ssl->encrypt_func = jhd_tls_ssl_cbc_with_etm_eq_tls10_encrypt_buf;
				ssl->decrypt_func = jhd_tls_ssl_cbc_with_etm_eq_tls10_decrypt_buf;
			}else{
				ssl->encrypt_func = jhd_tls_ssl_cbc_without_etm_eq_tls10_encrypt_buf;
				ssl->decrypt_func = jhd_tls_ssl_cbc_without_etm_eq_tls10_decrypt_buf;
			}
		}
	}

	log_buf_debug("keyblk==>",keyblk,256);
	if (jhd_tls_ssl_is_server_side(ssl)) {
		key1 = keyblk + mac_key_len * 2 + keylen;
		key2 = keyblk + mac_key_len * 2;


		if(cipher_info->mode == JHD_TLS_MODE_CBC){
			if (ssl->minor_ver == JHD_TLS_SSL_MINOR_VERSION_1){
				memcpy(ssl->iv_dec,key1 + keylen,cipher_info->block_size);
				memcpy(ssl->iv_enc,key1 + keylen + cipher_info->block_size,cipher_info->block_size);
				log_buf_debug("ssl->iv_dec==>",ssl->iv_dec,cipher_info->block_size);
				log_buf_debug("ssl->iv_enc==>",ssl->iv_enc,cipher_info->block_size);
			}
//			jhd_tls_md_hmac_starts(&ssl->md_ctx_enc, keyblk + mac_key_len, mac_key_len);
//			jhd_tls_md_hmac_starts(&ssl->md_ctx_dec, keyblk, mac_key_len);
			jhd_tls_md_hmac_init(ssl->md_info,keyblk + mac_key_len, mac_key_len,ssl->enc_hmac);
			jhd_tls_md_hmac_init(ssl->md_info,keyblk, mac_key_len,ssl->dec_hmac);
		}else{
			*((uint32_t*)ssl->iv_dec) = *((uint32_t*)(key1 + keylen));
			*((uint32_t*)ssl->iv_enc) = *((uint32_t*)(key1 + keylen + 4));
		}
	} else {
		key1 = keyblk + mac_key_len * 2;
		key2 = keyblk + mac_key_len * 2 + keylen;

		if(cipher_info->mode == JHD_TLS_MODE_CBC){
			if (ssl->minor_ver == JHD_TLS_SSL_MINOR_VERSION_1){
				memcpy(ssl->iv_enc,key2 + keylen,cipher_info->block_size);
				memcpy(ssl->iv_dec,key1 + keylen + cipher_info->block_size,cipher_info->block_size);
				log_buf_debug("ssl->iv_dec==>",ssl->iv_dec,cipher_info->block_size);
				log_buf_debug("ssl->iv_enc==>",ssl->iv_enc,cipher_info->block_size);
			}
//			jhd_tls_md_hmac_starts(&ssl->md_ctx_enc, keyblk, mac_key_len);
//			jhd_tls_md_hmac_starts(&ssl->md_ctx_dec, keyblk + mac_key_len, mac_key_len);
			jhd_tls_md_hmac_init(ssl->md_info,keyblk , mac_key_len,ssl->enc_hmac);
			jhd_tls_md_hmac_init(ssl->md_info,keyblk + mac_key_len, mac_key_len,ssl->dec_hmac);

		}else{
			*((uint32_t*)ssl->iv_dec) = *((uint32_t*)( key2 + keylen + 4));
			*((uint32_t*)ssl->iv_enc) = *((uint32_t*)( key2 + keylen));
		}
	}
	log_buf_debug("ssl->iv_dec==>",ssl->iv_dec,cipher_info->block_size);
	log_buf_debug("ssl->iv_enc==>",ssl->iv_enc,cipher_info->block_size);
	ssl->cipher_info->base->setkey_enc_func(ssl->enc_ctx, key1, cipher_info->key_bitlen);
	ssl->cipher_info->base->setkey_dec_func(ssl->dec_ctx, key2, cipher_info->key_bitlen);
#ifdef JHD_LOG_LEVEL_DEBUG
	memcpy(ssl->enc_key,key1,cipher_info->key_bitlen/8);
	memcpy(ssl->dec_key,key2,cipher_info->key_bitlen/8);
#endif
	log_buf_debug("ssl->enc_key================>",key1,cipher_info->key_bitlen/8);
	log_buf_debug("ssl->dec_key================>",key2,cipher_info->key_bitlen/8);
	log_notice("%s", "<= derive keys" );
}

void ssl_calc_verify_tls(jhd_tls_ssl_context *ssl, unsigned char hash[36]) {
	jhd_tls_md5_context md5;
	jhd_tls_sha1_context sha1;
	jhd_tls_md5_init(&md5);
	jhd_tls_sha1_init(&sha1);

	jhd_tls_md5_clone(&md5, &ssl->handshake->fin_md5);
	jhd_tls_sha1_clone(&sha1, &ssl->handshake->fin_sha1);

	jhd_tls_md5_finish_ret(&md5, hash);
	jhd_tls_sha1_finish_ret(&sha1, hash + 16);
}

void ssl_calc_verify_tls_sha256(jhd_tls_ssl_context *ssl, unsigned char hash[32]) {
	jhd_tls_sha256_context sha256;
	jhd_tls_sha256_init(&sha256);
	jhd_tls_sha256_clone(&sha256, &ssl->handshake->fin_sha256);
	jhd_tls_sha256_finish_ret(&sha256, hash);
}

void ssl_calc_verify_tls_sha384(jhd_tls_ssl_context *ssl, unsigned char hash[48]) {
	jhd_tls_sha512_context sha512;

	jhd_tls_sha512_init(&sha512);
	jhd_tls_sha512_clone(&sha512, &ssl->handshake->fin_sha512);
	jhd_tls_sha512_finish_ret(&sha512, hash);
}


#undef MAC_NONE
#undef MAC_PLAINTEXT
#undef MAC_CIPHERTEXT

#if !defined(JHD_TLS_INLINE)
int jhd_tls_ssl_is_server_side(jhd_tls_ssl_context *ssl) {
	return ssl->conf->server_side;
}
#endif

int jhd_tls_ssl_fetch_input(jhd_connection_t *c, size_t nb_want) {
	ssize_t ret;
	size_t len;
	int err;
	jhd_tls_ssl_context *ssl = c->ssl;
	log_notice("==>jhd_tls_ssl_fetch_input(c,nb_want(%ld))",nb_want);
	while (ssl->in_left < nb_want) {
		len = nb_want - ssl->in_left;
		ret = recv(c->fd, ssl->in_hdr+ssl->in_left, len, 0);
		log_debug("systemcall(recv(c->fd(%d), ssl->in_hdr+ssl->in_left(%u), len(%lu), 0)))=%s",c->fd,ssl->in_left,len,JHD_RETURN_STR(ret));
		if(ret >0){
			ssl->in_left +=ret;
		}else if(ret < 0) {
			err = errno;
			if (err == EAGAIN) {
				log_notice("<==jhd_tls_ssl_fetch_input(JHD_AGAIN)");
				return JHD_AGAIN;
			} else if (err != EINTR) {
				log_err("systemcall(recv(c->fd(%d), ssl->in_hdr+ssl->in_left(%u), len(%lu), 0)))=%s, errno=%d",c->fd,ssl->in_left,len,JHD_RETURN_STR(ret),err);
				log_notice("<==jhd_tls_ssl_fetch_input(JHD_ERROR)");
				return JHD_ERROR;
			}
		}else{
			log_err("systemcall(recv(c->fd(%d), ssl->in_hdr+ssl->in_left(%u), len(%lu), 0)))=%s",c->fd,ssl->in_left,len,JHD_RETURN_STR(ret));
			log_notice("<==jhd_tls_ssl_fetch_input(JHD_ERROR)");
			return JHD_ERROR;
		}
	}
	log_notice("<==jhd_tls_ssl_fetch_input(JHD_OK)");
	return JHD_OK;
}

/*
 * Flush any data not yet written
 */

int jhd_tls_ssl_flush_output(jhd_connection_t *c) {
	int err;
	ssize_t n;
	jhd_tls_ssl_context *ssl;
	ssl = c->ssl;
	for (;;) {
		n = send(c->fd, ssl->out_offt, ssl->out_msglen, 0);
		log_debug("syscall(send) return:%d",n);
		if (n >= 0) {
			ssl->out_msglen -= n;
			//FIXME wait error again???????????
			if(ssl->out_msglen){
				ssl->out_offt +=n;
				return JHD_AGAIN;
			}else{
				return JHD_OK;
			}
		} else {
			err = errno;
			if (err == EAGAIN) {
				return JHD_AGAIN;
			} else if (err != EINTR) {
				log_debug("systemcall(send) error errno=%d",err);
				c->send = jhd_connection_error_send;
				return JHD_ERROR;
			}
			log_debug("systemcall(send) error errno=EINTR");
		}
	}
}

int jhd_tls_ssl_send_fatal_handshake_failure(jhd_connection_t *c) {
	int ret;

	if ((ret = jhd_tls_ssl_send_alert_message(c,JHD_TLS_SSL_ALERT_LEVEL_FATAL,JHD_TLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE)) != 0) {
		return (ret);
	}

	return (0);
}
//TODO: make sure static char buff
static unsigned char   jhd_tls_ssl_out_static_buffer[16*1024];

int jhd_tls_ssl_send_alert_message(jhd_connection_t  *c, unsigned char level, unsigned char message) {
	int ret;
	jhd_tls_ssl_context *ssl;
	uint16_t old_msglen;
	ssize_t n;
	int err;
	log_debug( "send alert level=%u message=%u", level, message );
	ssl = c->ssl;
	if(ssl->out_msglen){
		for(;;){
			n = send(c->fd, ssl->out_offt, ssl->out_msglen, 0);
			if (n >= 0) {
				ssl->out_msglen -= n;
				ssl->out_offt += n;
				break;
			} else {
				err = errno;
				if (err == EAGAIN) {
					break;
				} else if (err != EINTR) {
					c->recv = jhd_connection_error_send;
					return JHD_ERROR;
				}
			}
		}
	}
	old_msglen = ssl->out_msglen;
	if(old_msglen){
		memcpy(jhd_tls_ssl_out_static_buffer,ssl->out_offt,old_msglen);
	}

	ssl->out_msglen = 2;
	ssl->out_offt = ssl->out_hdr;

	JHD_TLS_SSL_SET_SSL_RECORD(ssl,JHD_TLS_SSL_MSG_ALERT,2)
	ssl->out_msg[0] = level;
	ssl->out_msg[1] = message;

	ret = jhd_tls_ssl_is_server_side(ssl)?(ssl->state > JHD_TLS_SSL_SERVER_CHANGE_CIPHER_SPEC?1:0):(ssl->state > JHD_TLS_SSL_CLIENT_CHANGE_CIPHER_SPEC?1:0);
	if(ret){
		if (JHD_OK != jhd_tls_ssl_do_encrypt(ssl)) {
			c->send = jhd_connection_error_send;
			log_err("%s","encrypt_buf error");
			return JHD_ERROR;
		}
	}
	if(old_msglen){
		//TODO:log and make sure 16*1024
		log_assert((ssl->out_msglen+old_msglen)<16*1024/*,"ssl send buffer data too large"*/);
		 memmove(ssl->out_hdr+old_msglen,ssl->out_hdr,5+ssl->out_msglen);
		 memcpy(ssl->out_hdr,jhd_tls_ssl_out_static_buffer,old_msglen);
		 ssl->out_msglen += (5+old_msglen);
	}else{
		ssl->out_msglen += 5;
	}
	for (;;) {
		n = send(c->fd, ssl->out_offt, ssl->out_msglen, 0);
		if (n >= 0) {
			ssl->out_msglen -= n;
			ssl->out_offt += n;
			break;
		} else {
			err = errno;
			if (err == EAGAIN) {
				return JHD_AGAIN;
			} else if (err != EINTR) {
				c->recv = jhd_connection_error_send;
				return JHD_ERROR;
			}
		}
	}
	return JHD_OK;
}

/* Some certificate support -> implement write and parse */

int jhd_tls_ssl_write_certificate(jhd_connection_t *c) {
	int ret,n;
	const jhd_tls_x509_crt *crt = NULL;
	jhd_tls_ssl_context *ssl=c->ssl;
	log_notice("%s", ( "=> write certificate" ));
	if(ssl->out_msglen){
			ret = jhd_tls_ssl_flush_output(c);
			if(ret==JHD_OK){
				++ssl->state;
			}
	}else{
		if (jhd_tls_ssl_is_server_side(ssl) || (ssl->handshake->client_auth)) {
			log_assert(ssl->handshake->key_cert!= NULL && ssl->handshake->key_cert->key != NULL/*,"got no certificate to send"*/);
			crt = ssl->handshake->key_cert->cert;
			/*
			 *     0  .  0    handshake type
			 *     1  .  3    handshake length
			 *     4  .  6    length of all certs
			 *     7  .  9    length of cert. 1
			 *    10  . n-1   peer certificate
			 *     n  . n+2   length of cert. 2
			 *    n+3 . ...   upper level cert, etc.
			 */
			ret = 7;
			while (crt != NULL) {
				n = crt->raw.len;
				//TODO:check JHD_TLS_SSL_MAX_CONTENT_LEN
				if (n > JHD_TLS_SSL_MAX_CONTENT_LEN - 3 - ret) {
					log_emerg("certificate too large, %d > %d", ret + 3 + n, JHD_TLS_SSL_MAX_CONTENT_LEN );
					return JHD_ERROR;
				}
				ssl->out_msg[ret] = (unsigned char) (n >> 16);
				ssl->out_msg[ret + 1] = (unsigned char) (n >> 8);
				ssl->out_msg[ret + 2] = (unsigned char) (n);

				ret += 3;
				memcpy(ssl->out_msg + ret, crt->raw.p, n);
				ret += n;
				crt = crt->next;
			}
			ret -= 7;
			ssl->out_msg[4] = (unsigned char) (0);
			ssl->out_msg[5] = (unsigned char) (ret >> 8);
			ssl->out_msg[6] = (unsigned char) (ret);
			ret += 7;

			ssl->out_offt = ssl->out_hdr;
			ssl->out_msglen = ret + 5;
			JHD_TLS_SSL_SET_SSL_RECORD(ssl,JHD_TLS_SSL_MSG_HANDSHAKE,ret)
			ret -= 4;
			JHD_TLS_SSL_SET_HANDSHAKE(ssl,JHD_TLS_SSL_HS_CERTIFICATE,ret)
			log_buf_debug("write ssl record====>",ssl->out_hdr,ssl->out_msglen);
			ret = jhd_tls_ssl_flush_output(c);
			if(ret == JHD_OK){
				++ssl->state;
			}
		} else {
			ssl->state++;
			ret = JHD_OK;
		}
	}
	log_notice("%s", ( "<= write certificate" ));
	return ret;
}

int jhd_tls_ssl_parse_certificate(jhd_connection_t *c) {
	int ret;
	uint32_t msg_len;
	size_t n;
	unsigned char *buf;
	jhd_tls_x509_crt * cert;
	jhd_tls_ssl_context *ssl = c->ssl;
	log_notice("%s", ("=> parse certificate"));

	if (jhd_tls_ssl_is_server_side(ssl)) {
		ssl->state++;
		ret = JHD_OK;
	} else {
		if(ssl->in_msglen == 0){
			JHD_TLS_SSL_READ_SSL_RECORD_CONTENT
			ssl->in_offt = ssl->in_msg;
		}
		buf = ssl->in_offt;
		if(ssl->handshake->msg_len==0){

			msg_len = ((buf[2]<<8)|(buf[3]))  +  4;
			if ((msg_len > ssl->in_msglen)  || (buf[0] != JHD_TLS_SSL_HS_CERTIFICATE)||(buf[1]!= 0) || (msg_len < ( 4 + 3 + 3))) {
				log_err("%s", ( "bad certificate message" ));
				jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL, JHD_TLS_SSL_ALERT_MSG_DECODE_ERROR);
				goto func_error;
			}

			ssl->handshake->i = jhd_tls_ssl_hs_hdr_len(ssl);
			/*
			 * Same message structure as in jhd_tls_ssl_write_certificate()
			 */
			n = (buf[ssl->handshake->i + 1] << 8) | buf[ssl->handshake->i + 2];
			if (buf[ssl->handshake->i] != 0 || msg_len != n + 3 + jhd_tls_ssl_hs_hdr_len(ssl)) {
				log_err("%s", ( "bad certificate message" ));
				jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL, JHD_TLS_SSL_ALERT_MSG_DECODE_ERROR);
				goto func_error;
			}
			if ((ssl->handshake->peer_cert = jhd_tls_alloc(sizeof(jhd_tls_x509_crt))) == NULL) {
				jhd_tls_wait_mem(&c->read,sizeof(jhd_tls_x509_crt));
				ret = JHD_AGAIN;
				goto func_return;
			}
			jhd_tls_x509_crt_init(ssl->handshake->peer_cert);
			ssl->handshake->curr_cert = ssl->handshake->peer_cert;
			ssl->handshake->i += 3;
			ssl->handshake->msg_len = msg_len;
		}else{
			msg_len = ssl->handshake->msg_len;
		}
		if(ssl->handshake->curr_cert == NULL){
			if ((ssl->handshake->curr_cert = jhd_tls_alloc(sizeof(jhd_tls_x509_crt))) == NULL) {
						//TODO:add to memory watting queue
				ret = JHD_AGAIN;
				goto func_return;
			}
			jhd_tls_x509_crt_init(ssl->handshake->curr_cert);
			cert = ssl->handshake->peer_cert;
			for(;;){
				if(cert->next == NULL){
					cert->next = ssl->handshake->curr_cert;
					break;
				}
				cert= cert->next;
			}
		}
		for(;;){
			if (buf[ssl->handshake->i] != 0) {
				log_err("%s", ( "bad certificate message" ));
				jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL, JHD_TLS_SSL_ALERT_MSG_DECODE_ERROR);
				jhd_tls_x509_crt_free(ssl->handshake->peer_cert);
				jhd_tls_free(ssl->handshake->peer_cert);
				ssl->handshake->peer_cert = NULL;
				goto func_error;
			}
			n = (((unsigned int) buf[ssl->handshake->i + 1]) << 8) | ((unsigned int) buf[ssl->handshake->i + 2]);
			ssl->handshake->i += 3;
			if (n < 128 || ssl->handshake->i + n > msg_len) {
				log_err("%s", ( "bad certificate message" ));
				jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL, JHD_TLS_SSL_ALERT_MSG_DECODE_ERROR);
				jhd_tls_x509_crt_free(ssl->handshake->peer_cert);
				jhd_tls_free(ssl->handshake->peer_cert);
				ssl->handshake->peer_cert = NULL;
				goto func_error;
			}

			ret = jhd_tls_x509_crt_parse_der(ssl->handshake->curr_cert, buf + ssl->handshake->i, n,&c->read);
			if(ret == JHD_AGAIN){
				ssl->handshake->curr_cert->version = 0;
				goto func_return;
			}else if((ret == JHD_UNEXPECTED)||(ret == JHD_UNSUPPORTED)){
				ssl->handshake->curr_cert->version = 0;
			}else if(ret == JHD_ERROR){
				ssl->handshake->curr_cert->version=0;
				jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL, JHD_TLS_SSL_ALERT_MSG_BAD_CERT);
				log_err(" jhd_tls_x509_crt_parse_der()=%d", ret);
				jhd_tls_x509_crt_free(ssl->handshake->peer_cert);
				jhd_tls_free(ssl->handshake->peer_cert);
				ssl->handshake->peer_cert = NULL;
				goto func_error;
			}
			ssl->handshake->i += n;
			if(ssl->handshake->i < msg_len){
				if(ssl->handshake->curr_cert->version !=0){
					if((cert = jhd_tls_alloc(sizeof(jhd_tls_x509_crt))) == NULL) {
							jhd_tls_wait_mem(event,sizeof(jhd_tls_x509_crt));
							ssl->handshake->curr_cert = NULL;
							ret = JHD_AGAIN;
							goto func_return;
					}
					jhd_tls_x509_crt_init(cert);
					ssl->handshake->curr_cert->next = cert;
					ssl->handshake->curr_cert = cert;
				}else{
					jhd_tls_x509_crt_free(ssl->handshake->curr_cert);
					jhd_tls_x509_crt_init(ssl->handshake->curr_cert);
				}
			}else{
				break;
			}
		}
		ssl->handshake->msg_len = 0;
		ssl->handshake->update_checksum(ssl,ssl->in_offt,msg_len);
		ssl->in_msglen -=(msg_len);
		ssl->in_offt +=(msg_len);
		ssl->state++;
		ret = JHD_OK;
	}
	func_return:
		log_notice("%s", "<= parse certificate" );
		return ret;
	func_error:
		c->recv = jhd_connection_error_recv;
		log_notice("%s", "<= parse certificate" );
		return JHD_ERROR;

}

int jhd_tls_ssl_write_change_cipher_spec(jhd_connection_t *c) {
	int ret;
	jhd_tls_ssl_context *ssl = c->ssl;
	log_notice("%s", ( "=> write change cipher spec" ));
	if(ssl->out_msglen){
		ret = jhd_tls_ssl_flush_output(c);
		if(ret==JHD_OK){
			++(ssl->state);
		}
	}else{
		ssl->out_offt = ssl->out_hdr;
		ssl->out_msglen = 5  +  1;
		JHD_TLS_SSL_SET_SSL_RECORD(ssl,JHD_TLS_SSL_MSG_CHANGE_CIPHER_SPEC,1);
		ssl->out_msg[0] = (unsigned char) (1);
		log_buf_debug("write ssl record====>",ssl->out_hdr,ssl->out_msglen);
		ret = jhd_tls_ssl_flush_output(c);
		if(ret == JHD_OK){
			++(ssl->state);
		}
	}
	log_notice("%s", ( "<= write change cipher spec" ));
	return ret;
}

int jhd_tls_ssl_parse_change_cipher_spec(jhd_connection_t *c) {
	int ret;
	jhd_tls_ssl_context *ssl=c->ssl;
	log_notice("=> parse change cipher spec");
	log_assert(ssl->in_msglen == 0/*,"ssl->in_msglen != 0"*/);
	if (ssl->in_left < 6) {
		if ((ret = jhd_tls_ssl_fetch_input(c, 6)) != JHD_OK) {
			goto func_return;
		}
		ssl->in_left = 0;
	}
	log_buf_debug("readed ssl record==>",ssl->in_hdr,6);
	if (ssl->in_hdr[0] != JHD_TLS_SSL_MSG_CHANGE_CIPHER_SPEC) {
		log_err("bad change cipher spec message,invalid message type:%d in ssl record", ssl->in_hdr[0]);
		goto func_error;
	}
	if ((ssl->in_hdr[3] != 0)  || (ssl->in_hdr[4] != 1) || (ssl->in_msg[0] != 1)) {
		log_err("%s", "bad change cipher spec message");
		jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL, JHD_TLS_SSL_ALERT_MSG_DECODE_ERROR);
		goto func_error;
	}
	*((uint64_t*)(ssl->in_ctr)) = 0;

	if(ssl->minor_ver >= JHD_TLS_SSL_MINOR_VERSION_2){
		if(ssl->cipher_info->mode == JHD_TLS_MODE_CBC){
			ssl->in_msg= ssl->in_iv + ssl->cipher_info->block_size;
		}else{
			log_assert((ssl->cipher_info->mode == JHD_TLS_MODE_GCM)||(ssl->cipher_info->mode == JHD_TLS_MODE_CCM));
			ssl->in_msg = ssl->in_iv + 8;
		}
	}

	log_assert(((ssl->minor_ver < JHD_TLS_SSL_MINOR_VERSION_2)&&(ssl->cipher_info->mode == JHD_TLS_MODE_CBC))  ||( ssl->minor_ver >= JHD_TLS_SSL_MINOR_VERSION_2 ));

	ssl->state++;
	ret = JHD_OK;
	func_return:
		log_notice("<= parse change cipher spec(%s)",JHD_RETURN_STR(ret) );
		return ret;
	func_error:
		c->recv = jhd_connection_error_recv;
		log_notice("<= parse change cipher spec(JHD_ERROR)" );
		return JHD_ERROR;
}

void jhd_tls_ssl_optimize_checksum(jhd_tls_ssl_context *ssl, const jhd_tls_ssl_ciphersuite_t *ciphersuite_info) {
	if (ssl->minor_ver < JHD_TLS_SSL_MINOR_VERSION_3) {
		ssl->handshake->update_checksum = ssl_update_checksum_md5sha1;
	} else if (ciphersuite_info->md_info == &jhd_tls_sha384_info) {
		ssl->handshake->update_checksum = ssl_update_checksum_sha384;
	} else {
		ssl->handshake->update_checksum = ssl_update_checksum_sha256;
	}
}

void jhd_tls_ssl_reset_checksum(jhd_tls_ssl_context *ssl) {
	jhd_tls_md5_starts_ret(&ssl->handshake->fin_md5);
	jhd_tls_sha1_starts_ret(&ssl->handshake->fin_sha1);
	jhd_tls_sha256_starts_ret_with_256(&ssl->handshake->fin_sha256);
	jhd_tls_sha512_starts_ret_with_384(&ssl->handshake->fin_sha512);
}

static void ssl_update_checksum_start(jhd_tls_ssl_context *ssl, const unsigned char *buf, size_t len) {
	jhd_tls_md5_update_ret(&ssl->handshake->fin_md5, buf, len);
	jhd_tls_sha1_update_ret(&ssl->handshake->fin_sha1, buf, len);
	jhd_tls_sha256_update_ret(&ssl->handshake->fin_sha256, buf, len);
	jhd_tls_sha512_update_ret(&ssl->handshake->fin_sha512, buf, len);
//#ifdef JHD_LOG_LEVEL_DEBUG
//	jhd_tls_md_test_finish(&jhd_tls_md5_info,&ssl->handshake->fin_md5);
//	jhd_tls_md_test_finish(&jhd_tls_sha1_info,&ssl->handshake->fin_sha1);
//#endif

}

static void ssl_update_checksum_md5sha1(jhd_tls_ssl_context *ssl, const unsigned char *buf, size_t len) {
	jhd_tls_md5_update_ret(&ssl->handshake->fin_md5, buf, len);
	jhd_tls_sha1_update_ret(&ssl->handshake->fin_sha1, buf, len);
//#ifdef JHD_LOG_LEVEL_DEBUG
//	jhd_tls_md_test_finish(&jhd_tls_md5_info,&ssl->handshake->fin_md5);
//	jhd_tls_md_test_finish(&jhd_tls_sha1_info,&ssl->handshake->fin_sha1);
//#endif
}

static void ssl_update_checksum_sha256(jhd_tls_ssl_context *ssl, const unsigned char *buf, size_t len) {
	jhd_tls_sha256_update_ret(&ssl->handshake->fin_sha256, buf, len);
}

static void ssl_update_checksum_sha384(jhd_tls_ssl_context *ssl, const unsigned char *buf, size_t len) {
	jhd_tls_sha512_update_ret(&ssl->handshake->fin_sha512, buf, len);
}

static void ssl_calc_finished_tls(jhd_tls_ssl_context *ssl, unsigned char *buf, int from) {
	int len = 12;
	const char *sender;
	jhd_tls_md5_context md5;
	jhd_tls_sha1_context sha1;
	unsigned char padbuf[36];


	jhd_tls_md5_init(&md5);
	jhd_tls_sha1_init(&sha1);

	jhd_tls_md5_clone(&md5, &ssl->handshake->fin_md5);
	jhd_tls_sha1_clone(&sha1, &ssl->handshake->fin_sha1);

	/*
	 * TLSv1:
	 *   hash = PRF( master, finished_label,
	 *               MD5( handshake ) + SHA1( handshake ) )[0..11]
	 */

	sender = (from == JHD_TLS_SSL_IS_CLIENT) ? "client finished" : "server finished";

	jhd_tls_md5_finish_ret(&md5, padbuf);
	jhd_tls_sha1_finish_ret(&sha1, padbuf + 16);

	ssl->handshake->tls_prf(ssl->handshake->master, 48, sender, padbuf, 36, buf, len);
}

static void ssl_calc_finished_tls_sha256(jhd_tls_ssl_context *ssl, unsigned char *buf, int from) {
	int len = 12;
	const char *sender;
	jhd_tls_sha256_context sha256;
	unsigned char padbuf[32];
	jhd_tls_sha256_init(&sha256);

	jhd_tls_sha256_clone(&sha256, &ssl->handshake->fin_sha256);

	/*
	 * TLSv1.2:
	 *   hash = PRF( master, finished_label,
	 *               Hash( handshake ) )[0.11]
	 */
	sender = (from == JHD_TLS_SSL_IS_CLIENT) ? "client finished" : "server finished";

	jhd_tls_sha256_finish_ret(&sha256, padbuf);

	ssl->handshake->tls_prf(ssl->handshake->master, 48, sender, padbuf, 32, buf, len);


	jhd_tls_platform_zeroize(padbuf, sizeof(padbuf));
}

static void ssl_calc_finished_tls_sha384(jhd_tls_ssl_context *ssl, unsigned char *buf, int from) {
	int len = 12;
	const char *sender;
	jhd_tls_sha512_context sha512;
	unsigned char padbuf[48];
	jhd_tls_sha512_init(&sha512);

	jhd_tls_sha512_clone(&sha512, &ssl->handshake->fin_sha512);

	/*
	 * TLSv1.2:
	 *   hash = PRF( master, finished_label,
	 *               Hash( handshake ) )[0.11]
	 */

	sender = (from == JHD_TLS_SSL_IS_CLIENT) ? "client finished" : "server finished";

	jhd_tls_sha512_finish_ret(&sha512, padbuf);

	ssl->handshake->tls_prf(ssl->handshake->master, 48, sender, padbuf, 48, buf, len);

}

void jhd_tls_ssl_handshake_wrapup(jhd_connection_t *c) {
	jhd_tls_ssl_context *ssl = c->ssl;

	log_assert(ssl->handshake!=NULL);
	c->recv = jhd_tls_ssl_read;
	if (ssl->handshake->mfl_code == JHD_TLS_SSL_MAX_FRAG_LEN_512) {
		c->send = jhd_tls_ssl_write_512;
	} else if (ssl->handshake->mfl_code == JHD_TLS_SSL_MAX_FRAG_LEN_1024) {
		c->send = jhd_tls_ssl_write_1024;
	} else if (ssl->handshake->mfl_code == JHD_TLS_SSL_MAX_FRAG_LEN_2048) {
		c->send = jhd_tls_ssl_write_2048;
	} else if (ssl->handshake->mfl_code == JHD_TLS_SSL_MAX_FRAG_LEN_4096) {
		c->send = jhd_tls_ssl_write_4096;
	} else {
		c->send = jhd_tls_ssl_write;
	}
	jhd_tls_ssl_handshake_free(ssl);
	jhd_tls_free(ssl->handshake);
	ssl->handshake = NULL;
	ssl->state++;
}

int jhd_tls_ssl_write_finished(jhd_connection_t *c) {
	int ret;
	jhd_tls_ssl_context *ssl=c->ssl;
	log_notice("%s", ( "=> write finished" ));
	if(ssl->out_msglen){
		ret = jhd_tls_ssl_flush_output(c);
		if(ret==JHD_OK){
			++(ssl->state);
		}
	}else{
		if(ssl->minor_ver >= JHD_TLS_SSL_MINOR_VERSION_2){
			if(ssl->cipher_info->mode == JHD_TLS_MODE_CBC){
				ssl->out_msg= ssl->out_iv + ssl->cipher_info->block_size;
			}else{
				log_assert((ssl->cipher_info->mode == JHD_TLS_MODE_GCM)||(ssl->cipher_info->mode == JHD_TLS_MODE_CCM));
				ssl->out_msg = ssl->out_iv + 8;
			}
		}
		log_assert(((ssl->minor_ver < JHD_TLS_SSL_MINOR_VERSION_2)&&(ssl->cipher_info->mode == JHD_TLS_MODE_CBC))  ||( ssl->minor_ver >= JHD_TLS_SSL_MINOR_VERSION_2 ));
		ssl->handshake->calc_finished(ssl, ssl->out_msg + 4, ssl->conf->server_side);
		ssl->out_msglen = 4 + 12;

		JHD_TLS_SSL_SET_SSL_RECORD(ssl,JHD_TLS_SSL_MSG_HANDSHAKE,16)
		JHD_TLS_SSL_SET_HANDSHAKE(ssl,JHD_TLS_SSL_HS_FINISHED,12)

		*((uint64_t*)(ssl->out_ctr))=0;

		if(JHD_OK==jhd_tls_ssl_do_encrypt(ssl)){
			ssl->out_msglen += 5;
			ssl->out_offt = ssl->out_hdr;
			log_buf_debug("write ssl record====>",ssl->out_hdr,ssl->out_msglen);
			ret = jhd_tls_ssl_flush_output(c);
			if(ret == JHD_OK){
				++(ssl->state);
			}
		}else{
			c->send = jhd_connection_error_send;
			log_err("encrypt_buf error");
			ret = JHD_ERROR;
		}
	}
	log_notice("<= write finished");
	return ret;
}

#define SSL_MAX_HASH_LEN 12

int jhd_tls_ssl_parse_finished(jhd_connection_t *c) {
	int ret;
	unsigned char buf[SSL_MAX_HASH_LEN];
	jhd_tls_ssl_context *ssl = c->ssl;
	log_assert(ssl->in_msglen == 0/*,"ssl->in_msglen != 0"*/);
	log_notice("=> parse finished");

	JHD_TLS_SSL_READ_SSL_RECORD_CONTENT
	ssl->handshake->calc_finished(ssl, buf, ssl->conf->server_side ^ 1);

	if (JHD_OK != (jhd_tls_ssl_do_decrypt(ssl))) {
		jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL, JHD_TLS_SSL_ALERT_MSG_BAD_RECORD_MAC);
		goto func_error;
	}
	if ((ssl->in_msg[0] != JHD_TLS_SSL_HS_FINISHED) || (ssl->in_msg[1] != 0) ||(ssl->in_msg[2] != 0) ||  (ssl->in_msg[3] != 12)) {
		log_err("invalid finished message in handshake(%02X,%02X,%02X,%02X)",ssl->in_msg[0],ssl->in_msg[1],ssl->in_msg[2],ssl->in_msg[3]);
		jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL, JHD_TLS_SSL_ALERT_MSG_DECODE_ERROR);
		goto func_error;
	}

	if (jhd_tls_ssl_safer_memcmp(ssl->in_msg + jhd_tls_ssl_hs_hdr_len(ssl), buf, 12) != 0) {
		log_err("bad finished message invalid mac" );
		jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL, JHD_TLS_SSL_ALERT_MSG_DECODE_ERROR);
		goto func_error;
	}
	log_assert(ssl->in_msglen == 12+4);
	ssl->in_msglen -=(12+4);
	ssl->state++;
	ssl->handshake->update_checksum(ssl,ssl->in_msg,jhd_tls_ssl_hs_hdr_len(ssl)+12);
	ret = JHD_OK;
	func_return:
		log_notice("<= parse finished(%s)",JHD_RETURN_STR(ret));
		return ret;
	func_error:
	    c->recv = jhd_connection_error_recv;
		log_notice("<= parse finished(JHD_ERROR)");
		return JHD_ERROR;
}


#if !defined(JHD_TLS_INLINE)

/**
 * \brief          Initialize an SSL context
 *                 Just makes the context ready for jhd_tls_ssl_setup() or
 *                 jhd_tls_ssl_free()
 *
 * \param ssl      SSL context
 */
void jhd_tls_ssl_init(jhd_tls_ssl_context *ssl) {
	memset((void*) ssl, 0, sizeof(jhd_tls_ssl_context));
}

#endif

//MAX IN_HDR = 5+16 +16384 +48

int jhd_tls_ssl_context_alloc(jhd_tls_ssl_context **pssl,const jhd_tls_ssl_config *conf,jhd_event_t *ev){
	jhd_tls_ssl_context *ssl =*pssl;
	log_assert_worker();
	if(ssl == NULL){
		ssl = jhd_tls_alloc(sizeof(jhd_tls_ssl_context));
		if(ssl  == NULL){
			jhd_tls_wait_mem(ev,sizeof(jhd_tls_ssl_context));
			return JHD_AGAIN;
		}
		*pssl = ssl;
		jhd_tls_platform_zeroize(ssl,sizeof(jhd_tls_ssl_context));
		ssl->conf = conf;
	}
	if (ssl->in_hdr == NULL){
		ssl->in_hdr = jhd_tls_alloc(16512);
		if(ssl->in_hdr == NULL){
			jhd_tls_wait_mem(ev,16512);
			return JHD_AGAIN;
		}
		ssl->in_msg =ssl->in_iv = ssl->in_hdr + 5;
	}
	if(ssl->out_hdr == NULL){
		ssl->out_hdr =jhd_tls_alloc(16*1024);
		if(ssl->out_hdr == NULL){
			jhd_tls_wait_mem(ev,16*1024);
			return JHD_AGAIN;
		}
		ssl->out_msg =ssl->out_iv = ssl->out_hdr + 5;
	}
	if(NULL == ssl->handshake){
		ssl->handshake = jhd_tls_alloc(sizeof(jhd_tls_ssl_handshake_params));
		if (ssl->handshake == NULL) {
			jhd_tls_wait_mem(ev,sizeof(jhd_tls_ssl_handshake_params));
			return JHD_AGAIN;
		}
		jhd_tls_platform_zeroize(ssl->handshake,sizeof(jhd_tls_ssl_handshake_params));
		jhd_tls_md5_starts_ret(&ssl->handshake->fin_md5);
		jhd_tls_sha1_starts_ret(&ssl->handshake->fin_sha1);
		jhd_tls_sha256_starts_ret_with_256(&ssl->handshake->fin_sha256);
		jhd_tls_sha512_starts_ret_with_384(&ssl->handshake->fin_sha512);
		ssl->handshake->update_checksum = ssl_update_checksum_start;
	}
	return JHD_OK;
}


/*
 * Free an SSL context
 */
void jhd_tls_ssl_context_free(jhd_tls_ssl_context **pssl) {
	jhd_tls_ssl_context *ssl;

	log_assert_worker();
	log_assert(*pssl != NULL);
	ssl = *pssl;
	*pssl = NULL;

	if (ssl->out_hdr != NULL) {
		jhd_tls_free_with_size(ssl->out_hdr,16*1024);
	}
	if (ssl->in_hdr != NULL) {
		jhd_tls_free_with_size(ssl->in_hdr,16512);
	}
	if (ssl->handshake != NULL) {
		jhd_tls_ssl_handshake_free(ssl);
		jhd_tls_free_with_size(ssl->handshake,sizeof(jhd_tls_ssl_handshake_params));
	}
	if(ssl->enc_hmac != NULL){
		log_assert(NULL != ssl->md_info);
		jhd_tls_free_with_size(ssl->enc_hmac,ssl->md_info->block_size << 1);
	}
	if(ssl->dec_hmac != NULL){
		log_assert(NULL != ssl->md_info);
		jhd_tls_free_with_size(ssl->dec_hmac,ssl->md_info->block_size << 1);
	}
	if(ssl->dec_ctx != NULL){
		log_assert(NULL != ssl->cipher_info);
		jhd_tls_free_with_size(ssl->dec_ctx,ssl->cipher_info->base->ctx_size);
	}
	if(ssl->enc_ctx != NULL){
		log_assert(NULL != ssl->cipher_info);
		jhd_tls_free_with_size(ssl->enc_ctx,ssl->cipher_info->base->ctx_size);
	}
	jhd_tls_free_with_size(ssl,sizeof(jhd_tls_ssl_context));
}



#if !defined(JHD_TLS_INLINE)
/*
 * SSL set accessors
 */
void jhd_tls_ssl_conf_set_server_side(jhd_tls_ssl_config *conf, jhd_tls_bool server_side) {
	conf->server_side = server_side ? 1 : 0;
}
#endif



int jhd_tls_ssl_conf_own_cert(jhd_tls_ssl_config *conf, jhd_tls_x509_crt *cert, jhd_tls_pk_context *key) {
	jhd_tls_ssl_key_cert *new,*cur;
	new = jhd_tls_alloc(sizeof(jhd_tls_ssl_key_cert));
	if (new == NULL){
		return JHD_ERROR;
	}
	new->cert = cert;
	new->key = key;
	new->next = NULL;
	/* Update head is the list was null, else add to the end */
	if(conf->key_cert == NULL){
		conf->key_cert = new;
	}else{
		cur = conf->key_cert;
		while (cur->next != NULL){
			cur = cur->next;
		}
		cur->next = new;
	}
	return JHD_OK;
}

int jhd_tls_ssl_set_hostname(jhd_tls_ssl_context *ssl, const char *hostname) {
	/* Initialize to suppress unnecessary compiler warning */
	size_t hostname_len = 0;

	/* Check if new hostname is valid before
	 * making any change to current one */
	if (hostname != NULL) {
		hostname_len = strlen(hostname);

		if (hostname_len > JHD_TLS_SSL_MAX_HOST_NAME_LEN)
			return JHD_ERROR;
	}
	ssl->hostname = hostname;
	return (0);
}

int jhd_tls_ssl_conf_alpn_protocols(jhd_tls_ssl_config *conf, const char **protos) {
	size_t cur_len, tot_len;
	const char **p;

	/*
	 * RFC 7301 3.1: "Empty strings MUST NOT be included and byte strings
	 * MUST NOT be truncated."
	 * We check lengths now rather than later.
	 */
	tot_len = 0;
	for (p = protos; *p != NULL; p++) {
		cur_len = strlen(*p);
		tot_len += cur_len;

		if (cur_len == 0 || cur_len > 255 || tot_len > 65535)
			return JHD_ERROR;
	}

	conf->alpn_list = protos;

	return (0);
}

const char *jhd_tls_ssl_get_alpn_protocol(const jhd_tls_ssl_context *ssl) {
	return (ssl->alpn_chosen);
}

int jhd_tls_ssl_conf_max_frag_len(jhd_tls_ssl_config *conf, unsigned char mfl_code) {
	if (mfl_code >= JHD_TLS_SSL_MAX_FRAG_LEN_INVALID || mfl_code_to_length[mfl_code] > JHD_TLS_SSL_MAX_CONTENT_LEN) {
		return JHD_ERROR;
	}

	conf->mfl_code = mfl_code;

	return (0);
}

/*
 * SSL get accessors
 */
size_t jhd_tls_ssl_get_bytes_avail(const jhd_tls_ssl_context *ssl) {
	return (ssl->in_offt == NULL ? 0 : ssl->in_msglen);
}


const char *jhd_tls_ssl_get_version(const jhd_tls_ssl_context *ssl) {

	switch (ssl->minor_ver) {
		case JHD_TLS_SSL_MINOR_VERSION_0:
			return ("SSLv3.0");

		case JHD_TLS_SSL_MINOR_VERSION_1:
			return ("TLSv1.0");

		case JHD_TLS_SSL_MINOR_VERSION_2:
			return ("TLSv1.1");

		case JHD_TLS_SSL_MINOR_VERSION_3:
			return ("TLSv1.2");

		default:
			return ("unknown");
	}
}



size_t jhd_tls_ssl_get_max_frag_len(const jhd_tls_ssl_context *ssl) {
	size_t max_len;

	/*
	 * Assume mfl_code is correct since it was checked when set
	 */
	max_len = mfl_code_to_length[ssl->conf->mfl_code];

	/*
	 * Check if a smaller max length was negotiated
	 */
	if (mfl_code_to_length[ssl->handshake->mfl_code] < max_len) {
		max_len = mfl_code_to_length[ssl->handshake->mfl_code];
	}

	return max_len;
}


/*
 * Receive application data decrypted from the SSL layer
 */
ssize_t jhd_tls_ssl_read(jhd_connection_t *c, unsigned char *buf, size_t len) {
	ssize_t ret, n;
	jhd_tls_ssl_context *ssl= c->ssl;
	log_notice("===============>jhd_tls_ssl_read(len=%lu)",len);
	log_assert(len>0/*,"len==0"*/);
	log_assert(ssl->in_msglen <= 16 * 1024);

	log_debug("ssl->in_msglen =%u",ssl->in_msglen);
	if(ssl->in_msglen){
		if(len<=ssl->in_msglen){
			memcpy(buf,ssl->in_offt,len);
			ssl->in_msglen -=len;
			ssl->in_offt +=len;
			ret = len;
			goto func_return;
		}
		memcpy(buf,ssl->in_offt,ssl->in_msglen);
		n = ssl->in_msglen;
		len -= n;
		buf += n;
		ssl->in_msglen = 0;
	}else{
		n = 0;
	}
	for(;;){
		if (ssl->in_left < 5) {
			if ((ret = jhd_tls_ssl_fetch_input(c, 5/* ssl record header(5),*/)) != JHD_OK) {
				if(ret == JHD_ERROR){
					goto func_error;
				}else{
					ret = (n==0?JHD_AGAIN:n);
					goto func_return;
				}
			}
			//ignore  version error
//		    jhd_tls_ssl_read_version(&major, &minor, buf + 1);
			ssl->in_msglen = (ssl->in_hdr[3] << 8) | ssl->in_hdr[4];
			if ((ssl->in_msglen < ssl->minlen) ||(ssl->in_msglen > ssl->maxlen) ) {
				log_err("invalid ssl record length:%d", ssl->in_msglen);
//				jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL, JHD_TLS_SSL_ALERT_MSG_INTERNAL_ERROR);
				c->recv = jhd_connection_error_recv;
				goto func_error;
			}
		}else{
			ssl->in_msglen = (ssl->in_hdr[3] << 8) | ssl->in_hdr[4];
		}
		if ((ret = jhd_tls_ssl_fetch_input(c, 5 + ssl->in_msglen)) != JHD_OK) {
			ssl->in_msglen = 0;
			if(ret == JHD_ERROR){
				c->recv = jhd_connection_error_recv;
				if(n){
					ret = n;
					goto func_return;
				}
				goto func_error;
			}else{
				ret = (n==0?JHD_AGAIN:n);
				goto func_return;
			}
		}
		ssl->in_left = 0;
		ssl->in_offt = ssl->in_msg;
		if(ssl->in_hdr[0] == JHD_TLS_SSL_MSG_APPLICATION_DATA){
			if(jhd_tls_ssl_do_decrypt(ssl)!=JHD_OK){
				c->recv = jhd_connection_error_recv;
				if(n){
					ret = n;
					goto func_return;
				}
				goto func_error;
			}
			if(len <= ssl->in_msglen){
				memcpy(buf,ssl->in_offt,len);
				ssl->in_msglen -=len;
				ssl->in_offt +=len;
				ret = len+n;
				goto func_return;
			}
			memcpy(buf,ssl->in_offt,ssl->in_msglen);
			n += ssl->in_msglen;
			buf += ssl->in_msglen;
			len -=ssl->in_msglen;
			ssl->in_msglen = 0;
		}else if(ssl->in_hdr[0] == JHD_TLS_SSL_MSG_ALERT){
			if(jhd_tls_ssl_do_decrypt(ssl)!=JHD_OK){
				c->recv = jhd_connection_error_recv;
				if(n){
					ret = n;
					goto func_return;
				}
				goto func_error;
			}
			if(ssl->in_msglen!=2){
//				jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL, JHD_TLS_SSL_ALERT_MSG_INTERNAL_ERROR);
				c->recv = jhd_connection_error_recv;
				goto func_error;
			}
			log_debug("recv alert message [%d:%d]",ssl->in_msg[0],ssl->in_msg[1]);
			if((ssl->in_msg[0] !=JHD_TLS_SSL_ALERT_LEVEL_WARNING) || (ssl->in_msg[1] !=JHD_TLS_SSL_ALERT_MSG_NO_RENEGOTIATION)){
				c->recv = jhd_connection_error_recv;
				if(n){
					ret = n;
					goto func_return;
				}
				goto func_error;
			}
		}else if(ssl->in_hdr[0] == JHD_TLS_SSL_MSG_HANDSHAKE){
			if(jhd_tls_ssl_do_decrypt(ssl)!=JHD_OK){
				c->recv = jhd_connection_error_recv;
				if(n){
					ret = n;
					goto func_return;
				}
				goto func_error;
			}
			if((ssl->in_msg[0] != JHD_TLS_SSL_HS_CLIENT_HELLO) && (ssl->in_msg[0] != JHD_TLS_SSL_HS_HELLO_REQUEST) ){
				log_err("invalid ssl handshark type:%d",ssl->in_msg[0]);
				c->recv = jhd_connection_error_recv;
				if(n){
					ret = n;
					goto func_return;
				}
				goto func_error;
			}
			if(jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_WARNING, JHD_TLS_SSL_ALERT_MSG_NO_RENEGOTIATION)== JHD_ERROR){
				c->recv = jhd_connection_error_recv;
				if(n){
					ret = n;
					goto func_return;
				}
				goto func_error;
			}
			//TODO make goto func_return
//			ret = (n==0?JHD_AGAIN:n);
//			goto func_return;
		}else {
			log_err("invalid ssl record type:%d",ssl->in_hdr[0]);
			c->recv = jhd_connection_error_recv;
			goto func_error;
		}
	}
	func_return:
		log_notice("<================= jhd_tls_ssl_read(...) == %s[%d] {ssl->in_msglen = %u}",JHD_RETURN_STR(ret),ret,ssl->in_msglen);
		return ret;
	func_error:
		log_notice("<================= jhd_tls_ssl_read(...) == JHD_ERROR");
		return JHD_ERROR;
}






/*
 * Write application data (public-facing wrapper)
 */
ssize_t jhd_tls_ssl_write(jhd_connection_t *c, unsigned char *buf, size_t len) {
	int ret,err;
	ssize_t n = 0;
	jhd_tls_ssl_context *ssl=c->ssl;
	log_assert(len<8193/*,"len > 8192"*/);
	log_assert(len>0/*,"len<=0"*/);
	log_notice("=> jhd_tls_ssl_write(,,%ld)",len);
	if(ssl->out_msglen){
		for(;;){
			n = send(c->fd, ssl->out_offt, ssl->out_msglen, 0);
			if (n >= 0) {
				ssl->out_msglen -= n;
				ssl->out_offt +=n;
				//FIXME  waite send(...) == (-1)  then return
				if(ssl->out_msglen){
					ret = JHD_AGAIN;
					goto func_return;
				}
				break;
			} else {
				err = errno;
				if (err == EAGAIN) {
					ret = JHD_AGAIN;
					goto func_return;
				} else if (err != EINTR) {
					c->send = jhd_connection_error_send;
					ret = JHD_ERROR;
					goto func_return;
				}
			}
		}
	}
	log_assert(ssl->out_msglen==0);
	JHD_TLS_SSL_SET_SSL_RECORD(ssl,JHD_TLS_SSL_MSG_APPLICATION_DATA,len)
	memcpy(ssl->out_msg,buf,len);
	log_buf_debug("encrypt clean data==>",buf,len);
	ssl->out_msglen = len;
	if(jhd_tls_ssl_do_encrypt(ssl) != JHD_OK){
		goto func_error;
	}
	log_buf_debug("write encryption ssl record====>",ssl->out_hdr,ssl->out_msglen+5);
	ret = len;
	ssl->out_offt = ssl->out_hdr;
	ssl->out_msglen += 5;
	log_buf_debug("write encryption ssl record====>",ssl->out_hdr,ssl->out_msglen);
	for(;;) {
		n = send(c->fd, ssl->out_offt, ssl->out_msglen, 0);
		if (n >= 0) {
			ssl->out_msglen -= n;
			ssl->out_offt +=n;
			//FIXME wait  send(...)==(-1)  then return
			goto func_return;
		} else {
			err = errno;
			if (err == EAGAIN) {
				goto func_return;
			} else if (err != EINTR) {
				goto func_error;
			}
		}
	}
	func_return:
	log_notice("<= jhd_tls_ssl_write(,,%d) == %d",len,ret);
	return ret;
	func_error:
	c->send = jhd_connection_error_send;
	log_notice("<= jhd_tls_ssl_write(,,%d) == %d",len,JHD_ERROR);
	return JHD_ERROR;
}

ssize_t jhd_tls_ssl_write_512(jhd_connection_t *c, unsigned char *buf, size_t len){
	int ret,err;
	ssize_t n;
	unsigned char *end = buf+len;
#ifdef JHD_LOG_LEVEL_NOTICE
	size_t olen = len;
#endif

	jhd_tls_ssl_context *ssl=c->ssl;
	log_assert(len<8193/*,"len > 8192"*/);
	log_assert(len>0/*,"len<=0"*/);
	log_notice("=> jhd_tls_ssl_write_512(,,%ld)",len);
	if(ssl->out_msglen){
		for(;;){
			n = send(c->fd, ssl->out_offt, ssl->out_msglen, 0);
			if (n >= 0) {
				ssl->out_msglen -= n;
				ssl->out_offt +=n;
				//FIXME  waite send(...) == (-1)  then return
				if(ssl->out_msglen){
					ret = JHD_AGAIN;
					goto func_return;
				}
				break;
			} else {
				err = errno;
				if (err == EAGAIN) {
					ret = JHD_AGAIN;
					goto func_return;
				} else if (err != EINTR) {
					c->send = jhd_connection_error_send;
					ret = JHD_ERROR;
					goto func_return;
				}
			}
		}
	}
	log_assert(ssl->out_msglen==0);
	ret = 0;
	loop_begin:
	for(;;){
		if(len > 512){
			len = 512;
		}
		JHD_TLS_SSL_SET_SSL_RECORD(ssl,JHD_TLS_SSL_MSG_APPLICATION_DATA,len)
		memcpy(ssl->out_msg,buf,len);
		ret +=len;
		buf+=len;
		log_buf_debug("encrypt clean data==>",buf,len);
		ssl->out_msglen = len;
		if(jhd_tls_ssl_do_encrypt(ssl) != JHD_OK){
			goto func_error;
		}
		log_buf_debug("write encryption ssl record====>",ssl->out_hdr,ssl->out_msglen+5);
		ssl->out_offt = ssl->out_hdr;
		ssl->out_msglen += 5;
		log_buf_debug("write encryption ssl record====>",ssl->out_hdr,ssl->out_msglen);
		for(;;) {
			n = send(c->fd, ssl->out_offt, ssl->out_msglen, 0);
			if (n >= 0) {
				ssl->out_msglen -= n;
				ssl->out_offt +=n;
				//FIXME wait  send(...)==(-1)  then return
				if(ssl->out_msglen == 0){
					if(0!=(len = end -buf)){
						goto loop_begin;
					}
				}
				goto func_return;
			} else {
				err = errno;
				if (err == EAGAIN) {
					goto func_return;
				} else if (err != EINTR) {
					goto func_error;
				}
			}
		}
	}
	func_return:
	log_notice("<= jhd_tls_ssl_write_512(,,%d) == %d",olen,ret);
	return ret;
	func_error:
	c->send = jhd_connection_error_send;
	log_notice("<= jhd_tls_ssl_write_512(,,%d) == %d",olen,JHD_ERROR);
	return JHD_ERROR;
}
ssize_t jhd_tls_ssl_write_1024(jhd_connection_t *c, unsigned char *buf, size_t len){
	int ret,err;
	ssize_t n;
	unsigned char *end = buf+len;
#ifdef JHD_LOG_LEVEL_NOTICE
	size_t olen = len;
#endif

	jhd_tls_ssl_context *ssl=c->ssl;
	log_assert(len<8193/*,"len > 8192"*/);
	log_assert(len>0/*,"len<=0"*/);
	log_notice("=> jhd_tls_ssl_write_1024(,,%ld)",len);
	if(ssl->out_msglen){
		for(;;){
			n = send(c->fd, ssl->out_offt, ssl->out_msglen, 0);
			if (n >= 0) {
				ssl->out_msglen -= n;
				ssl->out_offt +=n;
				//FIXME  waite send(...) == (-1)  then return
				if(ssl->out_msglen){
					ret = JHD_AGAIN;
					goto func_return;
				}
				break;
			} else {
				err = errno;
				if (err == EAGAIN) {
					ret = JHD_AGAIN;
					goto func_return;
				} else if (err != EINTR) {
					c->send = jhd_connection_error_send;
					ret = JHD_ERROR;
					goto func_return;
				}
			}
		}
	}
	log_assert(ssl->out_msglen==0);
	ret = 0;
	loop_begin:
	for(;;){
		if(len > 1024){
			len = 1024;
		}
		JHD_TLS_SSL_SET_SSL_RECORD(ssl,JHD_TLS_SSL_MSG_APPLICATION_DATA,len)
		memcpy(ssl->out_msg,buf,len);
		ret +=len;
		buf+=len;
		log_buf_debug("encrypt clean data==>",buf,len);
		ssl->out_msglen = len;
		if(jhd_tls_ssl_do_encrypt(ssl) != JHD_OK){
			goto func_error;
		}
		log_buf_debug("write encryption ssl record====>",ssl->out_hdr,ssl->out_msglen+5);
		ssl->out_offt = ssl->out_hdr;
		ssl->out_msglen += 5;
		log_buf_debug("write encryption ssl record====>",ssl->out_hdr,ssl->out_msglen);
		for(;;) {
			n = send(c->fd, ssl->out_offt, ssl->out_msglen, 0);
			if (n >= 0) {
				ssl->out_msglen -= n;
				ssl->out_offt +=n;
				//FIXME wait  send(...)==(-1)  then return
				if(ssl->out_msglen == 0){
					if(0!=(len = end -buf)){
						goto loop_begin;
					}
				}
				goto func_return;
			} else {
				err = errno;
				if (err == EAGAIN) {
					goto func_return;
				} else if (err != EINTR) {
					goto func_error;
				}
			}
		}
	}
	func_return:
	log_notice("<= jhd_tls_ssl_write_1024(,,%d) == %d",olen,ret);
	return ret;
	func_error:
	c->send = jhd_connection_error_send;
	log_notice("<= jhd_tls_ssl_write_1024(,,%d) == %d",olen,JHD_ERROR);
	return JHD_ERROR;
}
ssize_t jhd_tls_ssl_write_2048(jhd_connection_t *c, unsigned char *buf, size_t len){
	int ret,err;
	ssize_t n;
	unsigned char *end = buf+len;
#ifdef JHD_LOG_LEVEL_NOTICE
	size_t olen = len;
#endif

	jhd_tls_ssl_context *ssl=c->ssl;
	log_assert(len<8193/*,"len > 8192"*/);
	log_assert(len>0/*,"len<=0"*/);
	log_notice("=> jhd_tls_ssl_write_2048(,,%ld)",len);
	if(ssl->out_msglen){
		for(;;){
			n = send(c->fd, ssl->out_offt, ssl->out_msglen, 0);
			if (n >= 0) {
				ssl->out_msglen -= n;
				ssl->out_offt +=n;
				//FIXME  waite send(...) == (-1)  then return
				if(ssl->out_msglen){
					ret = JHD_AGAIN;
					goto func_return;
				}
				break;
			} else {
				err = errno;
				if (err == EAGAIN) {
					ret = JHD_AGAIN;
					goto func_return;
				} else if (err != EINTR) {
					c->send = jhd_connection_error_send;
					ret = JHD_ERROR;
					goto func_return;
				}
			}
		}
	}
	log_assert(ssl->out_msglen==0);
	ret = 0;
	loop_begin:
	for(;;){
		if(len > 2048){
			len = 2048;
		}
		JHD_TLS_SSL_SET_SSL_RECORD(ssl,JHD_TLS_SSL_MSG_APPLICATION_DATA,len)
		memcpy(ssl->out_msg,buf,len);
		ret +=len;
		buf+=len;
		log_buf_debug("encrypt clean data==>",buf,len);
		ssl->out_msglen = len;
		if(jhd_tls_ssl_do_encrypt(ssl) != JHD_OK){
			goto func_error;
		}
		log_buf_debug("write encryption ssl record====>",ssl->out_hdr,ssl->out_msglen+5);
		ssl->out_offt = ssl->out_hdr;
		ssl->out_msglen += 5;
		log_buf_debug("write encryption ssl record====>",ssl->out_hdr,ssl->out_msglen);
		for(;;) {
			n = send(c->fd, ssl->out_offt, ssl->out_msglen, 0);
			if (n >= 0) {
				ssl->out_msglen -= n;
				ssl->out_offt +=n;
				//FIXME wait  send(...)==(-1)  then return
				if(ssl->out_msglen == 0){
					if(0!=(len = end -buf)){
						goto loop_begin;
					}
				}
				goto func_return;
			} else {
				err = errno;
				if (err == EAGAIN) {
					goto func_return;
				} else if (err != EINTR) {
					goto func_error;
				}
			}
		}
	}
	func_return:
	log_notice("<= jhd_tls_ssl_write_2048(,,%d) == %d",olen,ret);
	return ret;
	func_error:
	c->send = jhd_connection_error_send;
	log_notice("<= jhd_tls_ssl_write_2048(,,%d) == %d",olen,JHD_ERROR);
	return JHD_ERROR;
}
ssize_t jhd_tls_ssl_write_4096(jhd_connection_t *c, unsigned char *buf, size_t len){
	int ret,err;
	ssize_t n;
	unsigned char *end = buf+len;
#ifdef JHD_LOG_LEVEL_NOTICE
	size_t olen = len;
#endif

	jhd_tls_ssl_context *ssl=c->ssl;
	log_assert(len<8193/*,"len > 8192"*/);
	log_assert(len>0/*,"len<=0"*/);
	log_notice("=> jhd_tls_ssl_write_4096(,,%ld)",len);
	if(ssl->out_msglen){
		for(;;){
			n = send(c->fd, ssl->out_offt, ssl->out_msglen, 0);
			if (n >= 0) {
				ssl->out_msglen -= n;
				ssl->out_offt +=n;
				//FIXME  waite send(...) == (-1)  then return
				if(ssl->out_msglen){
					ret = JHD_AGAIN;
					goto func_return;
				}
				break;
			} else {
				err = errno;
				if (err == EAGAIN) {
					ret = JHD_AGAIN;
					goto func_return;
				} else if (err != EINTR) {
					c->send = jhd_connection_error_send;
					ret = JHD_ERROR;
					goto func_return;
				}
			}
		}
	}
	log_assert(ssl->out_msglen==0);
	ret = 0;
	loop_begin:
	for(;;){
		if(len > 4096){
			len = 4096;
		}
		JHD_TLS_SSL_SET_SSL_RECORD(ssl,JHD_TLS_SSL_MSG_APPLICATION_DATA,len)
		memcpy(ssl->out_msg,buf,len);
		ret +=len;
		buf+=len;
		log_buf_debug("encrypt clean data==>",buf,len);
		ssl->out_msglen = len;
		if(jhd_tls_ssl_do_encrypt(ssl) != JHD_OK){
			goto func_error;
		}
		log_buf_debug("write encryption ssl record====>",ssl->out_hdr,ssl->out_msglen+5);
		ssl->out_offt = ssl->out_hdr;
		ssl->out_msglen += 5;
		log_buf_debug("write encryption ssl record====>",ssl->out_hdr,ssl->out_msglen);
		for(;;) {
			n = send(c->fd, ssl->out_offt, ssl->out_msglen, 0);
			if (n >= 0) {
				ssl->out_msglen -= n;
				ssl->out_offt +=n;
				//FIXME wait  send(...)==(-1)  then return
				if(ssl->out_msglen == 0){
					if(0!=(len = end -buf)){
						goto loop_begin;
					}
				}
				goto func_return;
			} else {
				err = errno;
				if (err == EAGAIN) {
					goto func_return;
				} else if (err != EINTR) {
					goto func_error;
				}
			}
		}
	}
	func_return:
	log_notice("<= jhd_tls_ssl_write_4096(,,%d) == %d",olen,ret);
	return ret;
	func_error:
	c->send = jhd_connection_error_send;
	log_notice("<= jhd_tls_ssl_write_4096(,,%d) == %d",olen,JHD_ERROR);
	return JHD_ERROR;
}





/*
 * Notify the peer that the connection is being closed
 */

#if !defined(JHD_TLS_INLINE)
int jhd_tls_ssl_close_notify(jhd_connection_t *c) {
	return (((jhd_tls_ssl_context*)(c->ssl))->state == JHD_TLS_SSL_HANDSHAKE_OVER)?jhd_tls_ssl_send_alert_message(c,JHD_TLS_SSL_ALERT_LEVEL_WARNING, JHD_TLS_SSL_ALERT_MSG_CLOSE_NOTIFY):JHD_OK;
}
#endif



static void ssl_key_cert_free(jhd_tls_ssl_key_cert *key_cert) {
	jhd_tls_ssl_key_cert *cur = key_cert, *next;
	while (cur != NULL) {
		next = cur->next;
		if(cur->cert){
			jhd_tls_x509_crt_free(cur->cert);
			jhd_tls_free_with_size(cur->cert,sizeof(jhd_tls_x509_crt));
		}
		if(cur->key){
			if(cur->key->pk_ctx){
				jhd_tls_free_with_size(cur->key->pk_ctx,cur->key->pk_info->ctx_size);
				jhd_tls_free_with_size(cur->key,sizeof(jhd_tls_pk_context));
			}
		}
		jhd_tls_free_with_size(cur,sizeof(jhd_tls_ssl_key_cert));
		cur = next;
	}
}

void jhd_tls_ssl_handshake_free(jhd_tls_ssl_context *ssl) {
	jhd_tls_ssl_handshake_params *handshake = ssl->handshake;
	if(NULL != handshake->peer_cert){
		jhd_tls_x509_crt_free(handshake->peer_cert);
		jhd_tls_free_with_size(handshake->peer_cert,sizeof(jhd_tls_x509_crt));
	}
}




#if !defined(JHD_TLS_INLINE)
/**
 * \brief          Initialize an SSL configuration context
 *                 Just makes the context ready for
 *                 jhd_tls_ssl_config_defaults() or jhd_tls_ssl_config_free().
 *
 * \note           You need to call jhd_tls_ssl_config_defaults() unless you
 *                 manually set all of the relevent fields yourself.
 *
 * \param conf     SSL configuration context
 */
void jhd_tls_ssl_config_init(jhd_tls_ssl_config *conf) {
	memset(conf, 0, sizeof(jhd_tls_ssl_config));
}
#endif

/*
 * Load default in jhd_tls_ssl_config
 */
int jhd_tls_ssl_config_defaults(jhd_tls_ssl_config *conf, jhd_tls_bool server_side) {
	jhd_tls_ssl_conf_set_server_side(conf, server_side);
	return (0);
}

/*
 * Free jhd_tls_ssl_config
 */
void jhd_tls_ssl_config_free(jhd_tls_ssl_config *conf) {
	if(conf->key_cert)

	ssl_key_cert_free(conf->key_cert);

	conf->key_cert = NULL;
}



#if !defined(JHD_TLS_INLINE)
/*
 * Convert between JHD_TLS_PK_XXX and SSL_SIG_XXX
 */
unsigned char jhd_tls_ssl_sig_from_pk(jhd_tls_pk_context *pk) {
	return pk->pk_info == &jhd_tls_rsa_info ? ( JHD_TLS_SSL_SIG_RSA):(pk->pk_info == &jhd_tls_ecdsa_info?(JHD_TLS_SSL_SIG_ECDSA):(JHD_TLS_SSL_SIG_ANON));
}

unsigned char jhd_tls_ssl_sig_from_pk_alg(const jhd_tls_pk_info_t *pk_info) {
	return pk_info->pk_flag;
}

const jhd_tls_pk_info_t* jhd_tls_ssl_pk_alg_from_sig(unsigned char sig) {
	return sig==JHD_TLS_SSL_SIG_RSA?(&jhd_tls_rsa_info):(sig==JHD_TLS_SSL_SIG_ECDSA?&jhd_tls_ecdsa_info:NULL);
}

/*
 * Convert from JHD_TLS_SSL_HASH_XXX to JHD_TLS_MD_XXX
 */
const jhd_tls_md_info_t* jhd_tls_ssl_md_info_from_hash(unsigned char hash) {
	switch (hash) {
		case JHD_TLS_SSL_HASH_MD5:
			return (&jhd_tls_md5_info);
		case JHD_TLS_SSL_HASH_SHA1:
			return (&jhd_tls_sha1_info);

		case JHD_TLS_SSL_HASH_SHA224:
			return (&jhd_tls_sha224_info);
		case JHD_TLS_SSL_HASH_SHA256:
			return (&jhd_tls_sha256_info);

		case JHD_TLS_SSL_HASH_SHA384:
			return (&jhd_tls_sha384_info);
		case JHD_TLS_SSL_HASH_SHA512:
			return (&jhd_tls_sha256_info);
		default:
			return (NULL);
	}
}
unsigned char jhd_tls_ssl_hash_from_md_info(const jhd_tls_md_info_t *md_info) {
	return md_info->hash_flag;
}

const jhd_tls_md_info_t* jhd_tls_ssl_sig_hash_set_find(jhd_tls_ssl_sig_hash_set_t *set,const jhd_tls_pk_info_t *sig_alg) {
	return (sig_alg == &jhd_tls_rsa_info) ? set->rsa : (sig_alg == &jhd_tls_ecdsa_info ? set->ecdsa : NULL);
}

/* Add a signature-hash-pair to a signature-hash set */
void jhd_tls_ssl_sig_hash_set_add(jhd_tls_ssl_sig_hash_set_t *set,const jhd_tls_pk_info_t *sig_alg, const jhd_tls_md_info_t* md_info) {
	if(sig_alg== &jhd_tls_rsa_info) {
		if(set->rsa == NULL){set->rsa = md_info;}
	}else if((sig_alg)== &jhd_tls_ecdsa_info){
		if((set)->ecdsa == NULL){(set)->ecdsa = (md_info);}
	}
}

/* Allow exactly one hash algorithm for each signature. */
void jhd_tls_ssl_sig_hash_set_const_hash(jhd_tls_ssl_sig_hash_set_t *set,const jhd_tls_md_info_t* md_info) {
	set->rsa = md_info;
	set->ecdsa = md_info;
}
#endif

/*
 * Check if a curve proposed by the peer is in our list.
 * Return 0 if we're willing to use it, -1 otherwise.
 */
int jhd_tls_ssl_check_curve(const jhd_tls_ssl_context *ssl, jhd_tls_ecp_group_id grp_id) {
	const jhd_tls_ecp_curve_info *curve_info;
	for(curve_info = jhd_tls_ecp_curve_list();curve_info->grp_id != JHD_TLS_ECP_DP_NONE;++curve_info){
		if (curve_info->grp_id == grp_id)
			return (0);
	}
	return (-1);
}


int jhd_tls_ssl_check_cert_usage(const jhd_tls_x509_crt *cert, const jhd_tls_ssl_ciphersuite_t *ciphersuite, int cert_endpoint, uint32_t *flags) {
	int ret = 0;
	int usage = 0;
	const char *ext_oid;
	size_t ext_len;
	if (cert_endpoint == JHD_TLS_SSL_IS_SERVER) {
		/* Server part of the key exchange */
		switch (ciphersuite->key_exchange) {
			case JHD_TLS_KEY_EXCHANGE_RSA:
				usage = JHD_TLS_X509_KU_KEY_ENCIPHERMENT;
				break;

			case JHD_TLS_KEY_EXCHANGE_ECDHE_RSA:
			case JHD_TLS_KEY_EXCHANGE_ECDHE_ECDSA:
				usage = JHD_TLS_X509_KU_DIGITAL_SIGNATURE;
				break;
			case JHD_TLS_KEY_EXCHANGE_NONE:
				usage = 0;
		}
	} else {
		//TODO implement for usage = JHD_TLS_X509_KU_KEY_ENCIPHERMENT;
		/* Client auth: we only implement rsa_sign and jhd_tls_ecdsa_sign for now */
		usage = JHD_TLS_X509_KU_DIGITAL_SIGNATURE;
	}

	if (jhd_tls_x509_crt_check_key_usage(cert, usage) != 0) {
		*flags |= JHD_TLS_X509_BADCERT_KEY_USAGE;
		ret = -1;
	}

	if (cert_endpoint == JHD_TLS_SSL_IS_SERVER) {
		ext_oid = JHD_TLS_OID_SERVER_AUTH;
		ext_len = JHD_TLS_OID_SIZE(JHD_TLS_OID_SERVER_AUTH);
	} else {
		ext_oid = JHD_TLS_OID_CLIENT_AUTH;
		ext_len = JHD_TLS_OID_SIZE(JHD_TLS_OID_CLIENT_AUTH);
	}

	if (jhd_tls_x509_crt_check_extended_key_usage(cert, ext_oid, ext_len) != 0) {
		*flags |= JHD_TLS_X509_BADCERT_EXT_KEY_USAGE;
		ret = -1;
	}


	return (ret);
}


int jhd_tls_ssl_set_calc_verify_md(jhd_tls_ssl_context *ssl, int md) {
	if (ssl->minor_ver != JHD_TLS_SSL_MINOR_VERSION_3)
		return JHD_ERROR;

	switch (md) {
		case JHD_TLS_SSL_HASH_MD5:
			return JHD_ERROR;;

		case JHD_TLS_SSL_HASH_SHA1:
			ssl->handshake->calc_verify = ssl_calc_verify_tls;
			break;
		case JHD_TLS_SSL_HASH_SHA384:
			ssl->handshake->calc_verify = ssl_calc_verify_tls_sha384;
			break;

		case JHD_TLS_SSL_HASH_SHA256:
			ssl->handshake->calc_verify = ssl_calc_verify_tls_sha256;
			break;
		default:
			return JHD_ERROR;
	}

	return 0;

}

void jhd_tls_ssl_get_key_exchange_md_ssl_tls(unsigned char *output,const unsigned char *randbytes,const unsigned char *data,const size_t data_len) {
	jhd_tls_md5_context jhd_tls_md5;
	jhd_tls_sha1_context jhd_tls_sha1;

	jhd_tls_md5_init(&jhd_tls_md5);
	jhd_tls_sha1_init(&jhd_tls_sha1);

	/*
	 * digitally-signed struct {
	 *     opaque md5_hash[16];
	 *     opaque sha_hash[20];
	 * };
	 *
	 * md5_hash
	 *     MD5(ClientHello.random + ServerHello.random
	 *                            + ServerParams);
	 * sha_hash
	 *     SHA(ClientHello.random + ServerHello.random
	 *                            + ServerParams);
	 */
	jhd_tls_md5_starts_ret(&jhd_tls_md5);
	jhd_tls_md5_update_ret(&jhd_tls_md5,randbytes, 64);
	jhd_tls_md5_update_ret(&jhd_tls_md5, data, data_len);
	jhd_tls_md5_finish_ret(&jhd_tls_md5, output);

	jhd_tls_sha1_starts_ret(&jhd_tls_sha1);
	jhd_tls_sha1_update_ret(&jhd_tls_sha1,randbytes, 64);
	jhd_tls_sha1_update_ret(&jhd_tls_sha1, data, data_len);
	jhd_tls_sha1_finish_ret(&jhd_tls_sha1, output + 16);



}

void jhd_tls_ssl_get_key_exchange_md_tls1_2(unsigned char *hash, size_t *hashlen,const unsigned char *randbytes,const unsigned char *data,const size_t data_len,const  jhd_tls_md_info_t *md_info) {
	JHD_TLS_MD_CONTEXT_DEFINE(ctx);
	*hashlen = jhd_tls_md_get_size(md_info);
	jhd_tls_md_starts(md_info,ctx);
	jhd_tls_md_update(md_info,ctx,randbytes, 64);
	jhd_tls_md_update(md_info,ctx, data, data_len);
	jhd_tls_md_finish(md_info,ctx, hash);
}





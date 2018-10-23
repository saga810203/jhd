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



int jhd_tls_ssl_cbc_with_etm_eq_tls10_encrypt_buf(jhd_tls_ssl_context *ssl){
	const jhd_tls_cipher_info_t *cipher_info;
	unsigned char mac[JHD_TLS_SSL_MAC_ADD];
	uint16_t msglen;
	uint8_t padlen;
	unsigned char md_ctx[256];
	size_t i;
	log_notice("=>jhd_tls_ssl_cbc_with_etm_eq_tls10_encrypt_buf(%s;maclen:%ld,msglen=%ld,)",ssl->ciphersuite_info->name,(size_t)ssl->maclen,(size_t)ssl->out_msglen);


	cipher_info =ssl->cipher_info;
	log_assert(ssl->minor_ver ==JHD_TLS_SSL_MINOR_VERSION_1);
	log_assert(cipher_info->mode ==JHD_TLS_MODE_CBC);
	log_assert(ssl->md_info->ctx_size <= 256);
	log_assert(ssl->in_msglen <= (16*1024));


	log_buf_debug("clean msg",ssl->out_msg,ssl->out_msglen);
	padlen = cipher_info->block_size - (ssl->out_msglen + 1) % cipher_info->block_size;
	if (padlen ==cipher_info->block_size){
		padlen = 0;
	}
	msglen = ssl->out_msglen + padlen +1;
	for (i = ssl->out_msglen; i < msglen; i++){
		ssl->out_msg[i] = (unsigned char) padlen;
	}
	log_buf_debug("CLEAN MSG WITH PADDING",ssl->out_msg,msglen);
	log_assert((msglen >0) &&(msglen % cipher_info->block_size ==0));
	log_assert(msglen % cipher_info->block_size ==0);

	cipher_info->base->cbc_encrypt_func(ssl->enc_ctx,msglen, ssl->iv_enc, ssl->out_msg, ssl->out_msg);

	log_buf_debug("CRYPT MSG",ssl->out_msg,msglen);

	memcpy_8(mac,ssl->out_ctr);
	memcpy_4(mac+8,ssl->out_hdr);
	mac[11] = (unsigned char) (msglen >> 8);
	mac[12] = (unsigned char) (msglen);
	log_buf_debug("MAC ADD",mac,13);

	jhd_tls_md_hmac_starts(ssl->md_info,&md_ctx,ssl->enc_hmac);
	jhd_tls_md_hmac_update(ssl->md_info,&md_ctx,mac,13);
	jhd_tls_md_hmac_update(ssl->md_info,&md_ctx,ssl->out_msg, msglen);
	jhd_tls_md_hmac_finish(ssl->md_info,&md_ctx,ssl->enc_hmac, ssl->out_msg + msglen,mac);

	log_buf_debug("MAC",ssl->out_msg + msglen,ssl->md_info->size);
	log_buf_debug("CRYPT SSL RECORD",ssl->out_hdr,5+msglen+ssl->maclen);

	msglen += ssl->maclen;
	ssl->out_msglen = msglen;
	for (i = 8; i > 0;) {
		--i;
		if (++ssl->out_ctr[i] != 0) {
			break;
		}
	}
	ssl->out_hdr[3] = (unsigned char) (msglen >> 8);
	ssl->out_hdr[4] = (unsigned char) (msglen);
	log_notice("<= jhd_tls_ssl_cbc_with_etm_eq_tls10_encrypt_buf(JHD_OK,msglen:%d)",ssl->out_msglen);
	return JHD_OK;
}


int jhd_tls_ssl_cbc_with_etm_gteq_tls11_encrypt_buf(jhd_tls_ssl_context *ssl){
	const jhd_tls_cipher_info_t *cipher_info;
	unsigned char mac[JHD_TLS_SSL_MAC_ADD];
	uint16_t msglen;
	uint8_t padlen;
	unsigned char md_ctx[256];
	size_t i;

	log_notice("=>jhd_tls_ssl_cbc_with_etm_gteq_tls11_encrypt_buf(%s;maclen:%ld,msglen=%ld,)",ssl->ciphersuite_info->name,(size_t)ssl->maclen,(size_t)ssl->out_msglen);

	cipher_info =ssl->cipher_info;

	log_assert(ssl->minor_ver >=JHD_TLS_SSL_MINOR_VERSION_2);
	log_assert(cipher_info->mode ==JHD_TLS_MODE_CBC);
	log_assert(ssl->md_info->ctx_size <= 256);
	log_assert(ssl->in_msglen <= (16*1024));

	padlen = cipher_info->block_size - (ssl->out_msglen + 1) % cipher_info->block_size;
	if (padlen == cipher_info->block_size){
		padlen = 0;
	}
	msglen = ssl->out_msglen + padlen +1;
	for (i = ssl->out_msglen; i < msglen; i++){
		ssl->out_msg[i] = (unsigned char) padlen;
	}

	log_assert((msglen >0) &&(msglen % cipher_info->block_size ==0));
	log_assert(msglen % cipher_info->block_size ==0);

	jhd_tls_random(ssl->out_iv, cipher_info->block_size);

	//max 16
	memcpy_16(ssl->iv_enc,ssl->out_iv);

	cipher_info->base->cbc_encrypt_func(ssl->enc_ctx, msglen, ssl->iv_enc, ssl->out_msg, ssl->out_msg);

	msglen+=cipher_info->block_size;


	memcpy_8(mac,ssl->out_ctr);
	memcpy_4(mac+8,ssl->out_hdr);
	mac[11] = (unsigned char) (msglen >> 8) ;
	mac[12] = (unsigned char) (msglen);

	jhd_tls_md_hmac_starts(ssl->md_info,&md_ctx,ssl->enc_hmac);
	jhd_tls_md_hmac_update(ssl->md_info,&md_ctx,mac,13);
	jhd_tls_md_hmac_update(ssl->md_info,&md_ctx,ssl->out_iv, msglen);
	jhd_tls_md_hmac_finish(ssl->md_info,&md_ctx,ssl->enc_hmac, ssl->out_iv + msglen,mac);

	msglen+=ssl->maclen;
	ssl->out_msglen = msglen;

	for (i = 8; i > 0; ) {
		--i;
		if (++ssl->out_ctr[i] != 0) {
			break;
		}
	}
	ssl->out_hdr[3] = (unsigned char) (msglen >> 8);
	ssl->out_hdr[4] = (unsigned char) (msglen);
	log_notice("<= jhd_tls_ssl_cbc_with_etm_gteq_tls11_encrypt_buf(JHD_OK,msglen:%d)",ssl->out_msglen);
	return JHD_OK;
}

int jhd_tls_ssl_cbc_without_etm_eq_tls10_encrypt_buf(jhd_tls_ssl_context *ssl){
	const jhd_tls_cipher_info_t *cipher_info;
	unsigned char mac[JHD_TLS_SSL_MAC_ADD];
	uint16_t msglen;
	uint8_t padlen;
	size_t i;
	unsigned char md_ctx[256];

	log_notice("=>jhd_tls_ssl_cbc_without_etm_eq_tls10_encrypt_buf(%s;maclen:%ld,msglen=%ld,)",ssl->ciphersuite_info->name,(size_t)ssl->maclen,(size_t)ssl->out_msglen);

	cipher_info =ssl->cipher_info;

	log_assert(ssl->minor_ver ==JHD_TLS_SSL_MINOR_VERSION_1);
	log_assert(cipher_info->mode ==JHD_TLS_MODE_CBC);
	log_assert(ssl->out_msg == ssl->out_iv);
	log_assert(ssl->md_info->ctx_size <= 256);

	jhd_tls_md_hmac_starts(ssl->md_info,&md_ctx,ssl->enc_hmac);
	jhd_tls_md_hmac_update(ssl->md_info,&md_ctx,ssl->out_ctr, 8);
	jhd_tls_md_hmac_update(ssl->md_info,&md_ctx,ssl->out_hdr, ssl->out_msglen+ 5);
	jhd_tls_md_hmac_finish(ssl->md_info,&md_ctx,ssl->enc_hmac, mac,mac);

	memcpy(ssl->out_msg + ssl->out_msglen, mac, ssl->maclen);

	ssl->out_msglen += ssl->maclen;

	padlen = cipher_info->block_size - (ssl->out_msglen + 1) % cipher_info->block_size;
	if (padlen == cipher_info->block_size){
		padlen = 0;
	}
	msglen = ssl->out_msglen + padlen +1;
	for (i = ssl->out_msglen; i <msglen; i++){
		ssl->out_msg[i] = (unsigned char) padlen;
	}

	ssl->out_msglen=msglen;

	log_assert((msglen >0) &&(msglen % cipher_info->block_size ==0));
	log_assert(msglen % cipher_info->block_size ==0);

	cipher_info->base->cbc_encrypt_func(ssl->enc_ctx, msglen, ssl->iv_enc, ssl->out_msg, ssl->out_msg);

	for (i = 8; i > 0;) {
		--i;
		if (++ssl->out_ctr[i] != 0) {
			break;
		}
	}
	ssl->out_hdr[3] = (unsigned char) (msglen >> 8);
	ssl->out_hdr[4] = (unsigned char) (msglen);
	log_notice("<= jhd_tls_ssl_cbc_without_etm_eq_tls10_encrypt_buf(JHD_OK,msglen:%d)",ssl->out_msglen);
	return JHD_OK;
}


int jhd_tls_ssl_cbc_without_etm_gteq_tls11_encrypt_buf(jhd_tls_ssl_context *ssl){
	const jhd_tls_cipher_info_t *cipher_info;
	unsigned char mac[JHD_TLS_SSL_MAC_ADD];
	size_t msglen;
	uint8_t padlen;
	size_t i;
	unsigned char md_ctx[256];

	log_notice("=>jhd_tls_ssl_cbc_without_etm_gteq_tls11_encrypt_buf(%s;maclen:%ld,msglen=%ld,)",ssl->ciphersuite_info->name,(size_t)ssl->maclen,(size_t)ssl->out_msglen);


	cipher_info =ssl->cipher_info;

	log_assert(ssl->minor_ver >=JHD_TLS_SSL_MINOR_VERSION_2);
	log_assert(cipher_info->mode ==JHD_TLS_MODE_CBC);
	log_assert(ssl->md_info->ctx_size <= 256);

	jhd_tls_md_hmac_starts(ssl->md_info,&md_ctx,ssl->enc_hmac);
	jhd_tls_md_hmac_update(ssl->md_info,&md_ctx,ssl->out_ctr, 8);
	jhd_tls_md_hmac_update(ssl->md_info,&md_ctx,ssl->out_hdr, 5);
	jhd_tls_md_hmac_update(ssl->md_info,&md_ctx,ssl->out_msg, ssl->out_msglen);
	jhd_tls_md_hmac_finish(ssl->md_info,&md_ctx,ssl->enc_hmac, mac,mac);

	memcpy(ssl->out_msg + ssl->out_msglen, mac, ssl->maclen);
	ssl->out_msglen += ssl->maclen;

	padlen = cipher_info->block_size - (ssl->out_msglen + 1) % cipher_info->block_size;
	if (padlen == cipher_info->block_size){
		padlen = 0;
	}
	msglen = ssl->out_msglen + padlen +1;
	for (i = ssl->out_msglen; i <msglen; i++){
		ssl->out_msg[i] = (unsigned char) padlen;
	}

	log_assert((msglen >0) &&(msglen % cipher_info->block_size ==0));

	jhd_tls_random(ssl->out_iv, cipher_info->block_size);

	log_assert(msglen % cipher_info->block_size ==0);

	memcpy_16(ssl->iv_enc,ssl->out_iv);

	cipher_info->base->cbc_encrypt_func(ssl->enc_ctx, msglen, ssl->iv_enc, ssl->out_msg, ssl->out_msg);

	msglen+=cipher_info->block_size;

	ssl->out_msglen = msglen;

	for (i = 8; i > 0;) {
		--i;
		if (++ssl->out_ctr[i] != 0) {
			break;
		}
	}
	ssl->out_hdr[3] = (unsigned char) (msglen >> 8);
	ssl->out_hdr[4] = (unsigned char) (msglen);
	log_notice("<= jhd_tls_ssl_cbc_without_etm_gteq_tls11_encrypt_buf(JHD_OK,msglen:%d)",ssl->out_msglen);
	return JHD_OK;
}


int jhd_tls_ssl_cbc_with_etm_eq_tls10_decrypt_buf(jhd_tls_ssl_context *ssl){
	unsigned char mac[JHD_TLS_SSL_MAC_ADD];
	const jhd_tls_cipher_info_t *cipher_info;
	size_t padlen = 0;
	uint16_t msglen;
	unsigned char md_ctx[256];

	log_notice("=>jhd_tls_ssl_cbc_with_etm_eq_tls10_decrypt_buf(%s;maclen:%ld,msglen=%ld,)",ssl->ciphersuite_info->name,(size_t)ssl->maclen,(size_t)ssl->in_msglen);
	cipher_info =ssl->cipher_info;

	log_assert(ssl->minor_ver ==JHD_TLS_SSL_MINOR_VERSION_1);
	log_assert(cipher_info->mode ==JHD_TLS_MODE_CBC);
	log_assert(ssl->md_info->ctx_size <= 256);

	msglen = ssl->in_msglen;

	msglen-=ssl->maclen;

	*((size_t*)mac) = *((size_t*)( ssl->in_ctr));
	*((uint32_t*)(mac+8)) = *((uint32_t*)(ssl->in_hdr));
	mac[11] = (unsigned char) (msglen >> 8);
	mac[12] = (unsigned char) (msglen);



	jhd_tls_md_hmac_starts(ssl->md_info,&md_ctx,ssl->dec_hmac);
	jhd_tls_md_hmac_update(ssl->md_info,&md_ctx, mac, 13);
	jhd_tls_md_hmac_update(ssl->md_info,&md_ctx,ssl->in_iv, msglen);
	jhd_tls_md_hmac_finish(ssl->md_info,&md_ctx,ssl->dec_hmac, mac,mac);

	if (jhd_tls_ssl_safer_memcmp(ssl->in_iv + msglen, mac, ssl->maclen) != 0) {
		log_err( "message mac does not match");
		goto func_error;
	}
	if (msglen % cipher_info->block_size != 0) {
		log_err( "msglen (%u) %% ivlen (%d) != 0", msglen, cipher_info->block_size );
		goto func_error;
	}

	cipher_info->base->cbc_decrypt_func(ssl->dec_ctx, msglen, ssl->iv_dec, ssl->in_msg, ssl->in_msg);

	padlen = 1 + ssl->in_msg[msglen - 1];
	if(padlen > cipher_info->block_size){
		log_err( "padlen (%u) > ivlen (%d) != 0", padlen, cipher_info->block_size );
		goto func_error;
	}
	msglen -=padlen;
	if (msglen == 0) {
		ssl->nb_zero++;
		if (ssl->nb_zero > 3) {
			log_err( "received four consecutive empty " "messages, possible DoS attack");
			goto func_error;
		}
	} else{
		ssl->nb_zero = 0;
	}
	ssl->in_msglen = msglen;
	for (msglen = 8; msglen > 0;){
		--msglen;
		if (++ssl->in_ctr[msglen] != 0){
			break;
		}
	}

	/*
	 * ignore by saga
	 * if (msglen == 0) {
			log_err( "incoming message counter would wrap");
			return JHD_ERROR;
		}*/

	log_notice("<=jhd_tls_ssl_cbc_with_etm_eq_tls10_decrypt_buf(JHD_OK,msglen:%d)",(int)ssl->in_msglen);
	return JHD_OK;
	func_error:
	log_notice("<=jhd_tls_ssl_cbc_with_etm_eq_tls10_decrypt_buf(JHD_ERROR)");
	return JHD_ERROR;
}

int jhd_tls_ssl_cbc_without_etm_eq_tls10_decrypt_buf(jhd_tls_ssl_context *ssl){
	unsigned char mac[JHD_TLS_SSL_MAC_ADD];
	const jhd_tls_cipher_info_t *cipher_info;
	size_t padlen = 0;
	uint16_t msglen;
	unsigned char md_ctx[256];
	log_notice("=>jhd_tls_ssl_cbc_without_etm_eq_tls10_decrypt_buf(%s;maclen:%ld,msglen=%ld,)",ssl->ciphersuite_info->name,(size_t)ssl->maclen,(size_t)ssl->in_msglen);
	cipher_info =ssl->cipher_info;
	log_assert(ssl->minor_ver ==JHD_TLS_SSL_MINOR_VERSION_1);
	log_assert(cipher_info->mode ==JHD_TLS_MODE_CBC);
	log_assert(ssl->md_info->ctx_size <= 256);
	msglen = ssl->in_msglen;
	if (msglen % cipher_info->block_size != 0) {
		log_err( "msglen (%u) %% ivlen (%d) != 0", msglen, cipher_info->block_size );
		goto func_error;
	}
	cipher_info->base->cbc_decrypt_func(ssl->dec_ctx, msglen, ssl->iv_dec, ssl->in_msg, ssl->in_msg);
	padlen = 1 + ssl->in_msg[msglen - 1];

	if(padlen > cipher_info->block_size){
		log_err( "padlen (%u) > ivlen (%d) != 0", padlen, cipher_info->block_size );
		goto func_error;
	}

	msglen -= padlen;
	msglen -= ssl->maclen;

	ssl->in_hdr[3] = (unsigned char) (msglen >> 8);
	ssl->in_hdr[4] = (unsigned char) (msglen);

	jhd_tls_md_hmac_starts(ssl->md_info,&md_ctx,ssl->dec_hmac);
	jhd_tls_md_hmac_update(ssl->md_info,&md_ctx, ssl->in_ctr, 8);
	jhd_tls_md_hmac_update(ssl->md_info,&md_ctx,ssl->in_hdr, msglen+5);
	jhd_tls_md_hmac_finish(ssl->md_info,&md_ctx,ssl->dec_hmac, mac,mac);

	if (jhd_tls_ssl_safer_memcmp(ssl->in_msg + msglen, mac, ssl->maclen) != 0) {
		log_err( "message mac does not match");
		goto func_error;
	}

	if (msglen == 0) {
		ssl->nb_zero++;
		if (ssl->nb_zero > 3) {
			log_err( "received four consecutive empty " "messages, possible DoS attack");
			goto func_error;
		}
	} else{
		ssl->nb_zero = 0;
	}
	ssl->in_msglen = msglen;

	for (msglen = 8; msglen > 0;){
		--msglen;
		if (++ssl->in_ctr[msglen] != 0){
			break;
		}
	}

	/*
	 * ignore by saga
	 * if (msglen == 0) {
			log_err( "incoming message counter would wrap");
			return JHD_ERROR;
		}*/

	log_notice("<=jhd_tls_ssl_cbc_without_etm_eq_tls10_decrypt_buf(JHD_OK,msglen:%d)",(int)ssl->in_msglen);
	return JHD_OK;
	func_error:
	log_notice("<=jhd_tls_ssl_cbc_without_etm_eq_tls10_decrypt_buf(JHD_ERROR)");
	return JHD_ERROR;
}

int jhd_tls_ssl_cbc_with_etm_gteq_tls11_decrypt_buf(jhd_tls_ssl_context *ssl){
	unsigned char mac[JHD_TLS_SSL_MAC_ADD];
		const jhd_tls_cipher_info_t *cipher_info;
		size_t padlen = 0;
		uint16_t msglen;
		unsigned char md_ctx[256];

		log_notice("=>jhd_tls_ssl_cbc_with_etm_gteq_tls11_decrypt_buf(%s;maclen:%ld,msglen=%ld,)",ssl->ciphersuite_info->name,(size_t)ssl->maclen,(size_t)ssl->in_msglen);

		cipher_info =ssl->cipher_info;

		log_assert(ssl->minor_ver >JHD_TLS_SSL_MINOR_VERSION_1);
		log_assert(cipher_info->mode ==JHD_TLS_MODE_CBC);
		log_assert(ssl->md_info->ctx_size <= 256);

		msglen = ssl->in_msglen;

		msglen-=ssl->maclen;

		memcpy_8(mac,ssl->in_ctr);
		memcpy_4(mac+8,ssl->in_hdr);

		mac[11] = (unsigned char) (msglen >> 8);
		mac[12] = (unsigned char) (msglen);

		jhd_tls_md_hmac_starts(ssl->md_info,&md_ctx,ssl->dec_hmac);
		jhd_tls_md_hmac_update(ssl->md_info,&md_ctx, mac,13);
		jhd_tls_md_hmac_update(ssl->md_info,&md_ctx, ssl->in_iv, msglen);
		jhd_tls_md_hmac_finish(ssl->md_info,&md_ctx,ssl->dec_hmac, mac,mac);

		if (jhd_tls_ssl_safer_memcmp(ssl->in_iv + msglen, mac, ssl->maclen) != 0) {
			log_err( "message mac does not match");
			goto func_error;
		}
		if (msglen % cipher_info->block_size != 0) {
			log_err( "msglen (%u) %% ivlen (%d) != 0", msglen, cipher_info->block_size );
			goto func_error;
		}


		msglen-=cipher_info->block_size;

		cipher_info->base->cbc_decrypt_func(ssl->dec_ctx, msglen, ssl->in_iv/*ctx->iv*/, ssl->in_msg, ssl->in_msg);

		padlen = 1 + ssl->in_msg[msglen - 1];

		if(padlen > cipher_info->block_size){
			log_err( "padlen (%u) > ivlen (%d) != 0", padlen, cipher_info->block_size );
			goto func_error;
		}
		msglen -=padlen;
		if (msglen == 0) {
			ssl->nb_zero++;
			if (ssl->nb_zero > 3) {
				log_err( "received four consecutive empty " "messages, possible DoS attack");
				goto func_error;
			}
		} else{
			ssl->nb_zero = 0;
		}
		ssl->in_msglen = msglen;
		for (msglen = 8; msglen > 0;){
			--msglen;
			if (++ssl->in_ctr[msglen] != 0){
				break;
			}
		}
		/*
		 * ignore by saga
		 * if (msglen == 0) {
				log_err( "incoming message counter would wrap");
				return JHD_ERROR;
			}*/

		log_notice("<=jhd_tls_ssl_cbc_with_etm_gteq_tls11_decrypt_buf(JHD_OK,msglen:%d)",(int)ssl->in_msglen);
		return JHD_OK;
		func_error:
		log_notice("<=jhd_tls_ssl_cbc_with_etm_gteq_tls11_decrypt_buf(JHD_ERROR)");
		return JHD_ERROR;
}

int jhd_tls_ssl_cbc_without_etm_gteq_tls11_decrypt_buf(jhd_tls_ssl_context *ssl){
	unsigned char mac[JHD_TLS_SSL_MAC_ADD];
	const jhd_tls_cipher_info_t *cipher_info;
	size_t padlen = 0;
	uint16_t msglen;
	unsigned char md_ctx[256];
	log_notice("=>jhd_tls_ssl_cbc_without_etm_gteq_tls11_decrypt_buf(%s;maclen:%ld,msglen=%ld,)",ssl->ciphersuite_info->name,(size_t)ssl->maclen,(size_t)ssl->in_msglen);

	cipher_info =ssl->cipher_info;

	log_assert(ssl->minor_ver >JHD_TLS_SSL_MINOR_VERSION_1);
	log_assert(cipher_info->mode ==JHD_TLS_MODE_CBC);
	log_assert(ssl->md_info->ctx_size <= 256);

	msglen = ssl->in_msglen;

	if (msglen % cipher_info->block_size != 0) {
		log_err( "msglen (%u) %% ivlen (%d) != 0", msglen, cipher_info->block_size );
		goto func_error;
	}
	msglen-=cipher_info->block_size;
	cipher_info->base->cbc_decrypt_func(ssl->dec_ctx, msglen, ssl->in_iv, ssl->in_msg, ssl->in_msg);
	padlen = 1 + ssl->in_msg[msglen - 1];

	if(padlen > cipher_info->block_size){
		log_err( "padlen (%u) > ivlen (%d) != 0", padlen, cipher_info->block_size );
		goto func_error;
	}
	msglen -= padlen;
    msglen -= ssl->maclen;

	ssl->in_hdr[3] = (unsigned char) (msglen >> 8);
	ssl->in_hdr[4] = (unsigned char) (msglen);

	jhd_tls_md_hmac_starts(ssl->md_info,&md_ctx,ssl->dec_hmac);
	jhd_tls_md_hmac_update(ssl->md_info,&md_ctx,  ssl->in_ctr, 8);
	jhd_tls_md_hmac_update(ssl->md_info,&md_ctx,  ssl->in_hdr, 5);
	jhd_tls_md_hmac_update(ssl->md_info,&md_ctx,ssl->in_msg, msglen);
	jhd_tls_md_hmac_finish(ssl->md_info,&md_ctx,ssl->dec_hmac, mac,mac);

	if (jhd_tls_ssl_safer_memcmp(ssl->in_msg + msglen , mac, ssl->maclen) != 0) {
		log_err( "message mac does not match");
		goto func_error;
	}

	if (msglen == 0) {
		ssl->nb_zero++;
		if (ssl->nb_zero > 3) {
			log_err( "received four consecutive empty " "messages, possible DoS attack");
			goto func_error;
		}
	} else{
		ssl->nb_zero = 0;
	}
	ssl->in_msglen = msglen;

	for (msglen = 8; msglen > 0;){
		--msglen;
		if (++ssl->in_ctr[msglen] != 0){
			break;
		}
	}
	/*
	 * ignore by saga
	 * if (msglen == 0) {
			log_err( "incoming message counter would wrap");
			return JHD_ERROR;
		}*/

	log_notice("<=jhd_tls_ssl_cbc_without_etm_gteq_tls11_decrypt_buf(JHD_OK,msglen:%d)",(int)ssl->in_msglen);
	return JHD_OK;
	func_error:
	log_notice("<=jhd_tls_ssl_cbc_without_etm_gteq_tls11_decrypt_buf(JHD_ERROR)");
	return JHD_ERROR;
}

int jhd_tls_ssl_gcm_encrypt_buf(jhd_tls_ssl_context *ssl){
	const jhd_tls_cipher_info_t *cipher_info;
	unsigned char add[13];
	int i;
	log_notice("=>jhd_tls_ssl_gcm_encrypt_buf(%s;maclen:%ld,msglen=%ld,)",ssl->ciphersuite_info->name,(size_t)ssl->maclen,(size_t)ssl->out_msglen);

	cipher_info =ssl->cipher_info;

	log_assert(cipher_info->mode ==JHD_TLS_MODE_GCM);

	memcpy_8(add,ssl->out_ctr);
	memcpy_4(add+8,ssl->out_hdr);
	//TODO: delete next line
	add[11] = (unsigned char) (ssl->out_msglen >> 8);
	add[12] = (unsigned char)ssl->out_msglen;
	memcpy_8(ssl->out_iv,ssl->out_ctr);
	jhd_tls_gcm_encrypt(ssl->enc_ctx,ssl->iv_enc,ssl->out_ctr,add,ssl->out_msg+ssl->out_msglen,ssl->out_msglen,ssl->out_msg,ssl->out_msg);
	ssl->out_msglen+=(16+8);
	for (i = 8; i > 0;) {
		--i;
		if (++ssl->out_ctr[i] != 0) {
			break;
		}
	}
    /* The loop goes to its end iff the counter is wrapping */
    /*ignore by saga
    if( i == 0 )
    {
        log_err("outgoing message counter would wrap");
        return JHD_ERROR;
    }
    */
	ssl->out_hdr[3] = (unsigned char) (ssl->out_msglen >> 8);
	ssl->out_hdr[4] = (unsigned char) (ssl->out_msglen);
	log_notice("<= jhd_tls_ssl_gcm_encrypt_buf(JHD_OK,msglen:%d)",ssl->out_msglen);
	return JHD_OK;
}

int jhd_tls_ssl_ccm_encrypt_buf(jhd_tls_ssl_context *ssl){
	const jhd_tls_cipher_info_t *cipher_info;
	unsigned char add[13];
	int i;

	log_notice("=>jhd_tls_ssl_ccm_encrypt_buf(%s;maclen:%ld,msglen=%ld,)",ssl->ciphersuite_info->name,(size_t)ssl->maclen,(size_t)ssl->out_msglen);

	cipher_info =ssl->cipher_info;

	log_assert(cipher_info->mode ==JHD_TLS_MODE_CCM);
	memcpy_8(add,ssl->out_ctr);
	memcpy_4(add+8,ssl->out_hdr);
	//TODO: delete next line
	add[11] = (unsigned char) (ssl->out_msglen >> 8);
	add[12] = (unsigned char)ssl->out_msglen;
	memcpy_8(ssl->out_iv,ssl->out_ctr);
	jhd_tls_ccm_encrypt(ssl->enc_ctx,ssl->iv_enc,ssl->out_ctr,add,ssl->out_msg+ssl->out_msglen,ssl->out_msglen,ssl->out_msg,ssl->out_msg);
	ssl->out_msglen+=(16+8);
	for (i = 8; i > 0;) {
		--i;
		if (++ssl->out_ctr[i] != 0) {
			break;
		}
	}
    /* The loop goes to its end iff the counter is wrapping */
    /*ignore by saga
    if( i == 0 )
    {
        log_err("outgoing message counter would wrap");
        return JHD_ERROR;
    }
    */
	ssl->out_hdr[3] = (unsigned char) (ssl->out_msglen >> 8);
	ssl->out_hdr[4] = (unsigned char) (ssl->out_msglen);
	log_notice("<= jhd_tls_ssl_ccm_encrypt_buf(JHD_OK,msglen:%d)",ssl->out_msglen);
	return JHD_OK;
}

int jhd_tls_ssl_gcm_decrypt_buf(jhd_tls_ssl_context *ssl){
	const jhd_tls_cipher_info_t *cipher_info;
	unsigned char add[13];
	uint64_t i,tag[2];
	unsigned char *p;

	log_notice("=>jhd_tls_ssl_gcm_decrypt_buf(%s;maclen:%ld,msglen=%ld,)",ssl->ciphersuite_info->name,(size_t)ssl->maclen,(size_t)ssl->in_msglen);

	cipher_info =ssl->cipher_info;

	log_assert(cipher_info->mode ==JHD_TLS_MODE_GCM);
	log_assert(ssl->in_msglen >= (16+8));

	ssl->in_msglen -=  (8+16);
	memcpy_8(add,ssl->in_ctr);
	memcpy_4(add+8,ssl->in_hdr);
	add[11] = (unsigned char) (ssl->in_msglen >> 8);
	add[12] = (unsigned char) ssl->in_msglen;

	jhd_tls_gcm_decrypt(ssl->dec_ctx,ssl->iv_dec,ssl->in_iv,add,(unsigned char*)tag, ssl->in_msglen,ssl->in_msg,ssl->in_msg);

	p = ssl->in_msg + ssl->in_msglen;

    tag[0] ^= *((uint64_t*)p);
    tag[0] |= ((*((uint64_t*)(8+p))) ^ tag[1]);
    if( tag[0] != 0 ){
       log_err("gcm decrypt error:tag not macth");
       log_notice("<= jhd_tls_ssl_gcm_encrypt_buf(JHD_ERROR)");
       return JHD_ERROR;
    }
	for (i = 8; i > 0;) {
		--i;
		if (++ssl->in_ctr[i] != 0) {
			break;
		}
	}
    /* The loop goes to its end iff the counter is wrapping */
    /*ignore by saga
    if( i == 0 )
    {
        log_err("outgoing message counter would wrap");
        return JHD_ERROR;
    }
    */
	log_notice("<= jhd_tls_ssl_gcm_encrypt_buf(JHD_OK,msglen:%d)",(int)ssl->in_msglen);
	return JHD_OK;
}

int jhd_tls_ssl_ccm_decrypt_buf(jhd_tls_ssl_context *ssl){
	const jhd_tls_cipher_info_t *cipher_info;
	unsigned char add[13];
	uint64_t tag[2];
	uint16_t i;
	unsigned char *p;

	log_notice("=>jhd_tls_ssl_ccm_decrypt_buf(%s;maclen:%ld,msglen=%ld,)",ssl->ciphersuite_info->name,(size_t)ssl->maclen,(size_t)ssl->in_msglen);

	cipher_info =ssl->cipher_info;
	log_assert(cipher_info->mode ==JHD_TLS_MODE_CCM);
	log_assert(ssl->in_msglen >= (16+8));

	ssl->in_msglen -= (16+ 8);
	memcpy_8(add,ssl->in_ctr);
	memcpy_4(add+8,ssl->in_hdr);
	add[11] = (unsigned char) (ssl->in_msglen >> 8);
	add[12] = (unsigned char) ssl->in_msglen;

	jhd_tls_ccm_decrypt(ssl->dec_ctx,ssl->iv_dec,ssl->in_iv,add,(unsigned char*)(tag), ssl->in_msglen,ssl->in_msg,ssl->in_msg);

	p = ssl->in_msg+ssl->in_msglen;

	tag[0] ^= (*((uint64_t*)p));

	tag[0] |=  tag[1] ^  (*((uint64_t*)(p+8)));

    if( tag[0] != 0 ){
		log_err("ccm decrypt error");
		log_notice("<= jhd_tls_ssl_ccm_encrypt_buf(JHD_ERROR)");
		return JHD_ERROR;
	}
	for (i = 8; i > 0;) {
		--i;
		if (++ssl->in_ctr[i] != 0) {
			break;
		}
	}
    /* The loop goes to its end iff the counter is wrapping */
    /*ignore by saga
    if( i == 0 )
    {
        log_err("outgoing message counter would wrap");
        return JHD_ERROR;
    }
    */
	log_notice("<= jhd_tls_ssl_ccm_encrypt_buf(JHD_OK,msglen:%d)",(int)ssl->in_msglen);
	return JHD_OK;
}


#ifdef JHD_LOG_ASSERT_ENABLE

static unsigned char  assert_ssl[sizeof(jhd_tls_ssl_context)];
static unsigned char  assert_ssl_record[17*1024];



static void assert_log_ssl(void *ctx,int byencrypt){
	jhd_tls_ssl_context *ssl = ctx;
	int major,minor,block_size,iv_size,maclen;
	major = ssl->major_ver;
	minor = ssl->minor_ver;
	block_size = (ssl->cipher_info->block_size);
	if(ssl->cipher_info->mode == JHD_TLS_MODE_CBC){
		iv_size = block_size;
	}else{
		iv_size = 8;
	}
	maclen = ssl->maclen;
	log_assert_msg("---->ciphersuite:%s\n",ssl->ciphersuite_info->name);
	log_assert_msg("---->version:[%d,%d],block_size:%d,iv_size:%d,maclen:%d\n",major,minor,block_size,iv_size,maclen);
	if(byencrypt){
		log_assert_buf(ssl->enc_key,block_size,"enc_key");
		log_assert_buf(ssl->iv_enc,iv_size,"enc_iv");
		log_assert_buf(ssl->out_ctr,8,"enc_ctr");
		log_assert_buf(assert_ssl_record,ssl->out_msg- ssl->out_hdr + ssl->out_msglen,"ssl record(CLEAN)");
	}else{
		log_assert_buf(ssl->dec_key,block_size,"dec_key");
		log_assert_buf(ssl->iv_dec,iv_size,"enc_iv");
		log_assert_buf(ssl->in_ctr,8,"dec_ctr");
		log_assert_buf(assert_ssl_record,5 + ssl->in_msglen,"ssl record(CRYPT)");
	}
}

int jhd_tls_ssl_do_encrypt(jhd_tls_ssl_context *ssl){
	size_t msglen;
	int ret;

	if(ssl->out_msglen > 1024 *16){
		log_assert_msg("!!!!!!!!!!!!!!!   before encrypt ssl->out_msglen > 16*1024\n\n\n\n\n\n\n\n\n");
		log_assert(0);
	}
	memcpy(assert_ssl,ssl,sizeof(jhd_tls_ssl_context));
	memcpy(assert_ssl_record,ssl->out_hdr,ssl->out_msg - ssl->out_hdr+ssl->out_msglen);
	if(ssl->cipher_info->mode == JHD_TLS_MODE_CBC){
		if(ssl->encrypt_then_mac){
			msglen =ssl->cipher_info->block_size -(ssl->out_msglen % ssl->cipher_info->block_size);
			msglen +=ssl->out_msglen;
			msglen +=ssl->maclen;
		}else{
			msglen = ssl->out_msglen + ssl->maclen;
			msglen  =ssl->cipher_info->block_size -(  msglen % ssl->cipher_info->block_size);
			msglen +=ssl->out_msglen;
			msglen +=ssl->maclen;
		}
		if(ssl->minor_ver > JHD_TLS_SSL_MINOR_VERSION_1){
			msglen +=ssl->cipher_info->block_size;
		}
	}else{
		msglen = ssl->out_msglen + 8 + 16;
	}
	ret = ssl->encrypt_func(ssl);
	if(ret == 0){
		if(ssl->out_msglen > ssl->maxlen || ssl->out_msglen < ssl->minlen || ssl->out_msglen != msglen ){
			log_assert_msg("******assert info by jhd_tls_ssl_do_encrypt(return msglen:%d,calc msglen:%d,maxlen:%d,minlen:%d)************",(int)ssl->out_msglen,msglen,(int)ssl->maxlen,(int)ssl->minlen);
			assert_log_ssl(assert_ssl,1);
			log_assert(0);
		}
    }
	return ret;
}
int jhd_tls_ssl_do_decrypt(jhd_tls_ssl_context *ssl){
size_t olen,clen;

	int ret;

	if(ssl->in_msglen < ssl->minlen){
		log_assert_msg("!!!!!!!!!!!!!!!   before decrypt ssl->in_msglen(%d) > ssl->minlen(%d)\n\n\n\n\n\n\n\n\n",(int)ssl->in_msglen,(int)ssl->minlen);
		log_assert(0);
	}
	if(ssl->in_msglen > ssl->maxlen){
		log_assert_msg("!!!!!!!!!!!!!!!   before decrypt ssl->in_msglen(%d) > ssl->maxlen(%d)\n\n\n\n\n\n\n\n\n",(int)ssl->in_msglen,(int)ssl->maxlen);
		log_assert(0);
	}
	olen = ssl->in_msglen;
	memcpy(assert_ssl,ssl,sizeof(jhd_tls_ssl_context));
	memcpy(assert_ssl_record,ssl->in_hdr,5 +ssl->in_msglen);
	ret = ssl->decrypt_func(ssl);
	if(ret ==0){
		if(ssl->cipher_info->mode == JHD_TLS_MODE_CBC){
			if(ssl->encrypt_then_mac){
				clen = ssl->cipher_info->block_size -( ssl->in_msglen % ssl->cipher_info->block_size);
				clen += ssl->in_msglen;
				clen += ssl->maclen;
			}else{
				clen = ssl->in_msglen + ssl->maclen;
				clen =ssl->cipher_info->block_size - ( clen % ssl->cipher_info->block_size);
				clen += ssl->in_msglen;
				clen += ssl->maclen;
			}
			if(ssl->minor_ver > JHD_TLS_SSL_MINOR_VERSION_1){
				clen += ssl->cipher_info->block_size;
			}
		}else{
			clen = ssl->in_msglen + 8 + 16;
		}


		if(ssl->in_msglen > (16*1024)  || olen != clen ){
			log_assert_msg("******assert info by jhd_tls_ssl_do_decrypt(clean msglen:%d,crypt msglen:%lu,clac msglen:%lu)************",(int)ssl->in_msglen,olen,clen);
			assert_log_ssl(assert_ssl,0);
			log_assert(0);
		}
	}else{
		log_assert_msg("******error info by jhd_tls_ssl_do_decrypt(ERROR)************");
		assert_log_ssl(assert_ssl,0);
	}
	return ret;
}
#endif












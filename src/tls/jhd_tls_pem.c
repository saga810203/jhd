#include <jhd_config.h>
#include <jhd_log.h>
#include <tls/jhd_tls_config.h>
#include <tls/jhd_tls_pem.h>
#include <jhd_base64.h>
#include <tls/jhd_tls_des.h>
#include <tls/jhd_tls_aes.h>
#include <tls/jhd_tls_md5.h>
#include <tls/jhd_tls_cipher_internal.h>

#include <string.h>

#include <tls/jhd_tls_platform.h>


#if !defined(JHD_TLS_INLINE)
void jhd_tls_pem_init(jhd_tls_pem_context *ctx) {
	memset(ctx, 0, sizeof(jhd_tls_pem_context));
}
#endif

/*
 * Read a 16-byte hex string and convert it to binary
 */
//static int pem_get_iv(const unsigned char *s, unsigned char *iv, size_t iv_len) {
//	size_t i, j, k;
//
//	memset(iv, 0, iv_len);
//
//	for (i = 0; i < iv_len * 2; i++, s++) {
//		if (*s >= '0' && *s <= '9')
//			j = *s - '0';
//		else if (*s >= 'A' && *s <= 'F')
//			j = *s - '7';
//		else if (*s >= 'a' && *s <= 'f')
//			j = *s - 'W';
//		else
//			return JHD_ERROR;
//
//		k = ((i & 1) != 0) ? j : j << 4;
//
//		iv[i >> 1] = (unsigned char) (iv[i >> 1] | k);
//	}
//
//	return (0);
//}
//
//static int pem_pbkdf1(unsigned char *key, size_t keylen, unsigned char *iv, const unsigned char *pwd, size_t pwdlen) {
//	jhd_tls_md5_context md5_ctx;
//	unsigned char md5sum[16];
//	size_t use_len;
//	jhd_tls_md5_init(&md5_ctx);
//
//	/*
//	 * key[ 0..15] = MD5(pwd || IV)
//	 */
//	jhd_tls_md5_starts_ret(&md5_ctx);
//	jhd_tls_md5_update_ret(&md5_ctx, pwd, pwdlen);
//	jhd_tls_md5_update_ret(&md5_ctx, iv, 8);
//	jhd_tls_md5_finish_ret(&md5_ctx, md5sum);
//
//	if (keylen <= 16) {
//		memcpy(key, md5sum, keylen);
//		return 0;
//	}
//
//	memcpy(key, md5sum, 16);
//
//	/*
//	 * key[16..23] = MD5(key[ 0..15] || pwd || IV])
//	 */
//	jhd_tls_md5_starts_ret(&md5_ctx);
//	jhd_tls_md5_update_ret(&md5_ctx, md5sum, 16);
//	jhd_tls_md5_update_ret(&md5_ctx, pwd, pwdlen);
//	jhd_tls_md5_update_ret(&md5_ctx, iv, 8);
//	jhd_tls_md5_finish_ret(&md5_ctx, md5sum);
//
//	use_len = 16;
//	if (keylen < 32)
//		use_len = keylen - 16;
//
//	memcpy(key + 16, md5sum, use_len);
//
//	return (0);
//}
//
//
///*
// * Decrypt with DES-CBC, using PBKDF1 for key derivation
// */
//static int pem_des_decrypt(unsigned char des_iv[8], unsigned char *buf, size_t buflen, const unsigned char *pwd, size_t pwdlen) {
//	jhd_tls_des_context des_ctx;
//	unsigned char des_key[8];
//	int ret;
//
//	jhd_tls_platform_zeroize(&des_ctx, sizeof(jhd_tls_des_context));
//
//	if ((ret = pem_pbkdf1(des_key, 8, des_iv, pwd, pwdlen)) != 0)
//		goto exit;
//
//	  jhd_tls_des_setkey_dec(&des_ctx, des_key, 0) ;
//	  jhd_tls_des_crypt_cbc(&des_ctx, JHD_TLS_DECRYPT, buflen, des_iv, buf, buf);
//
//	exit: return (0);
//}
//
///*
// * Decrypt with 3DES-CBC, using PBKDF1 for key derivation
// */
//static int pem_des3_decrypt(unsigned char des3_iv[8], unsigned char *buf, size_t buflen, const unsigned char *pwd, size_t pwdlen) {
//	jhd_tls_des3_context des3_ctx;
//	unsigned char des3_key[24];
//	int ret;
//
//	jhd_tls_platform_zeroize(&des3_ctx, sizeof(jhd_tls_des3_context));
//
//	if ((ret = pem_pbkdf1(des3_key, 24, des3_iv, pwd, pwdlen)) != 0)
//		goto exit;
//
//	  jhd_tls_des3_set3key_dec(&des3_ctx, des3_key, 0) ;
//	  jhd_tls_des3_crypt_cbc(&des3_ctx, JHD_TLS_DECRYPT, buflen, des3_iv, buf, buf);
//
//	exit:
//
//	return (ret);
//}


//
///*
// * Decrypt with AES-XXX-CBC, using PBKDF1 for key derivation
// */
//static int pem_aes_decrypt(unsigned char aes_iv[16], unsigned int keylen, unsigned char *buf, size_t buflen, const unsigned char *pwd, size_t pwdlen) {
//	jhd_tls_aes_context aes_ctx;
//	unsigned char aes_key[32];
//	int ret;
//
//	jhd_tls_platform_zeroize(&aes_ctx, sizeof(jhd_tls_aes_context));
//
//	if ((ret = pem_pbkdf1(aes_key, keylen, aes_iv, pwd, pwdlen)) != 0)
//		goto exit;
//
//	aes_info.setkey_dec_func(&aes_ctx, aes_key, keylen * 8) ;
//	aes_info.cbc_decrypt_func(&aes_ctx,buflen, aes_iv, buf, buf);
//
//	exit:
//	jhd_tls_platform_zeroize(aes_key, keylen);
//
//	return (ret);
//}

//int jhd_tls_pem_read_buffer_include_crypt(unsigned char *buf, size_t *buf_len, const char *header, const char *footer,const unsigned char *data,const unsigned char *pwd,size_t pwdlen, size_t *use_len){
//	int ret, enc;
//	size_t len;
//	const unsigned char *s1, *s2, *end;
//	unsigned char pem_iv[16];
//	jhd_tls_cipher_type_t enc_alg = JHD_TLS_CIPHER_NONE;
//	*use_len = 0;
//	s1 = (unsigned char *) strstr((const char *) data, header);
//	if (s1 == NULL)
//		return JHD_AGAIN;
//	s2 = (unsigned char *) strstr((const char *) data, footer);
//	if (s2 == NULL || s2 <= s1)
//		return JHD_AGAIN;
//	s1 += strlen(header);
//	if (*s1 == ' ')
//		s1++;
//	if (*s1 == '\r')
//		s1++;
//	if (*s1 == '\n')
//		s1++;
//	else
//		return JHD_AGAIN;
//	end = s2;
//	end += strlen(footer);
//	if (*end == ' ')
//		end++;
//	if (*end == '\r')
//		end++;
//	if (*end == '\n')
//		end++;
//	*use_len = end - data;
//	enc = 0;
//	if (s2 - s1 >= 22 && memcmp(s1, "Proc-Type: 4,ENCRYPTED", 22) == 0) {
//		enc++;
//		s1 += 22;
//		if (*s1 == '\r')
//			s1++;
//		if (*s1 == '\n')
//			s1++;
//		else
//			return JHD_ERROR;
//
//
//		if (s2 - s1 >= 23 && memcmp(s1, "DEK-Info: DES-EDE3-CBC,", 23) == 0) {
//			enc_alg = JHD_TLS_CIPHER_DES_EDE3_CBC;
//			s1 += 23;
//			if (s2 - s1 < 16 || pem_get_iv(s1, pem_iv, 8) != 0)
//				return JHD_ERROR;
//
//			s1 += 16;
//		} else if (s2 - s1 >= 18 && memcmp(s1, "DEK-Info: DES-CBC,", 18) == 0) {
//			enc_alg = JHD_TLS_CIPHER_DES_CBC;
//
//			s1 += 18;
//			if (s2 - s1 < 16 || pem_get_iv(s1, pem_iv, 8) != 0)
//				return JHD_ERROR;
//
//			s1 += 16;
//		}
//
//
//
//		if (s2 - s1 >= 14 && memcmp(s1, "DEK-Info: AES-", 14) == 0) {
//			if (s2 - s1 < 22)
//				return JHD_UNSUPPORTED;
//			else if (memcmp(s1, "DEK-Info: AES-128-CBC,", 22) == 0)
//				enc_alg = JHD_TLS_CIPHER_AES_128_CBC;
//			else if (memcmp(s1, "DEK-Info: AES-192-CBC,", 22) == 0)
//				enc_alg = JHD_TLS_CIPHER_AES_192_CBC;
//			else if (memcmp(s1, "DEK-Info: AES-256-CBC,", 22) == 0)
//				enc_alg = JHD_TLS_CIPHER_AES_256_CBC;
//			else
//				return JHD_UNSUPPORTED;
//
//			s1 += 22;
//			if (s2 - s1 < 32 || pem_get_iv(s1, pem_iv, 16) != 0)
//				return JHD_ERROR;
//
//			s1 += 32;
//		}
//
//
//		if (enc_alg == JHD_TLS_CIPHER_NONE)
//			return JHD_UNSUPPORTED;
//
//		if (*s1 == '\r')
//			s1++;
//		if (*s1 == '\n')
//			s1++;
//		else
//			return JHD_ERROR;
//	}
//
//	if (s1 >= s2)
//		return JHD_ERROR;
//
//
//	if(((s2-s1 +3) / 4 * 3)<= *buf_len){
//
//	}
//
//	log_assert(((s2-s1 +3) / 4 * 3)<= *buf_len/*,"out buffer too small"*/);
//
//	if (JHD_OK != jhd_base64_decode(buf, *buf_len, &len, s1, s2 - s1)){
//		return JHD_ERROR;
//	}
//	if (enc != 0) {
//		if (pwd == NULL) {
//			return JHD_OK;
//		}
//		ret = 0;
//		if (enc_alg == JHD_TLS_CIPHER_DES_EDE3_CBC)
//			ret = pem_des3_decrypt(pem_iv, buf, len, pwd, pwdlen);
//		else if (enc_alg == JHD_TLS_CIPHER_DES_CBC)
//			ret = pem_des_decrypt(pem_iv, buf, len, pwd, pwdlen);
//		if (enc_alg == JHD_TLS_CIPHER_AES_128_CBC)
//			ret = pem_aes_decrypt(pem_iv, 16, buf, len, pwd, pwdlen);
//		else if (enc_alg == JHD_TLS_CIPHER_AES_192_CBC)
//			ret = pem_aes_decrypt(pem_iv, 24, buf, len, pwd, pwdlen);
//		else if (enc_alg == JHD_TLS_CIPHER_AES_256_CBC)
//			ret = pem_aes_decrypt(pem_iv, 32, buf, len, pwd, pwdlen);
//		if (ret != 0) {
//			return JHD_ERROR;
//		}
//
//		/*
//		 * The result will be ASN.1 starting with a SEQUENCE tag, with 1 to 3
//		 * length bytes (allow 4 to be sure) in all known use cases.
//		 *
//		 * Use that as a heuristic to try to detect password mismatches.
//		 */
//		if (len <= 2 || buf[0] != 0x30 || buf[1] > 0x83) {
//			return JHD_ERROR;
//		}
//	}
//	*buf_len = len;
//	return JHD_OK;
//
//
//
//}

int jhd_tls_pem_read_buffer(unsigned char *buf, size_t *buf_len, const char *header, const char *footer,const unsigned char *data,size_t *use_len){
	int ret;
	size_t len;
	const unsigned char *s1, *s2, *end;
	*use_len = 0;
	s1 = (unsigned char *) strstr((const char *) data, header);
	log_assert(s1!=NULL);
	s1 += strlen(header);
	if (*s1 == ' ')	s1++;
	if (*s1 == '\r') s1++;
	if (*s1 == '\n') s1++;
	else return JHD_ERROR;


	s2 = (unsigned char *) strstr((const char *) s1, footer);
	if (s2 == NULL || s2 == s1){
		return JHD_ERROR;
	}
	end = s2;
	end += strlen(footer);
	if (*end == ' ') end++;
	if (*end == '\r') end++;
	if (*end == '\n') end++;
	*use_len = end - data;

	log_assert(((s2-s1 +3) / 4 * 3)<= *buf_len/*,"out buffer too small"*/);
	if (JHD_OK != jhd_base64_decode(buf, *buf_len, &len, s1, s2 - s1)){
		return JHD_ERROR;
	}
	*buf_len = len;
	return JHD_OK;
}

void jhd_tls_pem_free(jhd_tls_pem_context *ctx) {
	if (ctx->buf != NULL){
		jhd_tls_free(ctx->buf);
	}
	if(ctx->info){
	jhd_tls_free(ctx->info);
	}
}



int jhd_tls_pem_write_buffer(const char *header, const char *footer, const unsigned char *der_data, size_t der_len, unsigned char *buf, size_t buf_len,
        size_t *olen) {
	int ret;
	unsigned char *encode_buf = NULL, *c, *p = buf;
	size_t len = 0, use_len, add_len = 0;

	jhd_base64_encode( NULL, 0, &use_len, der_data, der_len);
	add_len = strlen(header) + strlen(footer) + (use_len / 64) + 1;

	if (use_len + add_len > buf_len) {
		*olen = use_len + add_len;
		return JHD_ERROR;
	}

	if (use_len != 0 && ((encode_buf = jhd_tls_malloc(use_len)) == NULL))
		return JHD_ERROR;

	if ((ret = jhd_base64_encode(encode_buf, use_len, &use_len, der_data, der_len)) != 0) {
		jhd_tls_free(encode_buf);
		return (ret);
	}

	memcpy(p, header, strlen(header));
	p += strlen(header);
	c = encode_buf;

	while (use_len) {
		len = (use_len > 64) ? 64 : use_len;
		memcpy(p, c, len);
		use_len -= len;
		p += len;
		c += len;
		*p++ = '\n';
	}

	memcpy(p, footer, strlen(footer));
	p += strlen(footer);

	*p++ = '\0';
	*olen = p - buf;

	jhd_tls_free(encode_buf);
	return (0);
}


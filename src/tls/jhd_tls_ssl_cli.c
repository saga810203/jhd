#include <jhd_config.h>
#include <jhd_log.h>
#include <tls/jhd_tls_config.h>
#include <tls/jhd_tls_platform.h>
#include <tls/jhd_tls_ssl.h>
#include <tls/jhd_tls_ssl_internal.h>
#include <string.h>
#include <stdint.h>


static void ssl_write_hostname_ext(jhd_tls_ssl_context *ssl, unsigned char *buf, size_t *olen) {
	unsigned char *p = buf;
	size_t hostname_len;

	if (ssl->hostname == NULL){
		*olen = 0;
	}else{
		hostname_len = strlen(ssl->hostname);
		/*
		 * Sect. 3, RFC 6066 (TLS Extensions Definitions)
		 *
		 * In order to provide any of the server names, clients MAY include an
		 * extension of type "server_name" in the (extended) client hello. The
		 * "extension_data" field of this extension SHALL contain
		 * "ServerNameList" where:
		 *
		 * struct {
		 *     NameType name_type;
		 *     select (name_type) {
		 *         case host_name: HostName;
		 *     } name;
		 * } ServerName;
		 *
		 * enum {
		 *     host_name(0), (255)
		 * } NameType;
		 *
		 * opaque HostName<1..2^16-1>;
		 *
		 * struct {
		 *     ServerName server_name_list<1..2^16-1>
		 * } ServerNameList;
		 *
		 */
		*p++ = (unsigned char) (( JHD_TLS_TLS_EXT_SERVERNAME >> 8) & 0xFF);
		*p++ = (unsigned char) (( JHD_TLS_TLS_EXT_SERVERNAME) & 0xFF);

		*p++ = (unsigned char) (((hostname_len + 5) >> 8) & 0xFF);
		*p++ = (unsigned char) (((hostname_len + 5)) & 0xFF);

		*p++ = (unsigned char) (((hostname_len + 3) >> 8) & 0xFF);
		*p++ = (unsigned char) (((hostname_len + 3)) & 0xFF);

		*p++ = (unsigned char) (( JHD_TLS_TLS_EXT_SERVERNAME_HOSTNAME) & 0xFF);
		*p++ = (unsigned char) ((hostname_len >> 8) & 0xFF);
		*p++ = (unsigned char) ((hostname_len) & 0xFF);

		memcpy(p, ssl->hostname, hostname_len);

		*olen = hostname_len + 9;
	}
}

/*
 * Only if we handle at least one key exchange that needs signatures.
 */

static void ssl_write_signature_algorithms_ext(jhd_tls_ssl_context *ssl, unsigned char *buf, size_t *olen) {
	unsigned char *p = buf;
	size_t sig_alg_len = 0;
	unsigned char *sig_alg_list = buf + 6;
	sig_alg_len= 24;
	/*
	 * Prepare signature_algorithms extension (TLS 1.2)
	 */
	sig_alg_len = 0;
		sig_alg_list[sig_alg_len++] = JHD_TLS_SSL_HASH_MD5;
		sig_alg_list[sig_alg_len++] = JHD_TLS_SSL_SIG_ECDSA;
		sig_alg_list[sig_alg_len++] = JHD_TLS_SSL_HASH_MD5;
		sig_alg_list[sig_alg_len++] = JHD_TLS_SSL_SIG_RSA;
		sig_alg_list[sig_alg_len++] = JHD_TLS_SSL_HASH_SHA1;
		sig_alg_list[sig_alg_len++] = JHD_TLS_SSL_SIG_ECDSA;
		sig_alg_list[sig_alg_len++] = JHD_TLS_SSL_HASH_SHA1;
		sig_alg_list[sig_alg_len++] = JHD_TLS_SSL_SIG_RSA;

		sig_alg_list[sig_alg_len++] = JHD_TLS_SSL_HASH_SHA224;
		sig_alg_list[sig_alg_len++] = JHD_TLS_SSL_SIG_ECDSA;
		sig_alg_list[sig_alg_len++] = JHD_TLS_SSL_HASH_SHA224;
		sig_alg_list[sig_alg_len++] = JHD_TLS_SSL_SIG_RSA;

		sig_alg_list[sig_alg_len++] = JHD_TLS_SSL_HASH_SHA256;
		sig_alg_list[sig_alg_len++] = JHD_TLS_SSL_SIG_ECDSA;
		sig_alg_list[sig_alg_len++] = JHD_TLS_SSL_HASH_SHA256;
		sig_alg_list[sig_alg_len++] = JHD_TLS_SSL_SIG_RSA;

		sig_alg_list[sig_alg_len++] = JHD_TLS_SSL_HASH_SHA384;
		sig_alg_list[sig_alg_len++] = JHD_TLS_SSL_SIG_ECDSA;
		sig_alg_list[sig_alg_len++] = JHD_TLS_SSL_HASH_SHA384;
		sig_alg_list[sig_alg_len++] = JHD_TLS_SSL_SIG_RSA;

		sig_alg_list[sig_alg_len++] = JHD_TLS_SSL_HASH_SHA512;
		sig_alg_list[sig_alg_len++] = JHD_TLS_SSL_SIG_ECDSA;
		sig_alg_list[sig_alg_len++] = JHD_TLS_SSL_HASH_SHA512;
		sig_alg_list[sig_alg_len++] = JHD_TLS_SSL_SIG_RSA;

	/*
	 * enum {
	 *     none(0), md5(1), sha1(2), sha224(3), sha256(4), sha384(5),
	 *     sha512(6), (255)
	 * } HashAlgorithm;
	 *
	 * enum { anonymous(0), rsa(1), dsa(2), ecdsa(3), (255) }
	 *   SignatureAlgorithm;
	 *
	 * struct {
	 *     HashAlgorithm hash;
	 *     SignatureAlgorithm signature;
	 * } SignatureAndHashAlgorithm;
	 *
	 * SignatureAndHashAlgorithm
	 *   supported_signature_algorithms<2..2^16-2>;
	 */
	*p++ = (unsigned char) (( JHD_TLS_TLS_EXT_SIG_ALG >> 8) & 0xFF);
	*p++ = (unsigned char) (( JHD_TLS_TLS_EXT_SIG_ALG) & 0xFF);

	*p++ = (unsigned char) (((sig_alg_len + 2) >> 8) & 0xFF);
	*p++ = (unsigned char) (((sig_alg_len + 2)) & 0xFF);

	*p++ = (unsigned char) ((sig_alg_len >> 8) & 0xFF);
	*p++ = (unsigned char) ((sig_alg_len) & 0xFF);

	*olen = 6 + sig_alg_len;
}

static void ssl_write_supported_elliptic_curves_ext(jhd_tls_ssl_context *ssl, unsigned char *buf, size_t *olen) {
	unsigned char *p = buf;
	unsigned char *elliptic_curve_list = p + 6;
	size_t elliptic_curve_len = 0;
	const jhd_tls_ecp_curve_info *info;


	elliptic_curve_len = 0;
	for(info = jhd_tls_ecp_curve_list();info->grp_id != JHD_TLS_ECP_DP_NONE;++info)	{
		elliptic_curve_list[elliptic_curve_len++] = info->tls_id >> 8;
		elliptic_curve_list[elliptic_curve_len++] = info->tls_id & 0xFF;
	}

	if (elliptic_curve_len == 0){
		*olen = 0;
	}else{
		*p++ = (unsigned char) (( JHD_TLS_TLS_EXT_SUPPORTED_ELLIPTIC_CURVES >> 8) & 0xFF);
		*p++ = (unsigned char) (( JHD_TLS_TLS_EXT_SUPPORTED_ELLIPTIC_CURVES) & 0xFF);

		*p++ = (unsigned char) (((elliptic_curve_len + 2) >> 8) & 0xFF);
		*p++ = (unsigned char) (((elliptic_curve_len + 2)) & 0xFF);

		*p++ = (unsigned char) (((elliptic_curve_len) >> 8) & 0xFF);
		*p++ = (unsigned char) (((elliptic_curve_len)) & 0xFF);

		*olen = 6 + elliptic_curve_len;
	}
}

static void ssl_write_supported_point_formats_ext(jhd_tls_ssl_context *ssl, unsigned char *buf, size_t *olen) {
	unsigned char *p = buf;
	*p++ = (unsigned char) (( JHD_TLS_TLS_EXT_SUPPORTED_POINT_FORMATS >> 8) & 0xFF);
	*p++ = (unsigned char) (( JHD_TLS_TLS_EXT_SUPPORTED_POINT_FORMATS) & 0xFF);
	*p++ = 0x00;
	*p++ = 2;
	*p++ = 1;
	*p++ = JHD_TLS_ECP_PF_UNCOMPRESSED;
	*olen = 6;
}

static void ssl_write_max_fragment_length_ext(jhd_tls_ssl_context *ssl, unsigned char *buf, size_t *olen) {
	unsigned char *p = buf;
	if (ssl->conf->mfl_code == JHD_TLS_SSL_MAX_FRAG_LEN_NONE) {
		*olen = 0;
	}else{
		*p++ = (unsigned char) (( JHD_TLS_TLS_EXT_MAX_FRAGMENT_LENGTH >> 8) & 0xFF);
		*p++ = (unsigned char) (( JHD_TLS_TLS_EXT_MAX_FRAGMENT_LENGTH) & 0xFF);
		*p++ = 0x00;
		*p++ = 1;
		*p++ = ssl->conf->mfl_code;
		*olen = 5;
	}
}

static void ssl_write_truncated_hmac_ext(jhd_tls_ssl_context *ssl, unsigned char *buf, size_t *olen) {
	unsigned char *p = buf;
	*p++ = (unsigned char) (( JHD_TLS_TLS_EXT_TRUNCATED_HMAC >> 8) & 0xFF);
	*p++ = (unsigned char) (( JHD_TLS_TLS_EXT_TRUNCATED_HMAC) & 0xFF);
	*p++ = 0x00;
	*p++ = 0x00;
	*olen = 4;
}

static void ssl_write_encrypt_then_mac_ext(jhd_tls_ssl_context *ssl, unsigned char *buf, size_t *olen) {
	unsigned char *p = buf;
	*p++ = (unsigned char) (( JHD_TLS_TLS_EXT_ENCRYPT_THEN_MAC >> 8) & 0xFF);
	*p++ = (unsigned char) (( JHD_TLS_TLS_EXT_ENCRYPT_THEN_MAC) & 0xFF);
	*p++ = 0x00;
	*p++ = 0x00;
	*olen = 4;
}

static void ssl_write_extended_ms_ext(jhd_tls_ssl_context *ssl, unsigned char *buf, size_t *olen) {
	unsigned char *p = buf;
	*p++ = (unsigned char) (( JHD_TLS_TLS_EXT_EXTENDED_MASTER_SECRET >> 8) & 0xFF);
	*p++ = (unsigned char) (( JHD_TLS_TLS_EXT_EXTENDED_MASTER_SECRET) & 0xFF);
	*p++ = 0x00;
	*p++ = 0x00;
	*olen = 4;
}

static void ssl_write_alpn_ext(jhd_tls_ssl_context *ssl, unsigned char *buf, size_t *olen) {
	unsigned char *p = buf;
	size_t alpnlen = 0;
	const char **cur;
	if (ssl->conf->alpn_list == NULL) {
		*olen = 0;
	}else{
		for (cur = ssl->conf->alpn_list; *cur != NULL; cur++){
			alpnlen += (unsigned char) (strlen(*cur) & 0xFF) + 1;
		}
		*p++ = (unsigned char) (( JHD_TLS_TLS_EXT_ALPN >> 8) & 0xFF);
		*p++ = (unsigned char) (( JHD_TLS_TLS_EXT_ALPN) & 0xFF);

		/*
		 * opaque ProtocolName<1..2^8-1>;
		 *
		 * struct {
		 *     ProtocolName protocol_name_list<2..2^16-1>
		 * } ProtocolNameList;
		 */

		/* Skip writing extension and list length for now */
		p += 4;

		for (cur = ssl->conf->alpn_list; *cur != NULL; cur++) {
			*p = (unsigned char) (strlen(*cur) & 0xFF);
			memcpy(p + 1, *cur, *p);
			p += 1 + *p;
		}

		*olen = p - buf;

		/* List length = olen - 2 (ext_type) - 2 (ext_len) - 2 (list_len) */
		buf[4] = (unsigned char) (((*olen - 6) >> 8) & 0xFF);
		buf[5] = (unsigned char) (((*olen - 6)) & 0xFF);

		/* Extension length = olen - 2 (ext_type) - 2 (ext_len) */
		buf[2] = (unsigned char) (((*olen - 4) >> 8) & 0xFF);
		buf[3] = (unsigned char) (((*olen - 4)) & 0xFF);
	}
}

/**
 * \brief           Validate cipher suite against config in SSL context.
 *
 * \param suite_info    cipher suite to validate
 * \param ssl           SSL context
 * \param min_minor_ver Minimal minor version to accept a cipher suite
 * \param max_minor_ver Maximal minor version to accept a cipher suite
 *
 * \return          0 if valid, else 1
 */
static int ssl_validate_ciphersuite(const jhd_tls_ssl_ciphersuite_t * suite_info, const jhd_tls_ssl_context * ssl, int min_minor_ver, int max_minor_ver) {
	(void) ssl;
	if (suite_info == NULL)
		return (1);

	if (suite_info->min_minor_ver > max_minor_ver || suite_info->max_minor_ver < min_minor_ver)
		return (1);
	return (0);
}

static int ssl_write_client_hello(jhd_connection_t *c) {
	int ret;
	size_t n, olen, ext_len = 0;
	unsigned char *buf;
	unsigned char *p, *q;
	jhd_tls_ssl_context *ssl = c->ssl;
	const jhd_tls_ssl_ciphersuite_t *ciphersuite_info;
	log_notice("%s","=> write client hello");
	if(ssl->out_msglen){
		ret = jhd_tls_ssl_flush_output(c);
		if(ret == JHD_OK){
			++ssl->state;
		}
	}else{
		ssl->major_ver = JHD_TLS_SSL_MAX_MAJOR_VERSION;
		ssl->minor_ver = JHD_TLS_SSL_MAX_MINOR_VERSION;
		/*
		 *     0  .   0   handshake type
		 *     1  .   3   handshake length
		 *     4  .   5   highest version supported
		 *     6  .   9   current UNIX time
		 *    10  .  37   random bytes
		 */
		buf = ssl->out_msg;
		p = buf + 4;
		p[0] = JHD_TLS_SSL_MAX_MAJOR_VERSION;
		p[1] = JHD_TLS_SSL_MAX_MINOR_VERSION;
		p += 2;
		jhd_tls_random(ssl->handshake->randbytes,32);
//		memcpy(p, ssl->handshake->randbytes, 32);
		memcpy_32(p,ssl->handshake->randbytes);
		p += 32;
		/*
		 *    38  .  38   session id length
		 *    39  . 39+n  session id
		 *   39+n . 39+n  DTLS only: cookie length (1 byte)
		 *   40+n .  ..   DTSL only: cookie
		 *   ..   . ..    ciphersuitelist length (2 bytes)
		 *   ..   . ..    ciphersuitelist
		 *   ..   . ..    compression methods length (1 byte)
		 *   ..   . ..    compression methods
		 *   ..   . ..    extensions length (2 bytes)
		 *   ..   . ..    extensions
		 */

		*p++ = (unsigned char) 0;


		n = 0;
		q = p;
		p += 2;
		ciphersuite_info = supported_ciphersuites;
		while(ciphersuite_info->id!=0){
			if (ssl_validate_ciphersuite(ciphersuite_info, ssl, JHD_TLS_SSL_MIN_MINOR_VERSION, JHD_TLS_SSL_MAX_MINOR_VERSION) == 0){
				n++;
				*p++ = (unsigned char) ((ciphersuite_info->id) >> 8);
				*p++ = (unsigned char) (ciphersuite_info->id);
			}
			ciphersuite_info++;
		}
		n<<=1;
		*q++ = (unsigned char) (n >> 8);
		*q++ = (unsigned char) (n);
		*p++ = 1;
		*p++ = JHD_TLS_SSL_COMPRESS_NULL;

		ssl_write_hostname_ext(ssl, p + 2 + ext_len, &olen);
		ext_len += olen;

		/* Note that TLS_EMPTY_RENEGOTIATION_INFO_SCSV is always added
		 * even if JHD_TLS_SSL_RENEGOTIATION is not defined. */

		ssl_write_signature_algorithms_ext(ssl, p + 2 + ext_len, &olen);
		ext_len += olen;

		ssl_write_supported_elliptic_curves_ext(ssl, p + 2 + ext_len, &olen);
		ext_len += olen;

		ssl_write_supported_point_formats_ext(ssl, p + 2 + ext_len, &olen);
		ext_len += olen;
		ssl_write_max_fragment_length_ext(ssl, p + 2 + ext_len, &olen);
		ext_len += olen;

		ssl_write_truncated_hmac_ext(ssl, p + 2 + ext_len, &olen);
		ext_len += olen;

		ssl_write_encrypt_then_mac_ext(ssl, p + 2 + ext_len, &olen);
		ext_len += olen;
		ssl_write_extended_ms_ext(ssl, p + 2 + ext_len, &olen);
		ext_len += olen;

		ssl_write_alpn_ext(ssl, p + 2 + ext_len, &olen);
		ext_len += olen;
		*p++ = (unsigned char) ((ext_len >> 8) & 0xFF);
		*p++ = (unsigned char) ((ext_len) & 0xFF);
		p+= ext_len;

		ret = p - buf;
		ssl->out_offt = ssl->out_hdr;
		ssl->out_msglen = ret+5;
		JHD_TLS_SSL_SET_SSL_RECORD(ssl,JHD_TLS_SSL_MSG_HANDSHAKE,ret);
		ret-=4;
		JHD_TLS_SSL_SET_HANDSHAKE(ssl,JHD_TLS_SSL_HS_CLIENT_HELLO,ret);
		log_buf_debug("write ssl record====>",ssl->out_hdr,ssl->out_msglen);
		ret = jhd_tls_ssl_flush_output(c);
		if(ret == JHD_OK){
			++ssl->state;
		}
	}
	log_notice("%s","<= write client hello");
	return ret;
}

static int ssl_parse_renegotiation_info(jhd_connection_t *c, const unsigned char *buf, size_t len) {
	if (len != 1 || buf[0] != 0x00) {
		log_err("%s","non-zero length renegotiation info");
		jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL, JHD_TLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE);
		return JHD_ERROR;
	}
	return JHD_OK;
}

static int ssl_parse_max_fragment_length_ext(jhd_connection_t *c, const unsigned char *buf, size_t len) {
	/*
	 * server should use the extension only if we did,
	 * and if so the server's value should match ours (and len is always 1)
	 */
	jhd_tls_ssl_context *ssl=c->ssl;
	if (ssl->conf->mfl_code == JHD_TLS_SSL_MAX_FRAG_LEN_NONE || len != 1 || buf[0] != ssl->conf->mfl_code) {
		log_err("%s","non-matching max fragment length extension");
		jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL,JHD_TLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE);
		return JHD_ERROR;
	}
	return JHD_OK;
}

static int ssl_parse_truncated_hmac_ext(jhd_connection_t *c, const unsigned char *buf, size_t len) {
	if (len != 0) {
		log_err("%s", "non-matching truncated HMAC extension");
		jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL, JHD_TLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE);
		return JHD_ERROR;
	}
	((void) buf);
	((jhd_tls_ssl_context*)c->ssl)->handshake->trunc_hmac = JHD_TLS_SSL_TRUNC_HMAC_ENABLED;
	return JHD_OK;
}

static int ssl_parse_encrypt_then_mac_ext(jhd_connection_t *c, const unsigned char *buf, size_t len) {
	if (len != 0) {
		log_err("%s", ("non-matching encrypt-then-MAC extension"));
		jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL,JHD_TLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE);
		return JHD_ERROR;
	}
	((void) buf);
	((jhd_tls_ssl_context*)c->ssl)->handshake->encrypt_then_mac = JHD_TLS_SSL_ETM_ENABLED;
#if defined(JHD_LOG_LEVEL_DEBUH) || defined(JHD_LOG_ASSERT_ENABLE)
	((jhd_tls_ssl_context*)c->ssl)->encrypt_then_mac=JHD_TLS_SSL_ETM_ENABLED;
#endif
	return JHD_OK;
}

static int ssl_parse_extended_ms_ext(jhd_connection_t *c,  const unsigned char *buf, size_t len) {
	if (len != 0) {
		log_err("%s",("non-matching extended master secret extension"));
		jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL,JHD_TLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE);
		return JHD_ERROR;
	}
	((jhd_tls_ssl_context*)c->ssl)->handshake->extended_ms = JHD_TLS_SSL_EXTENDED_MS_ENABLED;
	return JHD_OK;
}

static int ssl_parse_supported_point_formats_ext(jhd_connection_t *c,  const unsigned char *buf, size_t len) {
	size_t list_size;
	const unsigned char *p;

	list_size = buf[0];
	if (list_size + 1 != len) {
		log_err("%s", ("bad server hello message"));
		jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL,JHD_TLS_SSL_ALERT_MSG_DECODE_ERROR);
		return JHD_ERROR;
	}

	p = buf + 1;
	while (list_size > 0) {
		if (p[0] == JHD_TLS_ECP_PF_UNCOMPRESSED || p[0] == JHD_TLS_ECP_PF_COMPRESSED) {
			((jhd_tls_ssl_context*)c->ssl)->handshake->ecdh_ctx.point_format = p[0];
			return JHD_OK;
		}
		list_size--;
		p++;
	}
	log_err("%s", ("no point format in common"));
	jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL,JHD_TLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE);
	return JHD_ERROR;
}

static int ssl_parse_alpn_ext(jhd_connection_t *c,  const unsigned char *buf, size_t len) {
	size_t list_len, name_len;
	const char **p;
	/* If we didn't send it, the server shouldn't send it */
	if (((jhd_tls_ssl_context*)c->ssl)->conf->alpn_list == NULL) {
		log_err("%s",("non-matching ALPN extension"));
		jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL,JHD_TLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE);
		return JHD_ERROR;
	}

	/*
	 * opaque ProtocolName<1..2^8-1>;
	 *
	 * struct {
	 *     ProtocolName protocol_name_list<2..2^16-1>
	 * } ProtocolNameList;
	 *
	 * the "ProtocolNameList" MUST contain exactly one "ProtocolName"
	 */

	/* Min length is 2 (list_len) + 1 (name_len) + 1 (name) */
	if (len < 4) {
		jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL,JHD_TLS_SSL_ALERT_MSG_DECODE_ERROR);
		return JHD_ERROR;
	}

	list_len = (buf[0] << 8) | buf[1];
	if (list_len != len - 2) {
		jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL,JHD_TLS_SSL_ALERT_MSG_DECODE_ERROR);
		return JHD_ERROR;
	}

	name_len = buf[2];
	if (name_len != list_len - 1) {
		jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL,JHD_TLS_SSL_ALERT_MSG_DECODE_ERROR);
		return JHD_ERROR;
	}

	/* Check that the server chosen protocol was in our list and save it */
	for (p = ((jhd_tls_ssl_context*)c->ssl)->conf->alpn_list; *p != NULL; p++) {
		if (name_len == strlen(*p) && memcmp(buf + 3, *p, name_len) == 0) {
			((jhd_tls_ssl_context*)c->ssl)->alpn_chosen = *p;
			return JHD_OK;
		}
	}

	log_err("%s", ("ALPN extension: no matching protocol"));
	jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL,JHD_TLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE);
	return JHD_ERROR;
}

static int ssl_parse_server_hello(jhd_connection_t *c) {
	int ret, i;
	uint32_t msg_len;
	size_t n;
	size_t ext_len;
	unsigned char *buf, *ext;
	const jhd_tls_ssl_ciphersuite_t *suite_info;
	jhd_tls_ssl_context *ssl=c->ssl;

	log_assert(ssl->in_msglen==0);
	log_notice("%s",  ("=> parse server hello"));
	JHD_TLS_SSL_READ_SSL_RECORD_CONTENT

	buf = ssl->in_offt = ssl->in_msg;
	msg_len = ((buf[2]<<8)|(buf[3]))  +  4;
	if ((msg_len > ssl->in_msglen) || (buf[0] != JHD_TLS_SSL_HS_SERVER_HELLO) || (buf[1]!=0) || (msg_len < (38+jhd_tls_ssl_hs_hdr_len(ssl)))) {
		log_err("%s", ( "bad server hello message" ));
		jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL, JHD_TLS_SSL_ALERT_MSG_DECODE_ERROR);
		goto func_error;
	}

	/*
	 *  0   .  1    server_version
	 *  2   . 33    random (maybe including 4 bytes of Unix time)
	 * 34   . 34    session_id length = n
	 * 35   . 34+n  session_id
	 * 35+n . 36+n  cipher_suite
	 * 37+n . 37+n  compression_method
	 *
	 * 38+n . 39+n  extensions length (optional)
	 * 40+n .  ..   extensions
	 */
	buf += jhd_tls_ssl_hs_hdr_len(ssl);
	ssl->major_ver = buf[0];
	ssl->minor_ver = buf[1];

	if (ssl->major_ver < JHD_TLS_SSL_MIN_MAJOR_VERSION || ssl->minor_ver < JHD_TLS_SSL_MIN_MINOR_VERSION || ssl->major_ver > JHD_TLS_SSL_MAX_MAJOR_VERSION
	        || ssl->minor_ver > JHD_TLS_SSL_MAX_MINOR_VERSION) {
		log_err("server version [%d:%d] unsupported ",ssl->major_ver, ssl->minor_ver);
		jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL,JHD_TLS_SSL_ALERT_MSG_PROTOCOL_VERSION);
		goto func_error;
	}
//	memcpy(ssl->handshake->randbytes + 32, buf + 2, 32);
	memcpy_32(ssl->handshake->randbytes + 32, buf + 2);
	n = buf[34];
	if (n > 32) {
		log_err("bad server hello message:session id length:%d",n);
		jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL,JHD_TLS_SSL_ALERT_MSG_DECODE_ERROR);
		goto func_error;
	}

	if (msg_len > jhd_tls_ssl_hs_hdr_len(ssl) + 39 + n) {
		ext_len = ((buf[38 + n] << 8) | (buf[39 + n]));

		if ((ext_len > 0 && ext_len < 4) ||( msg_len != (jhd_tls_ssl_hs_hdr_len(ssl) + 40 + n + ext_len))) {
			log_err("bad server hello message:ext_len:%d",ext_len);
			jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL,JHD_TLS_SSL_ALERT_MSG_DECODE_ERROR);
			goto func_error;
		}
	} else if (msg_len == jhd_tls_ssl_hs_hdr_len(ssl) + 38 + n) {
		ext_len = 0;
	} else {
		log_err("bad server hello message:msg_len:%d",msg_len);
		jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL,JHD_TLS_SSL_ALERT_MSG_DECODE_ERROR);
		goto func_error;
	}

	/* ciphersuite (used later) */
	i = (buf[35 + n] << 8) | buf[36 + n];

	/*
	 * Read and check compression
	 */

	if (buf[37 + n] != JHD_TLS_SSL_COMPRESS_NULL) {
		log_err("server hello, bad compression: %d", buf[37 + n]);
		jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL, JHD_TLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER);
		goto func_error;
	}

	/*
	 * Initialize update checksum functions
	 */
	suite_info = ssl->handshake->ciphersuite_info = jhd_tls_ssl_ciphersuite_from_id(i);

	if (suite_info == NULL) {
		log_err("ciphersuite info for %04x not found", i);
		jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL, JHD_TLS_SSL_ALERT_MSG_INTERNAL_ERROR);
		goto func_error;
	}
	jhd_tls_ssl_optimize_checksum(ssl, suite_info);

	if (ssl_validate_ciphersuite(suite_info, ssl, ssl->minor_ver, ssl->minor_ver) != 0) {
		log_err("%s", ("bad server hello message"));
		jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL,JHD_TLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER);
		goto func_error;
	}
	ext = buf + 40 + n;
	while (ext_len) {
		unsigned int ext_id = ((ext[0] << 8) | (ext[1]));
		unsigned int ext_size = ((ext[2] << 8) | (ext[3]));

		if (ext_size + 4 > ext_len) {
			log_err("%s",  ("bad server hello message"));
			jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL,JHD_TLS_SSL_ALERT_MSG_DECODE_ERROR);
			goto func_error;
		}
		switch (ext_id) {
			case JHD_TLS_TLS_EXT_RENEGOTIATION_INFO:
				log_debug("%s", ("found renegotiation extension"));

				if (JHD_OK != ssl_parse_renegotiation_info(c, ext + 4, ext_size)){
					goto func_error;
				}
				break;

			case JHD_TLS_TLS_EXT_MAX_FRAGMENT_LENGTH:
				log_debug("%s", ("found max_fragment_length extension"));
				if (JHD_OK != ssl_parse_max_fragment_length_ext(c, ext + 4, ext_size)) {
					goto func_error;
				}
				break;
			case JHD_TLS_TLS_EXT_TRUNCATED_HMAC:
				log_debug("%s", ("found truncated_hmac extension"));

				if (JHD_OK != ssl_parse_truncated_hmac_ext(c, ext + 4, ext_size)){
					goto func_error;
				}
				break;
			case JHD_TLS_TLS_EXT_ENCRYPT_THEN_MAC:
				log_debug("%s", ("found encrypt_then_mac extension"));

				if (JHD_OK != ssl_parse_encrypt_then_mac_ext(c, ext + 4, ext_size)){
					goto func_error;
				}
				break;
			case JHD_TLS_TLS_EXT_EXTENDED_MASTER_SECRET:
				log_debug("%s",("found extended_master_secret extension"));

				if (JHD_OK != ssl_parse_extended_ms_ext(c, ext + 4, ext_size)){
					goto func_error;
				}
				break;
			case JHD_TLS_TLS_EXT_SUPPORTED_POINT_FORMATS:
				log_debug("%s", ("found supported_point_formats extension"));

				if (JHD_OK != ssl_parse_supported_point_formats_ext(c, ext + 4, ext_size)) {
					goto func_error;
				}
				break;

			case JHD_TLS_TLS_EXT_ALPN:
				log_debug("%s", ("found alpn extension"));

				if (JHD_OK != ssl_parse_alpn_ext(c, ext + 4, ext_size)) {
					goto func_error;
				}
				break;
			default:
				log_debug("unknown extension found: %d (ignoring)", ext_id);
		}

		ext_len -= 4 + ext_size;
		ext += 4 + ext_size;

		if (ext_len > 0 && ext_len < 4) {
			log_err("%s", ("bad server hello message"));
			goto func_error;
		}
	}
	ssl->handshake->update_checksum(ssl,ssl->in_offt,msg_len);
	ssl->in_msglen -=(msg_len);
	ssl->in_offt +=(msg_len);
	ssl->state++;
	ret = JHD_OK;
	func_return:
		log_notice("%s", "<= parse server hello" );
		return ret;
	func_error:
	    c->recv = jhd_connection_error_recv;
		log_notice("%s", "<= parse server hello" );
		return JHD_ERROR;
}

static int ssl_check_server_ecdh_params(const jhd_tls_ssl_context *ssl) {
	  const jhd_tls_ecp_curve_info *curve_info;
	  curve_info = jhd_tls_ecp_curve_info_from_grp_id( ssl->handshake->ecdh_ctx.grp->id );
	    if( curve_info == NULL )
	    {
	        log_err( "%s", ( "should never happen" ) );
	        return JHD_ERROR;
	    }

	if (jhd_tls_ssl_check_curve(ssl, ssl->handshake->ecdh_ctx.grp->id) != 0)
		return JHD_ERROR;
	return JHD_OK;
}


static int ssl_parse_server_ecdh_params(jhd_tls_ssl_context *ssl,unsigned char **p, unsigned char *end) {
	int ret ;
	/*
	 * Ephemeral ECDH parameters:
	 *
	 * struct {
	 *     ECParameters curve_params;
	 *     ECPoint      public;
	 * } ServerECDHParams;
	 */
	if ((ret = jhd_tls_ecdh_read_params(&ssl->handshake->ecdh_ctx,(const unsigned char **) p, end)) != 0) {
		log_err("jhd_tls_ecdh_read_params(jhd_tls_ecdh_context*, const unsigned char**, const unsigned char*)==%d", ret);
		return JHD_ERROR;
	}

	if (ssl_check_server_ecdh_params(ssl) != JHD_OK) {
		log_err("%s", ("bad server key exchange message (ECDHE curve)"));
		return JHD_ERROR;
	}

	return JHD_OK;
}


/*
 * Generate a pre-master secret and encrypt it with the server's RSA key
 */
static int ssl_write_encrypted_pms(jhd_tls_ssl_context *ssl, size_t offset, size_t *olen, size_t pms_offset) {
	int ret;
	size_t len_bytes = ssl->minor_ver == JHD_TLS_SSL_MINOR_VERSION_0 ? 0 : 2;
	unsigned char *p = ssl->handshake->premaster + pms_offset;

	if (offset + len_bytes > JHD_TLS_SSL_MAX_CONTENT_LEN) {
		log_debug("buffer too small for encrypted pms");
		return JHD_ERROR;
	}

	/*
	 * Generate (part of) the pre-master as
	 *  struct {
	 *      ProtocolVersion client_version;
	 *      opaque random[46];
	 *  } PreMasterSecret;
	 */
	p[0] = JHD_TLS_SSL_MAX_MAJOR_VERSION;
	p[1] = JHD_TLS_SSL_MAX_MINOR_VERSION;

	jhd_tls_random(p + 2, 46);

	ssl->handshake->pmslen = 48;

	if (ssl->handshake->peer_cert == NULL) {
		log_debug("certificate required");
		return JHD_ERROR;
	}

	/*
	 * Now write it out, encrypted
	 */
	if (!jhd_tls_pk_can_do(&ssl->handshake->peer_cert->pk, &jhd_tls_rsa_info)) {
		log_debug("certificate key type mismatch");
		return JHD_ERROR;
	}

	if ((ret = jhd_tls_pk_encrypt(&ssl->handshake->peer_cert->pk, p, ssl->handshake->pmslen, ssl->out_msg + offset + len_bytes, olen,
	JHD_TLS_SSL_MAX_CONTENT_LEN - offset - len_bytes)) != 0) {
		log_err( "jhd_tls_rsa_pkcs1_encrypt error");
		return (ret);
	}

	if (len_bytes == 2) {
		ssl->out_msg[offset + 0] = (unsigned char) (*olen >> 8);
		ssl->out_msg[offset + 1] = (unsigned char) (*olen);
		*olen += 2;
	}

	return (0);
}


static int ssl_parse_signature_algorithm(jhd_tls_ssl_context *ssl, unsigned char **p, unsigned char *end, const jhd_tls_md_info_t **md_info,const jhd_tls_pk_info_t **pk_info) {
	((void) ssl);
	*md_info = NULL;
	*pk_info = NULL;
	/* Only in TLS 1.2 */
	if ((*p) + 2 > end){
		return JHD_ERROR;
	}
	/*
	 * Get hash algorithm
	 */
	if ((*md_info = jhd_tls_ssl_md_info_from_hash((*p)[0])) == NULL) {
		log_err("Server used unsupported " "HashAlgorithm %d", *(p)[0]);
		return JHD_ERROR;
	}

	/*
	 * Get signature algorithm
	 */
	if ((*pk_info = jhd_tls_ssl_pk_alg_from_sig((*p)[1])) == NULL) {
		log_err("server used unsupported " "SignatureAlgorithm %d", (*p)[1]);
		return JHD_ERROR;
	}

	log_debug("Server used SignatureAlgorithm %d", (*p)[1]);
	log_debug("Server used HashAlgorithm %d", (*p)[0]);
	*p += 2;

	return JHD_OK;
}

static int ssl_parse_server_key_exchange(jhd_connection_t *c) {
	int ret,msg_len;
	jhd_tls_ssl_context *ssl =c->ssl;
	const jhd_tls_ssl_ciphersuite_t *ciphersuite_info = ssl->handshake->ciphersuite_info;
	unsigned char *p = NULL, *end = NULL;
	size_t sig_len, hashlen;
	unsigned char hash[64];
	const jhd_tls_md_info_t *md_info = NULL;
	const jhd_tls_pk_info_t *pk_info = NULL;
	unsigned char *params ;
	size_t params_len;


	log_notice("%s", ("=> parse server key exchange"));
	if (ciphersuite_info->key_exchange == JHD_TLS_KEY_EXCHANGE_RSA) {
		log_debug("%s", ("skip parse server key exchange(key_exchange == RSA )"));
		ssl->state++;
		ret = JHD_OK;
		goto func_return;
	}
	if(ssl->in_msglen==0){
		JHD_TLS_SSL_READ_SSL_RECORD_CONTENT
		ssl->in_offt = ssl->in_msg;
	}
	p = ssl->in_offt;
	if((p[0] != JHD_TLS_SSL_HS_SERVER_KEY_EXCHANGE)){
		log_err("%s", ("server key exchange message must not be skipped"));
		jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL,JHD_TLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE);
		goto func_error;
	}
	msg_len = ((p[2]<<8)|(p[3]))  +  4;
	if ((msg_len > ssl->in_msglen) || (p[1]!=0)) {
		log_err("%s", ( "bad server key exchange message" ));
		jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL, JHD_TLS_SSL_ALERT_MSG_DECODE_ERROR);
		goto func_error;
	}


	end=p+msg_len;
	p += jhd_tls_ssl_hs_hdr_len(ssl);
	params = p;

	if (ssl_parse_server_ecdh_params(ssl,&p, end) != 0) {
		log_err("%s", ("bad server key exchange message"));
		jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL,JHD_TLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER);

		goto func_error;
	}
    params_len = p - params;
	if (ssl->minor_ver == JHD_TLS_SSL_MINOR_VERSION_3) {
		if (ssl_parse_signature_algorithm(ssl, &p, end, &md_info, &pk_info) != 0) {
			log_err("%s", ("bad server key exchange message"));
			jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL,JHD_TLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER);
			goto func_error;
		}

		if (pk_info != jhd_tls_ssl_get_ciphersuite_sig_pk_alg(ciphersuite_info)) {
			log_err("%s",("bad server key exchange message"));
			jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL,JHD_TLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER);
			goto func_error;
		}
	} else if (ssl->minor_ver < JHD_TLS_SSL_MINOR_VERSION_3) {
		pk_info = jhd_tls_ssl_get_ciphersuite_sig_pk_alg(ciphersuite_info);

		/* Default hash for ECDSA is SHA-1 */
		if (pk_info == &jhd_tls_ecdsa_info){
			md_info = &jhd_tls_sha1_info;
		}
	}

	/*
	 * Read signature
	 */

	if (p > end - 2) {
		log_err("%s", ("bad server key exchange message"));
		jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL,JHD_TLS_SSL_ALERT_MSG_DECODE_ERROR);
		goto func_error;
	}
	sig_len = (p[0] << 8) | p[1];
	p += 2;

	if (p != end - sig_len) {
		log_err("%s", ("bad server key exchange message"));
		jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL,JHD_TLS_SSL_ALERT_MSG_DECODE_ERROR);
		goto func_error;
	}
	if (md_info == NULL) {
		hashlen = 36;
		jhd_tls_ssl_get_key_exchange_md_ssl_tls(hash,ssl->handshake->randbytes, params, params_len);
	} else {
		jhd_tls_ssl_get_key_exchange_md_tls1_2(hash, &hashlen,ssl->handshake->randbytes, params, params_len, md_info);
	}
	if (ssl->handshake->peer_cert == NULL) {
		log_err("%s", ("certificate required"));
		jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL,JHD_TLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE);
		goto func_error;
	}

	/*
	 * Verify signature
	 */
	if (!(jhd_tls_pk_can_do(&ssl->handshake->peer_cert->pk, pk_info))) {
		log_err("%s", ("bad server key exchange message"));
		jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL,JHD_TLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE);
		goto func_error;
	}
    ret =jhd_tls_pk_verify(&ssl->handshake->peer_cert->pk, md_info, hash, hashlen, p, sig_len);
	if(JHD_OK !=ret){
		jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL,JHD_TLS_SSL_ALERT_MSG_DECRYPT_ERROR);
		log_err("jhd_tls_pk_verify(...)=%d", ret);
		goto func_error;
	}
	ssl->handshake->update_checksum(ssl,ssl->in_offt,msg_len);
	ssl->in_msglen -=(msg_len);
	ssl->in_offt +=(msg_len);
	ssl->state++;
	ret = JHD_OK;
	func_return:
		log_notice("%s", "<= parse server key exchange" );
		return ret;
	func_error:
		c->recv = jhd_connection_error_recv;
		log_notice("%s", "<= parse server key exchange" );
		return JHD_ERROR;
}

static int ssl_parse_certificate_request(jhd_connection_t *c) {
	int ret;
	uint32_t msg_len;
	unsigned char *buf;
	size_t n = 0;
	size_t cert_type_len = 0, dn_len = 0;
	jhd_tls_ssl_context *ssl = c->ssl;

	log_notice("%s","=> parse (certificate request OR server hello done)");
	if(ssl->in_msglen==0){
		JHD_TLS_SSL_READ_SSL_RECORD_CONTENT
		ssl->in_offt = ssl->in_msg;
	}
	buf = ssl->in_offt;
	if(buf[0] ==JHD_TLS_SSL_HS_CERTIFICATE_REQUEST ){
		log_debug("%s","begin parse certificate request");
		msg_len = ((buf[2]<<8)|(buf[3]))  +  4;
		if ((msg_len > ssl->in_msglen) ||(msg_len <= 4) || (buf[1]!=0)) {
				log_err("%s", ( "bad certificate request message" ));
				jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL, JHD_TLS_SSL_ALERT_MSG_DECODE_ERROR);
				goto func_error;
		}

//		end = buf + msg_len;
//		buf +=4;
		cert_type_len = buf[jhd_tls_ssl_hs_hdr_len(ssl)];
		n = cert_type_len;

		/*
		 * In the subsequent code there are two paths that read from buf:
		 *     * the length of the signature algorithms field (if minor version of
		 *       SSL is 3),
		 *     * distinguished name length otherwise.
		 * Both reach at most the index:
		 *    ...hdr_len + 2 + n,
		 * therefore the buffer length at this point must be greater than that
		 * regardless of the actual code path.
		 */
		if (msg_len <= jhd_tls_ssl_hs_hdr_len(ssl) + 2 + n) {
			log_err("%s", ("bad certificate request message"));
			jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL, JHD_TLS_SSL_ALERT_MSG_DECODE_ERROR);
			goto func_error;
		}

		/* supported_signature_algorithms */

		if (ssl->minor_ver == JHD_TLS_SSL_MINOR_VERSION_3) {
			size_t sig_alg_len = ((buf[jhd_tls_ssl_hs_hdr_len(ssl) + 1 + n] << 8) | (buf[jhd_tls_ssl_hs_hdr_len(ssl) + 2 + n]));


			/*
			 * The furthest access in buf is in the loop few lines below:
			 *     sig_alg[i + 1],
			 * where:
			 *     sig_alg = buf + ...hdr_len + 3 + n,
			 *     max(i) = sig_alg_len - 1.
			 * Therefore the furthest access is:
			 *     buf[...hdr_len + 3 + n + sig_alg_len - 1 + 1],
			 * which reduces to:
			 *     buf[...hdr_len + 3 + n + sig_alg_len],
			 * which is one less than we need the buf to be.
			 */
			if (msg_len <= jhd_tls_ssl_hs_hdr_len(ssl) + 3 + n + sig_alg_len) {
				log_err("%s", ("bad certificate request message"));
				jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL, JHD_TLS_SSL_ALERT_MSG_DECODE_ERROR);
				goto func_error;
			}
			n += 2 + sig_alg_len;
		}

		/* certificate_authorities */
		dn_len = ((buf[jhd_tls_ssl_hs_hdr_len(ssl) + 1 + n] << 8) | (buf[jhd_tls_ssl_hs_hdr_len(ssl) + 2 + n]));

		n += dn_len;
		if (msg_len != jhd_tls_ssl_hs_hdr_len(ssl) + 3 + n) {
			log_err("%s", ("bad certificate request message"));
			jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL,JHD_TLS_SSL_ALERT_MSG_DECODE_ERROR);
			goto func_error;
		}
		ssl->handshake->client_auth = 1;
		ssl->handshake->update_checksum(ssl,ssl->in_offt,msg_len);
		ssl->in_msglen -=(msg_len);
		ssl->in_offt +=(msg_len);
	}
	ssl->state++;
	ret = JHD_OK;
	func_return:
		log_notice("%s", "<= parse (certificate request OR server hello done)" );
		return ret;
	func_error:
		c->recv = jhd_connection_error_recv;
		log_notice("%s", "<= parse (certificate request OR server hello done)" );
		return JHD_ERROR;
}

static int ssl_parse_server_hello_done(jhd_connection_t *c) {
	int ret;
	unsigned char *buf;
	jhd_tls_ssl_context *ssl = c->ssl;

	log_notice("%s", ("=> parse server hello done"));

	if(ssl->in_msglen==0){
		JHD_TLS_SSL_READ_SSL_RECORD_CONTENT
		ssl->in_offt = ssl->in_msg;
	}
	buf = ssl->in_offt;

	if((buf[0]!=JHD_TLS_SSL_HS_SERVER_HELLO_DONE)||(buf[1]!=0)||(buf[2]!=0)||(buf[3]!=0)){
		log_err("%s","bad server hello done message");
		jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL,JHD_TLS_SSL_ALERT_MSG_DECODE_ERROR);
		goto func_error;
	}
	ssl->in_msglen-=4;
	ssl->in_offt+=4;
	ssl->state++;
	ret = JHD_OK;
	func_return:
		log_notice("%s", "<= parse server hello done" );
		return ret;
	func_error:
		c->recv = jhd_connection_error_recv;
		log_notice("%s", "<= parse server hello done" );
		return JHD_ERROR;
}

static int ssl_write_client_key_exchange(jhd_connection_t *c) {
	int ret;
	size_t i, n;
	jhd_tls_ecp_point public_key;
	jhd_tls_ssl_context *ssl = c->ssl;
	const jhd_tls_ssl_ciphersuite_t *ciphersuite_info = ssl->handshake->ciphersuite_info;

	log_notice("%s", ("=> write client key exchange"));

	jhd_tls_ecp_point_init(&public_key);
	if(ssl->out_msglen){
			ret = jhd_tls_ssl_flush_output(c);
			if(ret==JHD_OK){
				++ssl->state;
			}
	}else{
		if (ciphersuite_info->key_exchange == JHD_TLS_KEY_EXCHANGE_ECDHE_RSA || ciphersuite_info->key_exchange == JHD_TLS_KEY_EXCHANGE_ECDHE_ECDSA) {
			/*
			 * ECDH key exchange -- send client public value
			 */
			i = 4;
			ret = jhd_tls_ecdh_make_public(&ssl->handshake->ecdh_ctx,&n, &ssl->out_msg[i], 1000);
			if (ret != 0) {
				log_err("jhd_tls_ecdh_make_public(...)=%d", ret);
				goto func_error;
			}
			jhd_tls_ecp_point_read_binary(ssl->handshake->ecdh_ctx.grp, &public_key,(const unsigned char*) (&ssl->handshake->ecdh_ctx.remote_public_key_buf[1]), ssl->handshake->ecdh_ctx.remote_public_key_buf[0]);
			if ((ret = jhd_tls_ecdh_calc_secret(&ssl->handshake->ecdh_ctx,&public_key, &ssl->handshake->pmslen, ssl->handshake->premaster,JHD_TLS_MPI_MAX_SIZE)) != 0) {
				log_err("jhd_tls_ecdh_calc_secret(...)=%d", ret);
				goto func_error;
			}
		} else /*if (ciphersuite_info->key_exchange == JHD_TLS_KEY_EXCHANGE_RSA)*/ {
			i = 4;
			if ((ret = ssl_write_encrypted_pms(ssl, i, &n, 0)) != 0){
				log_err("ssl_write_encrypted_pms(...)=%d",ret);
				goto func_error;
			}
		}

		i+=n;

		ssl->out_offt = ssl->out_hdr;
		ssl->out_msglen = i + 5;

		ssl->out_hdr[0] = JHD_TLS_SSL_MSG_HANDSHAKE;
		ssl->out_hdr[1] = ssl->major_ver;
		ssl->out_hdr[2] = ssl->minor_ver;
		ssl->out_hdr[3] = (unsigned char) (i >> 8);
		ssl->out_hdr[4] = (unsigned char) (i);

		ssl->out_msg[0] = JHD_TLS_SSL_HS_CLIENT_KEY_EXCHANGE;
		i=-4;
		ssl->out_msg[1] = (unsigned char) (0);// i < 65535
		ssl->out_msg[2] = (unsigned char) (i >> 8);
		ssl->out_msg[3] = (unsigned char) (i);
		ssl->handshake->update_checksum(ssl, ssl->out_msg, i + 4);
		log_buf_debug("write ssl record====>",ssl->out_hdr,ssl->out_msglen);
		ret = jhd_tls_ssl_flush_output(c);
		if(ret == JHD_OK){
			++ssl->state;
		}
	}
	jhd_tls_ecp_point_free(&public_key);
	log_notice("%s", ( "<= write client key exchange" ));
	return ret;
	func_error:
	jhd_tls_ecp_point_free(&public_key);
	log_notice("%s", ( "<= write client key exchange" ));
	c->send = jhd_connection_error_send;
	return JHD_ERROR;

}

static int ssl_write_certificate_verify(jhd_connection_t *c) {
	int ret  ;
	size_t n,offset = 0;
	unsigned char hash[48];
	unsigned char *hash_start = hash;
	const jhd_tls_md_info_t *md_info;
	unsigned int hashlen;
	const jhd_tls_cipher_info_t *cipher_info;
	jhd_tls_ssl_context *ssl=c->ssl;


	log_notice("%s", ( "=> write certificate verify" ));
	if(ssl->out_msglen){
			ret = jhd_tls_ssl_flush_output(c);
			if(ret==JHD_OK){
				++ssl->state;
			}
	}else{
		cipher_info = jhd_tls_cipher_info_from_type(ssl->handshake->ciphersuite_info->cipher);
#if defined(JHD_LOG_LEVEL_NOTICE) || defined(JHD_LOG_ASSERT_ENABLE)
		ssl->ciphersuite_info = ssl->handshake->ciphersuite_info;
#endif
		md_info = ssl->handshake->ciphersuite_info->md_info;
		if ((cipher_info->mode == JHD_TLS_MODE_CBC)){
			ssl->md_info = md_info;
			n = md_info->block_size << 1;
			log_assert(md_info->block_size *2 == n);
			if(ssl->dec_hmac == NULL){
				ssl->dec_hmac = jhd_tls_alloc(n);
				if(ssl->dec_hmac == NULL){
					jhd_tls_wait_mem(&c->write,n)
					ret = JHD_AGAIN;
					goto func_return;
				}
			}
			if(ssl->enc_hmac == NULL){
				ssl->enc_hmac = jhd_tls_alloc(n);
				if(ssl->enc_hmac == NULL){
					jhd_tls_wait_mem(&c->write,n)
					ret = JHD_AGAIN;
					goto func_return;
				}
			}
		}

/*
		if ((cipher_info->mode != JHD_TLS_MODE_GCM) && (cipher_info->mode != JHD_TLS_MODE_CCM)){
			if(ssl->md_ctx_dec.md_ctx == NULL){
				ssl->md_ctx_dec.md_ctx = jhd_tls_alloc(md_info->ctx_size);
				if(ssl->md_ctx_dec.md_ctx == NULL){

					//FIXME: add memory watting queue;  size == md_info->ctx_size;
					ret = JHD_AGAIN;
					goto func_return;
				}
				jhd_tls_platform_zeroize(ssl->md_ctx_dec.md_ctx,md_info->ctx_size);
				ssl->md_ctx_dec.md_info = md_info;
			}
			if(ssl->md_ctx_dec.hmac_ctx == NULL){
				ssl->md_ctx_dec.hmac_ctx = jhd_tls_alloc(md_info->block_size * 2);
				if(ssl->md_ctx_dec.hmac_ctx == NULL){
					//FIXME: add memory watting queue;  size == md_info->block_size * 2;
					ret = JHD_AGAIN;
					goto func_return;
				}
			}
			if(ssl->md_ctx_enc.md_ctx == NULL){
				ssl->md_ctx_enc.md_ctx = jhd_tls_alloc(md_info->ctx_size);
				if(ssl->md_ctx_enc.md_ctx == NULL){

					//FIXME: add memory watting queue;  size == md_info->ctx_size;
					ret = JHD_AGAIN;
					goto func_return;
				}
				jhd_tls_platform_zeroize(ssl->md_ctx_enc.md_ctx,md_info->ctx_size);
				ssl->md_ctx_enc.md_info = md_info;
			}
			if(ssl->md_ctx_enc.hmac_ctx == NULL){
				ssl->md_ctx_enc.hmac_ctx = jhd_tls_alloc(md_info->block_size * 2);
				if(ssl->md_ctx_enc.hmac_ctx == NULL){

					//FIXME: add memory watting queue;  size == md_info->block_size * 2;
					ret = JHD_AGAIN;
					goto func_return;
				}
			}
		}
*/
		ssl->cipher_info = cipher_info;
		n = cipher_info->base->ctx_size;
		if(ssl->dec_ctx == NULL){
			ssl->dec_ctx = jhd_tls_alloc(n);
			if(ssl->dec_ctx == NULL){
				jhd_tls_wait_mem(&c->write,n);
				ret = JHD_AGAIN;
				goto func_return;
			}
			cipher_info->base->cipher_ctx_init(ssl->dec_ctx,cipher_info);
		}
		if(ssl->enc_ctx == NULL){
			ssl->enc_ctx = jhd_tls_alloc(n);
			if(ssl->enc_ctx == NULL){
				jhd_tls_wait_mem(&c->write,n);
				ret = JHD_AGAIN;
				goto func_return;
			}
			cipher_info->base->cipher_ctx_init(ssl->enc_ctx,cipher_info);
		}
		md_info = NULL;
		jhd_tls_ssl_derive_keys(ssl);

		if (ssl->handshake->client_auth == 0) {
			log_debug("%s", ("skip write certificate verify"));
			ssl->state++;
			ret = JHD_OK;
			goto func_return;
		}

		if (ssl->conf->key_cert == NULL) {
			log_err("%s", ("got no private key for certificate"));
			goto func_error;
		}
		/*
		 * Make an RSA signature of the handshake digests
		 */
		ssl->handshake->calc_verify(ssl, hash);
		if (ssl->minor_ver == JHD_TLS_SSL_MINOR_VERSION_3) {
			/*
			 * digitally-signed struct {
			 *     opaque handshake_messages[handshake_messages_length];
			 * };
			 *
			 * Taking shortcut here. We assume that the server always allows the
			 * PRF Hash function and has sent it in the allowed signature
			 * algorithms list received in the Certificate Request message.
			 *
			 * Until we encounter a server that does not, we will take this
			 * shortcut.
			 *
			 * Reason: Otherwise we should have running hashes for SHA512 and SHA224
			 *         in order to satisfy 'weird' needs from the server side.
			 */
			if (ssl->handshake->ciphersuite_info->md_info == &jhd_tls_sha384_info) {
				md_info = &jhd_tls_sha384_info;
				ssl->out_msg[4] = JHD_TLS_SSL_HASH_SHA384;
			} else {
				md_info = &jhd_tls_sha256_info;
				ssl->out_msg[4] = JHD_TLS_SSL_HASH_SHA256;
			}
			ssl->out_msg[5] = jhd_tls_ssl_sig_from_pk(ssl->conf->key_cert->key);

			/* Info from md_alg will be used instead */
			hashlen = 0;
			offset = 2;
		} else	{
			hashlen = 36;

			/*
			 * For ECDSA, default hash is SHA-1 only
			 */
			if (jhd_tls_pk_can_do(jhd_tls_ssl_own_key(ssl), &jhd_tls_ecdsa_info)) {
				hash_start += 16;
				hashlen -= 16;
				md_info = &jhd_tls_sha1_info;
			}
		}

		if ((ret = jhd_tls_pk_sign(ssl->conf->key_cert->key, md_info, hash_start, hashlen, ssl->out_msg + 6 + offset, &n)) != 0) {
			log_err("jhd_tls_pk_sign(...)=%d", ret);
			goto func_error;
		}


		ssl->out_msg[4 + offset] = (unsigned char) (n >> 8);
		ssl->out_msg[5 + offset] = (unsigned char) (n);

		n += (6 + offset);

		ssl->out_offt = ssl->out_hdr;
		ssl->out_msglen = n + 5;

		JHD_TLS_SSL_SET_SSL_RECORD(ssl,JHD_TLS_SSL_MSG_HANDSHAKE,n)
        n -= 4;
        JHD_TLS_SSL_SET_HANDSHAKE(ssl,JHD_TLS_SSL_HS_CERTIFICATE_VERIFY,n)
		log_buf_debug("write ssl record====>",ssl->out_hdr,ssl->out_msglen);
		ret = jhd_tls_ssl_flush_output(c);
		if(ret == JHD_OK){
			++ssl->state;
		}
	}
	func_return:
	log_notice("%s", ( "<= write certificate verify" ));
	return ret;

	func_error:
	c->send = jhd_connection_error_send;
	log_notice("%s", ( "<= write certificate verify" ));
	return JHD_ERROR;
}

/*
 * SSL handshake -- client side -- single step
 */
int jhd_tls_ssl_handshake_client_step(jhd_connection_t *c) {
	int ret = JHD_OK;
	jhd_tls_ssl_context *ssl = c->ssl;
	log_debug("client state: %d", ssl->state);
	switch (ssl->state) {
		case JHD_TLS_SSL_HELLO_REQUEST:
			ssl->state = JHD_TLS_SSL_CLIENT_HELLO;
			break;
			/*
			 *  ==>   ClientHello
			 */
		case JHD_TLS_SSL_CLIENT_HELLO:
			ret = ssl_write_client_hello(c);
			break;

			/*
			 *  <==   ServerHello
			 *        Certificate
			 *      ( ServerKeyExchange  )
			 *      ( CertificateRequest )
			 *        ServerHelloDone
			 */
		case JHD_TLS_SSL_SERVER_HELLO:
			ret = ssl_parse_server_hello(c);
			break;

		case JHD_TLS_SSL_SERVER_CERTIFICATE:
			ret = jhd_tls_ssl_parse_certificate(c);
			break;

		case JHD_TLS_SSL_SERVER_KEY_EXCHANGE:
			ret = ssl_parse_server_key_exchange(c);
			break;

		case JHD_TLS_SSL_CERTIFICATE_REQUEST:
			ret = ssl_parse_certificate_request(c);
			break;

		case JHD_TLS_SSL_SERVER_HELLO_DONE:
			ret = ssl_parse_server_hello_done(c);
			break;

			/*
			 *  ==> ( Certificate/Alert  )
			 *        ClientKeyExchange
			 *      ( CertificateVerify  )
			 *        ChangeCipherSpec
			 *        Finished
			 */
		case JHD_TLS_SSL_CLIENT_CERTIFICATE:
			ret = jhd_tls_ssl_write_certificate(c);
			break;

		case JHD_TLS_SSL_CLIENT_KEY_EXCHANGE:
			ret = ssl_write_client_key_exchange(c);
			break;

		case JHD_TLS_SSL_CERTIFICATE_VERIFY:
			ret = ssl_write_certificate_verify(c);
			break;

		case JHD_TLS_SSL_CLIENT_CHANGE_CIPHER_SPEC:
			ret = jhd_tls_ssl_write_change_cipher_spec(c);
			break;

		case JHD_TLS_SSL_CLIENT_FINISHED:
			ret = jhd_tls_ssl_write_finished(c);
			break;

		case JHD_TLS_SSL_SERVER_CHANGE_CIPHER_SPEC:
			ret = jhd_tls_ssl_parse_change_cipher_spec(c);
			break;

		case JHD_TLS_SSL_SERVER_FINISHED:
			ret = jhd_tls_ssl_parse_finished(c);
			break;
		case JHD_TLS_SSL_HANDSHAKE_WRAPUP:
			jhd_tls_ssl_handshake_wrapup(c);
			break;

		default:
			log_err("invalid state %d", ssl->state);
			return JHD_ERROR;
	}
	return (ret);
}


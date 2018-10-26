#include <jhd_config.h>
#include <tls/jhd_tls_config.h>
#include <jhd_time.h>
#include <tls/jhd_tls_platform.h>
#include <tls/jhd_tls_ssl.h>
#include <tls/jhd_tls_ssl_internal.h>
#include <string.h>
#include <tls/jhd_tls_ecp.h>



static int ssl_match_server_name(jhd_tls_x509_crt *cert,jhd_tls_ssl_context *ssl){
	size_t servername_list_size, hostname_len;
	const unsigned char *p=ssl->handshake->server_name_buf;
	servername_list_size = ((p[0] << 8) | (p[1]));
	p +=2;
	while (servername_list_size > 2) {
		hostname_len = ((p[1] << 8) | p[2]);
		if (p[0] == JHD_TLS_TLS_EXT_SERVERNAME_HOSTNAME && (hostname_len > 0)) {
			if(jhd_tls_x509_crt_verify_name(cert,p+3,hostname_len)==0){
				return JHD_OK;
			}
		}
		servername_list_size -= hostname_len + 3;
		p += hostname_len + 3;
	}
	return JHD_UNEXPECTED;
}

static int ssl_parse_servername_ext(jhd_connection_t *c, const unsigned char *buf, size_t len) {
	size_t servername_list_size, hostname_len,hostname_count;
	const unsigned char *p;
	jhd_tls_ssl_context *ssl = c->ssl;
#ifdef JHD_LOG_LEVEL_INFO
	char hn[256];
#endif
	hostname_count = 0;
	servername_list_size = ((buf[0] << 8) | (buf[1]));
	if (servername_list_size + 2 != len) {
		log_err( "invalid extension(servername), list_size + 2!= %lu",len);
		jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL, JHD_TLS_SSL_ALERT_MSG_DECODE_ERROR);
		return JHD_ERROR;
	}
	p = buf + 2;
	while (servername_list_size > 2) {
		hostname_len = ((p[1] << 8) | p[2]);
		if (hostname_len + 3 > servername_list_size) {
			log_err("%s", "invalid extension(servername), hostname_len + 3 > servername_list_size");
			jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL, JHD_TLS_SSL_ALERT_MSG_DECODE_ERROR);
			return JHD_ERROR;
		}
		if (p[0] == JHD_TLS_TLS_EXT_SERVERNAME_HOSTNAME && (hostname_len >0)) {
#ifdef JHD_LOG_LEVEL_INFO
			memset(hn,0,256);
			memcpy(hn, p + 3,hostname_len>255?255:hostname_len);
			log_info("client hello message servername ext==>servername:%s",hn);
#endif
			++hostname_count;
		}
		servername_list_size -= hostname_len + 3;
		p += hostname_len + 3;
	}
	if (servername_list_size != 0) {
		log_err("%s", "invalid extension(servername), servername_list_size error");
		jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL, JHD_TLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER);
		return JHD_ERROR;
	}
	if(hostname_count){
		ssl->handshake->server_name_buf = buf;
	}
	return JHD_OK;
}

static int ssl_parse_renegotiation_info(jhd_connection_t *c, const unsigned char *buf, size_t len) {
	if (len != 1 || buf[0] != 0x0) {
		log_err("%s","non-zero length renegotiation info");
		jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL, JHD_TLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE);
		return JHD_ERROR;
	}
	return JHD_OK;
}


/*
 * Status of the implementation of signature-algorithms extension:
 *
 * Currently, we are only considering the signature-algorithm extension
 * to pick a ciphersuite which allows us to send the ServerKeyExchange
 * message with a signature-hash combination that the user allows.
 *
 * We do *not* check whether all certificates in our certificate
 * chain are signed with an allowed signature-hash pair.
 * This needs to be done at a later stage.
 *
 */
static int ssl_parse_signature_algorithms_ext(jhd_connection_t *c, const unsigned char *buf, size_t len) {
	size_t sig_alg_list_size;

	const unsigned char *p;
	const unsigned char *end = buf + len;
	const jhd_tls_md_info_t *md_cur;
	const jhd_tls_pk_info_t *sig_cur;
	jhd_tls_ssl_context *ssl = c->ssl;
	sig_alg_list_size = ((buf[0] << 8) | (buf[1]));
	if (((sig_alg_list_size + 2) != len) || ((sig_alg_list_size % 2) != 0)) {
		log_err("invalid extension(signature-algorithms extension) list size:%lu",sig_alg_list_size);
		jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL, JHD_TLS_SSL_ALERT_MSG_DECODE_ERROR);
		return JHD_ERROR;
	}
	/* Currently we only guarantee signing the ServerKeyExchange message according
	 * to the constraints specified in this extension (see above), so it suffices
	 * to remember only one suitable hash for each possible signature algorithm.
	 *
	 * This will change when we also consider certificate signatures,
	 * in which case we will need to remember the whole signature-hash
	 * pair list from the extension.
	 */
	for (p = buf + 2; p < end; p += 2) {
		/* Silently ignore unknown signature or hash algorithms. */
		if ((sig_cur = jhd_tls_ssl_pk_alg_from_sig(p[1])) == NULL) {
			log_debug("client hello v3, signature_algorithm ext, unknown sig alg encoding %u", p[1] );
			continue;
		}
		log_info("client hello v3, signature_algorithm ext,find sig:%s",sig_cur->name);

		/* Check if we support the hash the user proposes */
		 md_cur = jhd_tls_ssl_md_info_from_hash(p[0]);
		if (md_cur ) {
			jhd_tls_ssl_sig_hash_set_add(&ssl->handshake->hash_algs, sig_cur, md_cur);
			log_info( "client hello v3, signature_algorithm ext:" " match sig %s and hash %s", sig_cur->name, md_cur->name );
		}else{
			log_debug( "client hello v3, signature_algorithm ext:" " unknown(unsupported) hash alg encoding %u", p[0]);
			continue;
		}
	}
	return JHD_OK;
}

static int ssl_parse_supported_elliptic_curves(jhd_connection_t *c, const unsigned char *buf, size_t len) {
	size_t list_size, our_size;
	const unsigned char *p;
	const jhd_tls_ecp_curve_info *curve_info/*, **curves*/;
	jhd_tls_ssl_context *ssl = c->ssl;
	list_size = ((buf[0] << 8) | (buf[1]));
	if (list_size + 2 != len || list_size % 2 != 0) {
		log_err("invalid extension(elliptic_curves extension) list size:%lu",list_size);
		jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL, JHD_TLS_SSL_ALERT_MSG_DECODE_ERROR);
		return JHD_ERROR;
	}
	our_size = list_size / 2 + 1;
	if (our_size > JHD_TLS_ECP_DP_MAX)
		our_size = JHD_TLS_ECP_DP_MAX;
	p = buf + 2;
	while (list_size > 0 && our_size > 1) {
		curve_info = jhd_tls_ecp_curve_info_from_tls_id((p[0] << 8) | p[1]);
		if (curve_info != NULL) {
			log_info("client hello v3, elliptic_curves ext:found:%s[%02X%02X]",curve_info->name,p[0],p[1]);
			ssl->handshake->curves_flag |= (1 << ((int) (curve_info->grp_id)));
			our_size--;
		}
		list_size -= 2;
		p += 2;
	}
	return JHD_OK;
}

static int ssl_parse_supported_point_formats(jhd_connection_t *c, const unsigned char *buf, size_t len) {
	size_t list_size;
	const unsigned char *p;
	jhd_tls_ssl_context *ssl = c->ssl;
	list_size = buf[0];
	if (list_size + 1 != len) {
		log_err("invalid supported point formats extension:list_size error" );
		jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL, JHD_TLS_SSL_ALERT_MSG_DECODE_ERROR);
		return JHD_ERROR;
	}
	p = buf + 1;
	while (list_size > 0) {
		if (p[0] == JHD_TLS_ECP_PF_UNCOMPRESSED || p[0] == JHD_TLS_ECP_PF_COMPRESSED) {
			ssl->handshake->ecdh_ctx.point_format = p[0];
			log_info("supported point formats extension:%s[%02X]",p[0] == JHD_TLS_ECP_PF_UNCOMPRESSED?"ECP_PF_UNCOMPRESSED":"ECP_PF_COMPRESSED",p[0]);
			return (0);
		}
		list_size--;
		p++;
	}
	return JHD_OK;
}

static inline char* ssl_get_max_fragment_length_descp(unsigned char c){
	return c == JHD_TLS_SSL_MAX_FRAG_LEN_NONE?
					"JHD_TLS_SSL_MAX_FRAG_LEN_NONE":
					(c == JHD_TLS_SSL_MAX_FRAG_LEN_512?
									"JHD_TLS_SSL_MAX_FRAG_LEN_512":
									(
									c == JHD_TLS_SSL_MAX_FRAG_LEN_1024?
													"JHD_TLS_SSL_MAX_FRAG_LEN_1024":(
													c == JHD_TLS_SSL_MAX_FRAG_LEN_2048?"JHD_TLS_SSL_MAX_FRAG_LEN_2048":"JHD_TLS_SSL_MAX_FRAG_LEN_2048"
													)
									)
					);
}
static int ssl_parse_max_fragment_length_ext(jhd_connection_t *c, const unsigned char *buf, size_t len) {
	jhd_tls_ssl_context *ssl = c->ssl;
	if (len != 1 || buf[0] >= JHD_TLS_SSL_MAX_FRAG_LEN_INVALID) {
		log_err("invalid max fragment length extension:len(%d),val(%02X)",len,buf[02]);
		jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL, JHD_TLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER);
		return JHD_ERROR;
	}
	log_info("max fragment length extension:%s[%02X]",ssl_get_max_fragment_length_descp(buf[0]),buf[0]);
	ssl->handshake->mfl_code = buf[0];
	return JHD_OK;
}
static int ssl_parse_truncated_hmac_ext(jhd_connection_t *c,  const unsigned char *buf, size_t len) {
	jhd_tls_ssl_context *ssl = c->ssl;
	if (len != 0) {
		log_err("invalid truncated hmac extension:ext_len(%ld)",len );
		jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL, JHD_TLS_SSL_ALERT_MSG_DECODE_ERROR);
		return JHD_ERROR;
	}
	((void) buf);
	log_info("truncated hmac extension:SSL_TRUNC_HMAC_ENABLED");
	ssl->handshake->trunc_hmac = JHD_TLS_SSL_TRUNC_HMAC_ENABLED;
	return JHD_OK;
}

static int ssl_parse_encrypt_then_mac_ext(jhd_connection_t *c,  const unsigned char *buf, size_t len) {
	jhd_tls_ssl_context *ssl = c->ssl;
	if (len != 0) {
		log_err("invalid encrypt then mac extension:ext_len(%ld)",len );
		jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL, JHD_TLS_SSL_ALERT_MSG_DECODE_ERROR);
		return JHD_ERROR;
	}
	((void) buf);
	log_info("encrypt then mac extension:SSL_ETM_ENABLED");
	ssl->handshake->encrypt_then_mac = JHD_TLS_SSL_ETM_ENABLED;
#if defined(JHD_LOG_LEVEL_DEBUH) || defined(JHD_LOG_ASSERT_ENABLE)
	((jhd_tls_ssl_context*)c->ssl)->encrypt_then_mac=JHD_TLS_SSL_ETM_ENABLED;
#endif
	return JHD_OK;
}

static int ssl_parse_extended_ms_ext(jhd_connection_t *c,  const unsigned char *buf, size_t len) {
	jhd_tls_ssl_context *ssl = c->ssl;
	if (len != 0) {
		log_err("invalid extended master secret extension:ext_len(%ld)",len );
		jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL, JHD_TLS_SSL_ALERT_MSG_DECODE_ERROR);
		return JHD_ERROR;
	}
	((void) buf);
	log_info("extended master secret extension:SSL_EXTENDED_MS_ENABLED");
	ssl->handshake->extended_ms = JHD_TLS_SSL_EXTENDED_MS_ENABLED;
	return JHD_OK;
}

static int ssl_parse_alpn_ext(jhd_connection_t *c,  const unsigned char *buf, size_t len) {
	size_t list_len, cur_len, ours_len;
	const unsigned char *theirs, *start, *end;
	const char **ours;
#ifdef JHD_LOG_LEVEL_INFO
	char alpn_name[256];
#endif

	jhd_tls_ssl_context *ssl = c->ssl;
	if (ssl->conf->alpn_list == NULL){
		log_info("ssl config(alpn_list == NULL)");
		return JHD_OK;
	}
	/*
	 * opaque ProtocolName<1..2^8-1>;
	 *
	 * struct {
	 *     ProtocolName protocol_name_list<2..2^16-1>
	 * } ProtocolNameList;
	 */

	/* Min length is 2 (list_len) + 1 (name_len) + 1 (name) */
	if (len < 4) {
		log_err("invalid alpn extension:ext_len(%ld)",len);
		jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL, JHD_TLS_SSL_ALERT_MSG_DECODE_ERROR);
		return JHD_ERROR;
	}

	list_len = (buf[0] << 8) | buf[1];
	if (list_len != len - 2) {
		log_err("invalid alpn extension:ext_len(%ld),alpn_list_len(%ld)",len,list_len);
		jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL, JHD_TLS_SSL_ALERT_MSG_DECODE_ERROR);
		return JHD_ERROR;
	}

	/*
	 * Validate peer's list (lengths)
	 */
	start = buf + 2;
	end = buf + len;
	for (theirs = start; theirs != end; theirs += cur_len) {
		cur_len = *theirs++;

		/* Current identifier must fit in list */
		if (cur_len > (size_t) (end - theirs)) {
			log_err("invalid alpn extension:ext_item_len(%ld)",cur_len);
			jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL, JHD_TLS_SSL_ALERT_MSG_DECODE_ERROR);
			return JHD_ERROR;
		}

		/* Empty strings MUST NOT be included */
		if (cur_len == 0) {
			log_err("invalid alpn extension:ext_item_len(%ld)",cur_len);
			jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL, JHD_TLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER);
			return JHD_ERROR;
		}
#ifdef JHD_LOG_LEVEL_INFO
		memset(alpn_name,0,256);
		memcpy(alpn_name,theirs,cur_len);
		log_info("alpn extension==>item:%s",alpn_name);
#endif
	}

	/*
	 * Use our order of preference
	 */
	for (ours = ssl->conf->alpn_list; *ours != NULL; ours++) {
		ours_len = strlen(*ours);
		for (theirs = start; theirs != end; theirs += cur_len) {
			cur_len = *theirs++;

			if (cur_len == ours_len && memcmp(theirs, *ours, cur_len) == 0) {
				ssl->alpn_chosen = *ours;
				log_info("alpn extension==>choose:%s",*ours);
				return JHD_OK;
			}
		}
	}

	/* If we get there, no match was found */
	jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL, JHD_TLS_SSL_ALERT_MSG_NO_APPLICATION_PROTOCOL);
	return JHD_ERROR;
}

/*
 * Auxiliary functions for ServerHello parsing and related actions
 */

/*
 * Return 0 if the given key uses one of the acceptable curves, -1 otherwise
 */

//static int ssl_check_key_curve(jhd_tls_pk_context *pk, const jhd_tls_ecp_curve_info **curves) {
//	const jhd_tls_ecp_curve_info **crv = curves;
//	jhd_tls_ecp_group_id grp_id = jhd_tls_pk_ec(*pk)->grp.id;
//
//	while (*crv != NULL) {
//		if ((*crv)->grp_id == grp_id)
//			return (0);
//		crv++;
//	}
//
//	return (-1);
//}
static inline int ssl_check_key_curve(jhd_tls_pk_context *pk, const int curves_flag) {
	return ((1 << ((int) jhd_tls_pk_ec(*pk)->grp->id)) & curves_flag) ? (0) : (-1);
}

/*
 * Try picking a certificate for this ciphersuite,
 * return 0 on success and -1 on failure.
 */
static jhd_tls_bool ssl_pick_cert(jhd_tls_ssl_context *ssl, const jhd_tls_ssl_ciphersuite_t * ciphersuite_info) {
	jhd_tls_ssl_key_cert *cur, *list, *fallback = NULL;
	const jhd_tls_pk_info_t *pk_info = jhd_tls_ssl_get_ciphersuite_sig_pk_alg(ciphersuite_info);
	uint32_t flags;
	list = ssl->conf->key_cert;
	for (cur = list; cur != NULL; cur = cur->next) {
		if (!jhd_tls_pk_can_do(&cur->cert->pk, pk_info)) {
			continue;
		}
		if (jhd_tls_ssl_check_cert_usage(cur->cert, ciphersuite_info,JHD_TLS_SSL_IS_SERVER, &flags) != 0) {
			continue;
		}
		//if (pk_alg == JHD_TLS_PK_ECDSA && ssl_check_key_curve(&cur->cert->pk, ssl->handshake->curves) != 0) {
		if (pk_info == &jhd_tls_ecdsa_info && ssl_check_key_curve(&cur->cert->pk, ssl->handshake->curves_flag) != 0) {
			continue;
		}
		if(ssl->handshake->server_name_buf != NULL){
			if(ssl_match_server_name(cur->cert,ssl)!=0){
				continue;
			}
		}
		if (ssl->minor_ver < JHD_TLS_SSL_MINOR_VERSION_3 && cur->cert->sig_md != &jhd_tls_sha1_info) {
			if (fallback == NULL){
				fallback = cur;
			}
			continue;
		}
		/* If we get there, we got a winner */
		break;
	}

	if (cur == NULL)
		cur = fallback;
	if (cur != NULL) {
		ssl->handshake->key_cert = cur;
		return jhd_tls_true;
	}
	log_debug("ciphersuite(%s) not found valid cert and private key",ciphersuite_info->name);
	return jhd_tls_false;
}

/*
 * Check if a given ciphersuite is suitable for use with our config/keys/etc
 * Sets ciphersuite_info only if the suite matches.
 */
static jhd_tls_bool ssl_ciphersuite_match(jhd_tls_ssl_context *ssl, const jhd_tls_ssl_ciphersuite_t *ciphersuite_info) {
	if (ciphersuite_info->min_minor_ver > ssl->minor_ver || ciphersuite_info->max_minor_ver < ssl->minor_ver) {
		log_debug("ciphersuite[%s] unsupptored version",ciphersuite_info->name);
		return jhd_tls_false;
	}
	if (jhd_tls_ssl_ciphersuite_uses_ec(ciphersuite_info) && (ssl->handshake->curves_flag == 0)) {
		log_debug("ciphersuite[%s] use curves, but not found supported curves",ciphersuite_info->name);
		return jhd_tls_false;
	}


	/* If the ciphersuite requires signing, check whether
	 * a suitable hash algorithm is present. */
	if (ssl->minor_ver == JHD_TLS_SSL_MINOR_VERSION_3) {
		const jhd_tls_pk_info_t *pk_info = jhd_tls_ssl_get_ciphersuite_sig_alg(ciphersuite_info);
		if (jhd_tls_ssl_sig_hash_set_find(&ssl->handshake->hash_algs,pk_info) == NULL) {
			log_debug("ciphersuite[%s] requires signing, but not found",ciphersuite_info->name);
			return jhd_tls_false;
		}
	}
	/*
	 * Final check: if ciphersuite requires us to have a
	 * certificate/key of a particular type:
	 * - select the appropriate certificate if we have one, or
	 * - try the next ciphersuite if we don't
	 * This must be done last since we modify the key_cert list.
	 */
	return ssl_pick_cert(ssl, ciphersuite_info);
}

/* This function doesn't alert on errors that happen early during
 ClientHello parsing because they might indicate that the client is
 not talking SSL/TLS at all and would not understand our alert. */
static int ssl_parse_client_hello(jhd_connection_t *c) {
	int ret, got_common_suite;
	uint16_t j,ciph_offset, comp_offset, ext_offset,ciph_len, comp_len, ext_len,msg_len;
	unsigned char *buf, *p, *ext;
	const jhd_tls_ssl_ciphersuite_t *ciphersuite_info;
	int sig_hash_alg_ext_present = 0;
	jhd_tls_ssl_context *ssl=c->ssl;


	log_assert(ssl->in_msglen ==0);
	log_notice("==> parse client hello");
	if(ssl->in_left < 5){
		if ((ret = jhd_tls_ssl_fetch_input(c, 5/* ssl record header(5),+  handshark header(4) */)) != JHD_OK) {
			goto func_return;
		}
		if (ssl->in_hdr[0] != JHD_TLS_SSL_MSG_HANDSHAKE) {
			log_err("invalid ssl record type:%u",ssl->in_hdr[0]);
			goto func_error;
		}
		if (ssl->in_hdr[1] < JHD_TLS_SSL_MAJOR_VERSION_3) {
			log_err( "invalid ssl record major version:%u",ssl->in_hdr[1] );
			goto func_error;
		}
		ssl->in_msglen = (ssl->in_hdr[3] << 8) | ssl->in_hdr[4];
		if ((ssl->in_msglen > JHD_TLS_SSL_MAX_CONTENT_LEN)||(ssl->in_msglen < (38/*client hello min len*/ + 4/*handshake min len*/))) {
			log_err( "invalid ssl record(client hello message)  length:%u",ssl->in_msglen);
			goto func_error;
		}
		log_debug("read ssl record legth:%u",ssl->in_msglen);
	}else{
		ssl->in_msglen = (ssl->in_hdr[3] << 8) | ssl->in_hdr[4];
	}
	if ((ret = jhd_tls_ssl_fetch_input(c, 5 + ssl->in_msglen)) != JHD_OK) {
		ssl->in_msglen = 0;
		goto func_return;
	}
	log_debug("ssl record length:%d",ssl->in_msglen);
	log_buf_debug("readed ssl record==>",ssl->in_hdr,ssl->in_msglen+5);
	ssl->in_left = 0;
	buf = ssl->in_msg;
	if (buf[0] != JHD_TLS_SSL_HS_CLIENT_HELLO) {
		log_err( "bad client hello message,invalid hankshake message type:%u",buf[0]);
		goto func_error;
	}
	msg_len = ssl->in_msglen - jhd_tls_ssl_hs_hdr_len(ssl);
	/* We don't support fragmentation of ClientHello (yet?) */
	if (buf[1] != 0 || msg_len != ((buf[2] << 8) | buf[3])) {
		log_err( "bad client hello message,invalid hankshake message len:%u",(buf[1] <<16)  | (buf[2] << 8) | buf[3]);
		goto func_error;
	}
	log_debug("client hello message length:%d",msg_len);
	buf += jhd_tls_ssl_hs_hdr_len(ssl);
	ssl->major_ver = buf[0];
	ssl->minor_ver = buf[1];
	log_debug("client hello message :[%u,%u]",ssl->major_ver,ssl->minor_ver);
	ssl->handshake->max_major_ver = ssl->major_ver;
	ssl->handshake->max_minor_ver = ssl->minor_ver;
	if (ssl->major_ver < JHD_TLS_SSL_MIN_MAJOR_VERSION || ssl->minor_ver < JHD_TLS_SSL_MIN_MINOR_VERSION) {
		log_err( "bad client hello message,unsported ssl version:[%u:%u]",ssl->major_ver,ssl->minor_ver);
		jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL, JHD_TLS_SSL_ALERT_MSG_PROTOCOL_VERSION);
		goto func_error;
	}

	if (ssl->major_ver > JHD_TLS_SSL_MAX_MAJOR_VERSION) {
		ssl->major_ver = JHD_TLS_SSL_MAX_MAJOR_VERSION;
		ssl->minor_ver = JHD_TLS_SSL_MAX_MINOR_VERSION;
	} else if (ssl->minor_ver > JHD_TLS_SSL_MAX_MINOR_VERSION){
		ssl->minor_ver = JHD_TLS_SSL_MAX_MINOR_VERSION;
	}
//	memcpy(ssl->handshake->randbytes, buf + 2, 32);
	memcpy_32(ssl->handshake->randbytes, buf + 2);

	if (buf[34] + 34 + 2 > msg_len) /* 2 for cipherlist length field */
	{
		log_err( "invalid session id length:%u",buf[34]);
		jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL, JHD_TLS_SSL_ALERT_MSG_DECODE_ERROR);
		goto func_error;
	}
	log_buf_debug("client hello message random bytes==>\n",buf+2,32);
	//ciphersuites
	ciph_offset = 35 + buf[34];
	ciph_len = (buf[ciph_offset] << 8) | (buf[ciph_offset + 1]);
	if (ciph_len < 2 || ciph_len + 2 + ciph_offset + 1 > msg_len || (ciph_len % 2) != 0) {
		log_err( "invalid ciphersuite length:%u",ciph_len);
		jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL, JHD_TLS_SSL_ALERT_MSG_DECODE_ERROR);
		goto func_error;
	}
	comp_offset = ciph_offset + 2 + ciph_len;
	comp_len = buf[comp_offset];
	if (comp_len < 1 || comp_len > 16 || comp_len + comp_offset + 1 > msg_len) {
		log_err( "invalid compression length:%d",comp_len);
		jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL, JHD_TLS_SSL_ALERT_MSG_DECODE_ERROR);
		goto func_error;
	}
	//extensions
	ext_offset = comp_offset + 1 + comp_len;
	if (msg_len > ext_offset) {
		if (msg_len < ext_offset + 2) {
			log_err( "invalid extensions offset:%u",ext_offset);
			jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL, JHD_TLS_SSL_ALERT_MSG_DECODE_ERROR);
			goto func_error;
		}
		ext_len = (buf[ext_offset + 0] << 8) | (buf[ext_offset + 1]);
		if ((ext_len > 0 && ext_len < 4) || msg_len != ext_offset + 2 + ext_len) {
			log_err( "invalid extension length:%u",ext_len);
			jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL, JHD_TLS_SSL_ALERT_MSG_DECODE_ERROR);
			goto func_error;
		}
	} else {
		ext_len = 0;
	}
	ext = buf + ext_offset + 2;
	while (ext_len != 0) {
		unsigned int ext_id = ((ext[0] << 8) | (ext[1]));
		unsigned int ext_size = ((ext[2] << 8) | (ext[3]));
		if (ext_size + 4 > ext_len) {
			log_err( "invalid extension size:%u",ext_size);
			jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL, JHD_TLS_SSL_ALERT_MSG_DECODE_ERROR);
			goto func_error;
		}
		switch (ext_id) {
			case JHD_TLS_TLS_EXT_SERVERNAME:
				log_info("found ServerName extension");
				if(JHD_OK != ssl_parse_servername_ext(c, ext + 4, ext_size)){
					goto func_error;
				}
				break;
			case JHD_TLS_TLS_EXT_RENEGOTIATION_INFO:
				log_info("found renegotiation extension");
				if(JHD_OK!= ssl_parse_renegotiation_info(c, ext + 4, ext_size)){
					goto func_error;
				}
				break;
			case JHD_TLS_TLS_EXT_SIG_ALG:
				log_info("found signature_algorithms extension" );
				if(JHD_OK != ssl_parse_signature_algorithms_ext(c, ext + 4, ext_size)){
					goto func_error;
				}
				sig_hash_alg_ext_present = 1;
				break;
			case JHD_TLS_TLS_EXT_SUPPORTED_ELLIPTIC_CURVES:
				log_info("found supported elliptic curves extension" );
				if(JHD_OK != ssl_parse_supported_elliptic_curves(c, ext + 4, ext_size)){
					goto func_error;
				}
				break;
			case JHD_TLS_TLS_EXT_SUPPORTED_POINT_FORMATS:
				log_info("found supported point formats extension" );
				ssl->handshake->cli_exts |= JHD_TLS_TLS_EXT_SUPPORTED_POINT_FORMATS_PRESENT;
				if(JHD_OK != ssl_parse_supported_point_formats(c, ext + 4, ext_size)){
					goto func_error;
				}
				break;
			case JHD_TLS_TLS_EXT_MAX_FRAGMENT_LENGTH:
				log_info("found max fragment length extension");
				if(JHD_OK != ssl_parse_max_fragment_length_ext(c, ext + 4, ext_size)){
					goto func_error;
				}
				break;

			case JHD_TLS_TLS_EXT_TRUNCATED_HMAC:
				log_info("found truncated hmac extension" );
				if(JHD_OK != ssl_parse_truncated_hmac_ext(c, ext + 4, ext_size)){
					goto func_error;
				}
				break;
			case JHD_TLS_TLS_EXT_ENCRYPT_THEN_MAC:
				log_info("found encrypt then mac extension" );

				if(JHD_OK != ssl_parse_encrypt_then_mac_ext(c, ext + 4, ext_size)){
					goto func_error;
				}
				break;
			case JHD_TLS_TLS_EXT_EXTENDED_MASTER_SECRET:
				log_info("found extended master secret extension" );
				if(JHD_OK != ssl_parse_extended_ms_ext(c, ext + 4, ext_size)){
					goto func_error;
				}
				break;
			case JHD_TLS_TLS_EXT_ALPN:
				log_info("found alpn extension");
				if(JHD_OK != ssl_parse_alpn_ext(c, ext + 4, ext_size)){
					goto func_error;
				}
				break;

			default:
				log_debug("unknown extension found: %d (ignoring)", ext_id );
		}
		ext_len -= 4 + ext_size;
		ext += 4 + ext_size;
		if (ext_len > 0 && ext_len < 4) {
			log_err( "invalid extension length(remain):%u",ext_len);
			jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL,JHD_TLS_SSL_ALERT_MSG_DECODE_ERROR);
			goto func_error;
		}
	}

	/*
	 * Try to fall back to default hash SHA1 if the client
	 * hasn't provided any preferred signature-hash combinations.
	 */
	if (sig_hash_alg_ext_present == 0) {
		jhd_tls_ssl_sig_hash_set_const_hash(&ssl->handshake->hash_algs, &jhd_tls_sha1_info);
	}

	got_common_suite = 0;

#ifdef JHD_LOG_LEVEL_INFO
	for (j = 0, p = buf + ciph_offset + 2; j < ciph_len; j += 2, p += 2) {
		ciphersuite_info = supported_ciphersuites;
		while (ciphersuite_info->id != 0) {
			if ((p[0] == (((ciphersuite_info->id) >> 8) & 0xFF)) && (p[1] == ((ciphersuite_info->id) & 0xFF))) {
				break;
			}
			ciphersuite_info++;
		}
		if(ciphersuite_info->id != 0){
			log_info("server support ciphersuite(%s) in client supported list",ciphersuite_info->name);
		}else{
			log_info("server unsupport ciphersuite[%02X,%02X] in client supported list",p[0],p[1]);
		}
	}
#endif

//	ciphersuite_info = supported_ciphersuites;
//	while (ciphersuite_info->id != 0) {
//		for (j = 0, p = buf + ciph_offset + 2; j < ciph_len; j += 2, p += 2) {
//			if (p[0] != (((ciphersuite_info->id) >> 8) & 0xFF) || p[1] != ((ciphersuite_info->id) & 0xFF)) {
//				continue;
//			}
//			got_common_suite = 1;
//			if (ssl_ciphersuite_match(ssl, ciphersuite_info)) {
//				goto have_ciphersuite;
//			}
//		}
//		ciphersuite_info++;
//	}
	for (j = 0, p = buf + ciph_offset + 2; j < ciph_len; j += 2, p += 2) {
		ciphersuite_info = supported_ciphersuites;
		while (ciphersuite_info->id != 0) {
			if (p[0] != (((ciphersuite_info->id) >> 8) & 0xFF) || p[1] != ((ciphersuite_info->id) & 0xFF)) {
				ciphersuite_info++;
				continue;
			}
			got_common_suite = 1;
			if (ssl_ciphersuite_match(ssl, ciphersuite_info)) {
				goto have_ciphersuite;
			}

		}

	}
	if (got_common_suite) {
		log_err("got ciphersuites in common, " "but none of them usable" );
		jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL,JHD_TLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE);
		goto func_error;
	} else {
		log_debug("got no ciphersuites in common" );
		jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL,JHD_TLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE);
		goto func_error;
	}
	have_ciphersuite:
	log_debug("selected ciphersuite: %s", ciphersuite_info->name );
	ssl->handshake->ciphersuite_info = ciphersuite_info;
	ssl->handshake->update_checksum(ssl, ssl->in_msg, ssl->in_msglen);
	ssl->in_msglen = 0;
	ssl->state++;
	ret = JHD_OK;
func_return:
	log_notice("<= parse client hello(%s)",JHD_RETURN_STR(ret));
	return ret;
func_error:
	c->recv = jhd_connection_error_recv;
	log_notice("<= parse client hello(JHD_ERROR)" );
	return JHD_ERROR;

}

static void ssl_write_truncated_hmac_ext(jhd_tls_ssl_context *ssl, unsigned char *buf, size_t *olen) {
	unsigned char *p = buf;
	if (ssl->handshake->trunc_hmac == JHD_TLS_SSL_TRUNC_HMAC_DISABLED) {
		*olen = 0;
		return;
	}
	*p++ = (unsigned char) (( JHD_TLS_TLS_EXT_TRUNCATED_HMAC >> 8) & 0xFF);
	*p++ = (unsigned char) (( JHD_TLS_TLS_EXT_TRUNCATED_HMAC) & 0xFF);
	*p++ = 0x00;
	*p++ = 0x00;
	*olen = 4;
	log_info("server write_truncated_hmac_ext:%s","JHD_TLS_SSL_TRUNC_HMAC_ENABLED");
	log_buf_debug("server write_truncated_hmac_ext==>",buf,*olen);
}

static void ssl_write_encrypt_then_mac_ext(jhd_tls_ssl_context *ssl, unsigned char *buf, size_t *olen) {
	unsigned char *p = buf;
	const jhd_tls_cipher_info_t *cipher = NULL;
	if (ssl->handshake->encrypt_then_mac == JHD_TLS_SSL_ETM_DISABLED) {
		*olen = 0;
		return;
	}
	/*
	 * RFC 7366: "If a server receives an encrypt-then-MAC request extension
	 * from a client and then selects a stream or Authenticated Encryption
	 * with Associated Data (AEAD) ciphersuite, it MUST NOT send an
	 * encrypt-then-MAC response extension back to the client."
	 */


	cipher = jhd_tls_cipher_info_from_type(ssl->handshake->ciphersuite_info->cipher);

	if (cipher->mode != JHD_TLS_MODE_CBC) {
		*olen = 0;
		return;
	}
	*p++ = (unsigned char) (( JHD_TLS_TLS_EXT_ENCRYPT_THEN_MAC >> 8) & 0xFF);
	*p++ = (unsigned char) (( JHD_TLS_TLS_EXT_ENCRYPT_THEN_MAC) & 0xFF);

	*p++ = 0x00;
	*p++ = 0x00;

	*olen = 4;
	log_info("server write_encrypt_then_mac_ext:JHD_TLS_SSL_ETM_ENABLED");
	log_buf_debug("server write_encrypt_then_mac_ext==>",buf,*olen);
}

static void ssl_write_extended_ms_ext(jhd_tls_ssl_context *ssl, unsigned char *buf, size_t *olen) {
	unsigned char *p = buf;
	*p++ = (unsigned char) (( JHD_TLS_TLS_EXT_EXTENDED_MASTER_SECRET >> 8) & 0xFF);
	*p++ = (unsigned char) (( JHD_TLS_TLS_EXT_EXTENDED_MASTER_SECRET) & 0xFF);
	*p++ = 0x00;
	*p++ = 0x00;
	*olen = 4;
	log_info("server write_extended_ms_ext");
	log_buf_debug("server write_extended_ms_ext==>",buf,*olen);
}

static void ssl_write_renegotiation_ext(jhd_tls_ssl_context *ssl, unsigned char *buf, size_t *olen) {
	unsigned char *p = buf;
	*p++ = (unsigned char) (( JHD_TLS_TLS_EXT_RENEGOTIATION_INFO >> 8) & 0xFF);
	*p++ = (unsigned char) (( JHD_TLS_TLS_EXT_RENEGOTIATION_INFO) & 0xFF);
	*p++ = 0x00;
	*p++ = 0x01;
	*p++ = 0x00;
	*olen = 5;
	log_info("server write_renegotiation_ext");
	log_buf_debug("server write_renegotiation_ext==>",buf,5);
}

static void ssl_write_max_fragment_length_ext(jhd_tls_ssl_context *ssl, unsigned char *buf, size_t *olen) {
	unsigned char *p = buf;
	if (ssl->handshake->mfl_code == JHD_TLS_SSL_MAX_FRAG_LEN_NONE) {
		*olen = 0;
		return;
	}
	*p++ = (unsigned char) (( JHD_TLS_TLS_EXT_MAX_FRAGMENT_LENGTH >> 8) & 0xFF);
	*p++ = (unsigned char) (( JHD_TLS_TLS_EXT_MAX_FRAGMENT_LENGTH) & 0xFF);
	*p++ = 0x00;
	*p++ = 1;
	*p++ = ssl->handshake->mfl_code;
	*olen = 5;
	log_info("server  write_max_fragment_length_ext:%s",ssl_get_max_fragment_length_descp(ssl->handshake->mfl_code));
	log_buf_debug("server  write_max_fragment_length_ext==>",buf,5);
}

static void ssl_write_supported_point_formats_ext(jhd_tls_ssl_context *ssl, unsigned char *buf, size_t *olen) {
	unsigned char *p = buf;
	((void) ssl);
	if ((ssl->handshake->cli_exts & JHD_TLS_TLS_EXT_SUPPORTED_POINT_FORMATS_PRESENT) == 0) {
		*olen = 0;
		return;
	}
	*p++ = (unsigned char) (( JHD_TLS_TLS_EXT_SUPPORTED_POINT_FORMATS >> 8) & 0xFF);
	*p++ = (unsigned char) (( JHD_TLS_TLS_EXT_SUPPORTED_POINT_FORMATS) & 0xFF);

	*p++ = 0x00;
	*p++ = 2;

	*p++ = 1;
	*p++ = JHD_TLS_ECP_PF_UNCOMPRESSED;

	*olen = 6;
	log_info("server  write_supported_point_formats_ext:%s","JHD_TLS_ECP_PF_UNCOMPRESSED");
	log_buf_debug("server  write_supported_point_formats_ext==>",buf,6);
}

static void ssl_write_alpn_ext(jhd_tls_ssl_context *ssl, unsigned char *buf, size_t *olen) {
	if (ssl->alpn_chosen == NULL) {
		*olen = 0;
		return;
	}
	/*
	 * 0 . 1    ext identifier
	 * 2 . 3    ext length
	 * 4 . 5    protocol list length
	 * 6 . 6    protocol name length
	 * 7 . 7+n  protocol name
	 */
	buf[0] = (unsigned char) (( JHD_TLS_TLS_EXT_ALPN >> 8) & 0xFF);
	buf[1] = (unsigned char) (( JHD_TLS_TLS_EXT_ALPN) & 0xFF);

	*olen = 7 + strlen(ssl->alpn_chosen);

	buf[2] = (unsigned char) (((*olen - 4) >> 8) & 0xFF);
	buf[3] = (unsigned char) (((*olen - 4)) & 0xFF);

	buf[4] = (unsigned char) (((*olen - 6) >> 8) & 0xFF);
	buf[5] = (unsigned char) (((*olen - 6)) & 0xFF);

	buf[6] = (unsigned char) (((*olen - 7)) & 0xFF);

	memcpy(buf + 7, ssl->alpn_chosen, *olen - 7);
	log_buf_debug("server  write_alpn_ext==>",buf,*olen);
}

static int ssl_write_server_hello(jhd_connection_t *c) {
	int ret;
	size_t olen, ext_len = 0;
	unsigned char *buf, *p;
	jhd_tls_ssl_context *ssl=c->ssl;
	log_notice("=> write server hello" );
	if(ssl->out_msglen){
		ret = jhd_tls_ssl_flush_output(c);
		if(ret==JHD_OK){
			++ssl->state;
		}
	}else{
		/*
		 *     0  .   0   handshake type
		 *     1  .   3   handshake length
		 *     4  .   5   protocol version
		 *     6  .   9   UNIX time()
		 *    10  .  37   random bytes
		 */
		buf = ssl->out_msg;
		p = buf + 4;
		*(p++) = ssl->major_ver;
		*(p++) = ssl->minor_ver;
		jhd_tls_random32_with_time(p);
		log_buf_debug("server random bytes==>",p,32);
//		memcpy(ssl->handshake->randbytes + 32, p, 32);
		memcpy_32(ssl->handshake->randbytes + 32, p);
		p += 32;
		/*
		 *    38  .  38     session id length
		 *    39  . 38+n    session id
		 *   39+n . 40+n    chosen ciphersuite
		 *   41+n . 41+n    chosen compression alg.
		 *   42+n . 43+n    extensions length
		 *   44+n . 43+n+m  extensions
		 */

		//TODO: session id len == 0??????????;
//		*p++ = (unsigned char) (32);/* ssl->session_negotiate->id_len;*/
//		jhd_tls_random(p, 32);
//		p += 32;

		*p++ = 0;
		*p++ = (unsigned char) (ssl->handshake->ciphersuite_info->id >> 8);
		*p++ = (unsigned char) (ssl->handshake->ciphersuite_info->id);
		log_debug("server choosed ciphersuite[%02X,%02X],name:%s",(unsigned char) (ssl->handshake->ciphersuite_info->id >> 8),(unsigned char) (ssl->handshake->ciphersuite_info->id),ssl->handshake->ciphersuite_info->name);
		*p++ = (unsigned char) (JHD_TLS_SSL_COMPRESS_NULL);
		log_debug("server compres==>JHD_TLS_SSL_COMPRESS_NULL[%02X]", (unsigned char) (JHD_TLS_SSL_COMPRESS_NULL));
		/*
		 *  First write extensions, then the total length
		 */
		ssl_write_renegotiation_ext(ssl, p + 2 + ext_len, &olen);
		ext_len += olen;

		ssl_write_max_fragment_length_ext(ssl, p + 2 + ext_len, &olen);
		ext_len += olen;

		ssl_write_truncated_hmac_ext(ssl, p + 2 + ext_len, &olen);
		ext_len += olen;
		ssl_write_encrypt_then_mac_ext(ssl, p + 2 + ext_len, &olen);
		ext_len += olen;

		ssl_write_extended_ms_ext(ssl, p + 2 + ext_len, &olen);
		ext_len += olen;

		ssl_write_supported_point_formats_ext(ssl, p + 2 + ext_len, &olen);
		ext_len += olen;

		ssl_write_alpn_ext(ssl, p + 2 + ext_len, &olen);
		ext_len += olen;
		if (ext_len > 0) {
			*p++ = (unsigned char) ((ext_len >> 8) & 0xFF);
			*p++ = (unsigned char) ((ext_len) & 0xFF);
			p += ext_len;
		}

		ret = p - buf;
		ssl->out_offt = ssl->out_hdr;
		ssl->out_msglen = ret+5;
		JHD_TLS_SSL_SET_SSL_RECORD(ssl,JHD_TLS_SSL_MSG_HANDSHAKE,ret)
		ret -=4;
		JHD_TLS_SSL_SET_HANDSHAKE(ssl,JHD_TLS_SSL_HS_SERVER_HELLO,ret)
		log_buf_debug("write ssl record====>",ssl->out_hdr,ssl->out_msglen);
		ret = jhd_tls_ssl_flush_output(c);
		if(ret == JHD_OK){
			++ssl->state;
		}
	}
	return ret;
}

static int ssl_write_certificate_request(jhd_connection_t *c) {
	((jhd_tls_ssl_context*)(c->ssl))->state++;
	return JHD_OK;
//	int ret = JHD_TLS_ERR_SSL_FEATURE_UNAVAILABLE;
//	size_t dn_size, total_dn_size; /* excluding length bytes */
//	size_t ct_len, sa_len; /* including length bytes */
//	unsigned char *buf, *p;
//	const unsigned char * const end = ssl->out_msg + JHD_TLS_SSL_MAX_CONTENT_LEN;
//	const jhd_tls_x509_crt *crt;
//	int authmode;
//
//	JHD_TLS_SSL_DEBUG_MSG(2, ( "=> write certificate request" ));
//
//	ssl->state++;
//
//	if (ssl->handshake->sni_authmode != JHD_TLS_SSL_VERIFY_UNSET)
//		authmode = ssl->handshake->sni_authmode;
//	else
//		authmode = ssl->conf->authmode;
//
//	if (authmode == JHD_TLS_SSL_VERIFY_NONE) {
//		JHD_TLS_SSL_DEBUG_MSG(2, ( "<= skip write certificate request" ));
//		return (0);
//	}
//
//	/*
//	 *     0  .   0   handshake type
//	 *     1  .   3   handshake length
//	 *     4  .   4   cert type count
//	 *     5  .. m-1  cert types
//	 *     m  .. m+1  sig alg length (TLS 1.2 only)
//	 *    m+1 .. n-1  SignatureAndHashAlgorithms (TLS 1.2 only)
//	 *     n  .. n+1  length of all DNs
//	 *    n+2 .. n+3  length of DN 1
//	 *    n+4 .. ...  Distinguished Name #1
//	 *    ... .. ...  length of DN 2, etc.
//	 */
//	buf = ssl->out_msg;
//	p = buf + 4;
//
//	/*
//	 * Supported certificate types
//	 *
//	 *     ClientCertificateType certificate_types<1..2^8-1>;
//	 *     enum { (255) } ClientCertificateType;
//	 */
//	ct_len = 0;
//
//	p[1 + ct_len++] = JHD_TLS_SSL_CERT_TYPE_RSA_SIGN;
//	p[1 + ct_len++] = JHD_TLS_SSL_CERT_TYPE_ECDSA_SIGN;
//
//	p[0] = (unsigned char) ct_len++;
//	p += ct_len;
//
//	sa_len = 0;
//
//	/*
//	 * Add signature_algorithms for verify (TLS 1.2)
//	 *
//	 *     SignatureAndHashAlgorithm supported_signature_algorithms<2..2^16-2>;
//	 *
//	 *     struct {
//	 *           HashAlgorithm hash;
//	 *           SignatureAlgorithm signature;
//	 *     } SignatureAndHashAlgorithm;
//	 *
//	 *     enum { (255) } HashAlgorithm;
//	 *     enum { (255) } SignatureAlgorithm;
//	 */
//	if (ssl->minor_ver == JHD_TLS_SSL_MINOR_VERSION_3) {
//		const int *cur;
//
//		/*
//		 * Supported signature algorithms
//		 */
//		for (cur = jhd_tls_ssl_preset_default_hashes; *cur != JHD_TLS_MD_NONE; cur++) {
//			unsigned char hash = jhd_tls_ssl_hash_from_md_alg(*cur);
//
//			if ( JHD_TLS_SSL_HASH_NONE == hash || jhd_tls_ssl_set_calc_verify_md(ssl, hash))
//				continue;
//
//			p[2 + sa_len++] = hash;
//			p[2 + sa_len++] = JHD_TLS_SSL_SIG_RSA;
//
//			p[2 + sa_len++] = hash;
//			p[2 + sa_len++] = JHD_TLS_SSL_SIG_ECDSA;
//
//		}
//
//		p[0] = (unsigned char) (sa_len >> 8);
//		p[1] = (unsigned char) (sa_len);
//		sa_len += 2;
//		p += sa_len;
//	}
//
//	/*
//	 * DistinguishedName certificate_authorities<0..2^16-1>;
//	 * opaque DistinguishedName<1..2^16-1>;
//	 */
//	p += 2;
//
//	total_dn_size = 0;
//
//	if (ssl->conf->cert_req_ca_list == JHD_TLS_SSL_CERT_REQ_CA_LIST_ENABLED) {
//
//		if (ssl->handshake->sni_ca_chain != NULL)
//			crt = ssl->handshake->sni_ca_chain;
//		else
//			crt = ssl->conf->ca_chain;
//
//		while (crt != NULL && crt->version != 0) {
//			dn_size = crt->subject_raw.len;
//
//			if (end < p || (size_t) (end - p) < dn_size || (size_t) (end - p) < 2 + dn_size) {
//				JHD_TLS_SSL_DEBUG_MSG(1, ( "skipping CAs: buffer too short" ));
//				break;
//			}
//
//			*p++ = (unsigned char) (dn_size >> 8);
//			*p++ = (unsigned char) (dn_size);
//			memcpy(p, crt->subject_raw.p, dn_size);
//			p += dn_size;
//
//			JHD_TLS_SSL_DEBUG_BUF(3, "requested DN", p - dn_size, dn_size);
//
//			total_dn_size += 2 + dn_size;
//			crt = crt->next;
//		}
//	}
//
//	ssl->out_msglen = p - buf;
//	ssl->out_msgtype = JHD_TLS_SSL_MSG_HANDSHAKE;
//	ssl->out_msg[0] = JHD_TLS_SSL_HS_CERTIFICATE_REQUEST;
//	ssl->out_msg[4 + ct_len + sa_len] = (unsigned char) (total_dn_size >> 8);
//	ssl->out_msg[5 + ct_len + sa_len] = (unsigned char) (total_dn_size);
//
//	ret = jhd_tls_ssl_write_record(ssl);
//
//	JHD_TLS_SSL_DEBUG_MSG(2, ( "<= write certificate request" ));
//
//	return (ret);
}

/* Prepare the ServerKeyExchange message, up to and including
 * calculating the signature if any, but excluding formatting the
 * signature and sending the message. */
static int ssl_prepare_server_key_exchange(jhd_connection_t *c, size_t *signature_len,int * const out_len) {
	jhd_tls_ssl_context *ssl =c->ssl;
	int ret;
	const jhd_tls_ssl_ciphersuite_t *ciphersuite_info = ssl->handshake->ciphersuite_info;
	unsigned char *dig_signed = NULL;
	unsigned char hash[JHD_TLS_MD_MAX_SIZE];
	jhd_tls_ecp_curve_info *curve = NULL;
	size_t dig_signed_len;
	size_t hashlen = 0;

	log_notice("==>ssl_prepare_server_key_exchange");

	/*
	 * - ECDHE key exchanges
	 */
	for (curve = (jhd_tls_ecp_curve_info *) jhd_tls_ecp_curve_list(); curve->grp_id != JHD_TLS_ECP_DP_NONE; ++curve) {
		if (ssl->handshake->curves_flag & (1 << ((int) curve->grp_id))) {
			goto curve_matching_done;
		}

	}
	curve = NULL;
curve_matching_done:
	if (curve == NULL) {
		log_err("no matching curve for ECDHE");
		return JHD_ERROR;
	}
	if (NULL == (ssl->handshake->ecdh_ctx.grp=jhd_tls_ecp_group_get(curve->grp_id))) {
		log_err("execute jhd_tls_ecp_group_get(%d)==NULL",(int)curve->grp_id);
		return JHD_ERROR;
	}
	dig_signed = ssl->out_msg + 4;
	if ((ret = jhd_tls_ecdh_make_params(&ssl->handshake->ecdh_ctx,&dig_signed_len, dig_signed, JHD_TLS_SSL_MAX_CONTENT_LEN -4,&c->write)) != 0) {
		/*JHD_ERROR   or    JHD_AGAIN*/
		return ret;
	}
	log_buf_debug("ecdh_params==>",dig_signed,dig_signed_len);
	*out_len =4 + dig_signed_len;
	/*
	 * 2.1: Choose hash algorithm:
	 * A: For TLS 1.2, obey signature-hash-algorithm extension
	 *    to choose appropriate hash.
	 * B: For SSL3, TLS1.0, TLS1.1 and ECDHE_ECDSA, use SHA1
	 *    (RFC 4492, Sec. 5.4)
	 * C: Otherwise, use MD5 + SHA1 (RFC 4346, Sec. 7.4.3)
	 */

	const jhd_tls_md_info_t *md_info;
	if (ssl->minor_ver == JHD_TLS_SSL_MINOR_VERSION_3) {
		md_info = jhd_tls_ssl_sig_hash_set_find(&ssl->handshake->hash_algs,jhd_tls_ssl_get_ciphersuite_sig_pk_alg(ciphersuite_info));
		log_assert(md_info!=NULL);
	} else if (ciphersuite_info->key_exchange == JHD_TLS_KEY_EXCHANGE_ECDHE_ECDSA) {
		/* B: Default hash SHA1 */
		md_info = &jhd_tls_sha1_info;
	} else {
		/* C: MD5 + SHA1 */
		md_info = NULL;
	}

	/*
	 * 2.2: Compute the hash to be signed
	 */
	/** begin with TLS1 TLS1_1 TLS1_2**/
	if (md_info) {
		jhd_tls_ssl_get_key_exchange_md_tls1_2(hash, &hashlen,ssl->handshake->randbytes,dig_signed, dig_signed_len, md_info);
	} else
	/** end with TLS1 TLS1_1 TLS1_2**/
	{
		hashlen = 36;
		jhd_tls_ssl_get_key_exchange_md_ssl_tls(hash,ssl->handshake->randbytes,dig_signed, dig_signed_len);
	};
	/*
	 * 2.3: Compute and add the signature
	 */
	/**begin with TLS1_2*/
	if (ssl->minor_ver == JHD_TLS_SSL_MINOR_VERSION_3) {
		/*
		 * For TLS 1.2, we need to specify signature and hash algorithm
		 * explicitly through a prefix to the signature.
		 *
		 * struct {
		 *    HashAlgorithm hash;
		 *    SignatureAlgorithm signature;
		 * } SignatureAndHashAlgorithm;
		 *
		 * struct {
		 *    SignatureAndHashAlgorithm algorithm;
		 *    opaque signature<0..2^16-1>;
		 * } DigitallySigned;
		 *
		 */
		ssl->out_msg[(*out_len)++] = md_info->hash_flag;   // jhd_tls_ssl_hash_from_md_info(md_info);
		ssl->out_msg[(*out_len)++] = ciphersuite_info->pk_info->pk_flag;//   jhd_tls_ssl_sig_from_pk_alg(jhd_tls_ssl_get_ciphersuite_sig_pk_alg(ciphersuite_info));
		log_info("only(TLS1.2)  md_info->hash_flsg(%02X)   ciphersuite_info->pk_info->hash_flag(%02X)",md_info->hash_flag,ciphersuite_info->pk_info->pk_flag);
	}
	/*end with TLS1_2*/

	/* Append the signature to ssl->out_msg, leaving 2 bytes for the
	 * signature length which will be added in ssl_write_server_key_exchange
	 * after the call to ssl_prepare_server_key_exchange.
	 * ssl_write_server_key_exchange also takes care of incrementing
	 * ssl->out_msglen. */
	if ((ret = jhd_tls_pk_sign(ssl->handshake->key_cert->key, md_info, hash, hashlen, ssl->out_msg + (*out_len) + 2, signature_len)) != 0) {
		log_err("execute jhd_tls_pk_sign()==%d", ret);
		return JHD_ERROR;
	}
	log_buf_debug("sign==>", ssl->out_msg + (*out_len) + 2,*signature_len);

//	}

	return JHD_OK;
}

/* Prepare the ServerKeyExchange message and send it. For ciphersuites
 * that do not include a ServerKeyExchange message, do nothing. Either
 * way, if successful, move on to the next step in the SSL state
 * machine. */
static int ssl_write_server_key_exchange(jhd_connection_t *c) {
	int ret,len;
	size_t signature_len = 0;
	jhd_tls_ssl_context *ssl = c->ssl;
	const jhd_tls_ssl_ciphersuite_t *ciphersuite_info = ssl->handshake->ciphersuite_info;
	log_notice("=> write server key exchange");
	if(ssl->out_msglen){
		ret = jhd_tls_ssl_flush_output(c);
		if(ret==JHD_OK){
			++ssl->state;
		}
	}else{
		//RSA
		if (ciphersuite_info->key_exchange == JHD_TLS_KEY_EXCHANGE_RSA) {
			ssl->state++;
			ret = JHD_OK;
		}else{
			//ECDHE_RSA  ECHDE_ECDSA
			/* ServerKeyExchange is needed. Prepare the message. */
			ret = ssl_prepare_server_key_exchange(c, &signature_len,&len);
			if(ret ==JHD_OK){
				/* If there is a signature, write its length.
				 * ssl_prepare_server_key_exchange already wrote the signature
				 * itself at its proper place in the output buffer. */
				if (signature_len != 0) {
					ssl->out_msg[len++] = (unsigned char) (signature_len >> 8);
					ssl->out_msg[len++] = (unsigned char) (signature_len);
					/* Skip over the already-written signature */
					len += signature_len;
				}
				ssl->out_offt = ssl->out_hdr;
				ssl->out_msglen = len + 5;
				JHD_TLS_SSL_SET_SSL_RECORD(ssl,JHD_TLS_SSL_MSG_HANDSHAKE,len)
				len -= 4;
				JHD_TLS_SSL_SET_HANDSHAKE(ssl,JHD_TLS_SSL_HS_SERVER_KEY_EXCHANGE,len)
				log_buf_debug("write ssl record====>",ssl->out_hdr,ssl->out_msglen);
				ret = jhd_tls_ssl_flush_output(c);
				if(ret == JHD_OK){
					++ssl->state;
				}
			}else if(JHD_ERROR == ret){
				c->send = jhd_connection_error_send;
			}/*else{
				ret  == JHD_AGAIN;
			}*/
		}
	}
	log_notice("<= write server key exchange(%s)",JHD_RETURN_STR(ret));
	return ret;
}

static int ssl_write_server_hello_done(jhd_connection_t *c) {
	int ret;
	jhd_tls_ssl_context *ssl = c->ssl;
	log_notice("=> write server hello done");
	if(ssl->out_msglen){
			ret = jhd_tls_ssl_flush_output(c);
			if(ret==JHD_OK){
				++ssl->state;
			}
	}else{
		ssl->out_offt = ssl->out_hdr;
		ssl->out_msglen = 9;
		JHD_TLS_SSL_SET_SSL_RECORD(ssl,JHD_TLS_SSL_MSG_HANDSHAKE,4)
		JHD_TLS_SSL_SET_HANDSHAKE(ssl,JHD_TLS_SSL_HS_SERVER_HELLO_DONE,0)
		log_buf_debug("write ssl record====>",ssl->out_hdr,ssl->out_msglen);
		ret = jhd_tls_ssl_flush_output(c);
		if(ret == JHD_OK){
			++ssl->state;
		}
	}
	log_notice("<= write server hello done(%s)",JHD_RETURN_STR(ret));
	return ret;
}

static int ssl_decrypt_encrypted_pms(jhd_tls_ssl_context *ssl, const unsigned char *p, const unsigned char *end, unsigned char *peer_pms, size_t *peer_pmslen,
        size_t peer_pmssize) {
	int ret;
	jhd_tls_pk_context *private_key = jhd_tls_ssl_own_key(ssl);
	jhd_tls_pk_context *public_key = &jhd_tls_ssl_own_cert(ssl)->pk;
	size_t len = jhd_tls_pk_get_len(public_key);

	/*
	 * Prepare to decrypt the premaster using own private RSA key
	 */

	if (*p++ != ((len >> 8) & 0xFF) || *p++ != ((len) & 0xFF)) {
		log_err("bad client key exchange message");
		return JHD_ERROR;
	}


	if (p + len != end) {
		log_err("bad client key exchange message");
		return JHD_ERROR;
	}

	if (!jhd_tls_pk_can_do(private_key, &jhd_tls_rsa_info)) {
		log_err("got no RSA private key");
		return JHD_ERROR;
	}

	ret = jhd_tls_pk_decrypt(private_key, p, len, peer_pms, peer_pmslen, peer_pmssize);
	return (ret);
}

static int ssl_parse_encrypted_pms(jhd_tls_ssl_context *ssl, const unsigned char *p, const unsigned char *end) {
	int ret;
	unsigned char *pms = ssl->handshake->premaster;
	unsigned char ver[2];
	unsigned char fake_pms[48], peer_pms[48];
	unsigned char mask;
	size_t i, peer_pmslen;
	unsigned int diff;

	/* In case of a failure in decryption, the decryption may write less than
	 * 2 bytes of output, but we always read the first two bytes. It doesn't
	 * matter in the end because diff will be nonzero in that case due to
	 * peer_pmslen being less than 48, and we only care whether diff is 0.
	 * But do initialize peer_pms for robustness anyway. This also makes
	 * memory analyzers happy (don't access uninitialized memory, even
	 * if it's an unsigned char). */
	peer_pms[0] = peer_pms[1] = ~0;

	ret = ssl_decrypt_encrypted_pms(ssl, p, end, peer_pms, &peer_pmslen, sizeof(peer_pms));

	ver[0] = ssl->handshake->max_major_ver;
	ver[1] = ssl->handshake->max_minor_ver;
	/* Avoid data-dependent branches while checking for invalid
	 * padding, to protect against timing-based Bleichenbacher-type
	 * attacks. */
	diff = (unsigned int) ret;
	diff |= peer_pmslen ^ 48;
	diff |= peer_pms[0] ^ ver[0];
	diff |= peer_pms[1] ^ ver[1];
	mask = -((diff | -diff) >> (sizeof(unsigned int) * 8 - 1));


	/*
	 * Protection against Bleichenbacher's attack: invalid PKCS#1 v1.5 padding
	 * must not cause the connection to end immediately; instead, send a
	 * bad_record_mac later in the handshake.
	 * To protect against timing-based variants of the attack, we must
	 * not have any branch that depends on whether the decryption was
	 * successful. In particular, always generate the fake premaster secret,
	 * regardless of whether it will ultimately influence the output or not.
	 */

	jhd_tls_random(fake_pms, sizeof(fake_pms));
	ssl->handshake->pmslen = 48;

	/* Set pms to either the true or the fake PMS, without
	 * data-dependent branches. */
	for (i = 0; i < ssl->handshake->pmslen; i++)
		pms[i] = (mask & fake_pms[i]) | ((~mask) & peer_pms[i]);

	return (0);
}

static int ssl_parse_client_key_exchange(jhd_connection_t *c) {
	int ret;
	const jhd_tls_ssl_ciphersuite_t *ciphersuite_info;
	unsigned char *p, *end;
	uint16_t msg_len,hmac_size;
	jhd_tls_ecp_point public_key;
	const jhd_tls_cipher_info_t *cipher_info;
	const jhd_tls_md_info_t *md_info;
	jhd_tls_ssl_context *ssl = c->ssl;
	ciphersuite_info = ssl->handshake->ciphersuite_info;

 	log_notice("=> parse client key exchange");
	jhd_tls_ecp_point_init(&public_key);
	if(ssl->in_msglen== 0){
		JHD_TLS_SSL_READ_SSL_RECORD_CONTENT
		ssl->in_offt = ssl->in_msg;
	}
	cipher_info = jhd_tls_cipher_info_from_type(ciphersuite_info->cipher);
#ifdef JHD_LOG_LEVEL_NOTICE
	ssl->ciphersuite_info = ciphersuite_info;
#endif

	md_info = ciphersuite_info->md_info;
	if ((cipher_info->mode == JHD_TLS_MODE_CBC)){
		ssl->md_info = md_info;
		hmac_size = md_info->block_size << 1;
		log_assert(md_info->block_size *2 ==hmac_size);
		if(ssl->dec_hmac == NULL){
			ssl->dec_hmac = jhd_tls_alloc(hmac_size);
			if(ssl->dec_hmac == NULL){
				jhd_tls_wait_mem(&c->write,hmac_size)
				ret = JHD_AGAIN;
				goto func_return;
			}
		}
		if(ssl->enc_hmac == NULL){
			ssl->enc_hmac = jhd_tls_alloc(hmac_size);
			if(ssl->enc_hmac == NULL){
				jhd_tls_wait_mem(&c->write,hmac_size)
				ret = JHD_AGAIN;
				goto func_return;
			}
		}
	}

/*	if (cipher_info->mode == JHD_TLS_MODE_CBC){
		if(ssl->md_ctx_dec.md_ctx == NULL){
			ssl->md_ctx_dec.md_ctx = jhd_tls_alloc(md_info->ctx_size);
			if(ssl->md_ctx_dec.md_ctx == NULL){
                jhd_tls_wait_mem(event,md_info->ctx_size);
                log_debug("alloc md_ctx_dec.md_ctx error;md_info(%s) md_info->ctx_size(%ld)",md_info->name,md_info->ctx_size);
				ret = JHD_AGAIN;
				goto func_return;
			}
			jhd_tls_platform_zeroize(ssl->md_ctx_dec.md_ctx,md_info->ctx_size);
			ssl->md_ctx_dec.md_info = md_info;
		}
		if(ssl->md_ctx_dec.hmac_ctx == NULL){
			ssl->md_ctx_dec.hmac_ctx = jhd_tls_alloc(md_info->block_size * 2);
			if(ssl->md_ctx_dec.hmac_ctx == NULL){
				jhd_tls_wait_mem(event,md_info->block_size * 2);
				log_debug("alloc md_ctx_dec.hmac_ctx error;md_info(%s) md_info->block_size(%ld)",md_info->name,md_info->block_size);
				ret = JHD_AGAIN;
				goto func_return;
			}
		}
		if(ssl->md_ctx_enc.md_ctx == NULL){
			ssl->md_ctx_enc.md_ctx = jhd_tls_alloc(md_info->ctx_size);
			if(ssl->md_ctx_enc.md_ctx == NULL){
				jhd_tls_wait_mem(event,md_info->ctx_size);
				log_debug("alloc md_ctx_enc.md_ctx error;md_info(%s) md_info->ctx_size(%ld)",md_info->name,md_info->ctx_size);
				ret = JHD_AGAIN;
				goto func_return;
			}
			jhd_tls_platform_zeroize(ssl->md_ctx_enc.md_ctx,md_info->ctx_size);
			ssl->md_ctx_enc.md_info = md_info;
		}
		if(ssl->md_ctx_enc.hmac_ctx == NULL){
			ssl->md_ctx_enc.hmac_ctx = jhd_tls_alloc(md_info->block_size * 2);
			if(ssl->md_ctx_enc.hmac_ctx == NULL){
				jhd_tls_wait_mem(event,md_info->block_size * 2);
				log_debug("alloc md_ctx_enc.hmac_ctx error;md_info(%s) md_info->block_size(%ld)",md_info->name,md_info->block_size);
				ret = JHD_AGAIN;
				goto func_return;
			}
		}
	}*/

	ssl->cipher_info = cipher_info;
	if(ssl->dec_ctx == NULL){
		ssl->dec_ctx = jhd_tls_alloc(cipher_info->base->ctx_size);
		if(ssl->dec_ctx == NULL){
			jhd_tls_wait_mem(&c->read,cipher_info->base->ctx_size);
			ret = JHD_AGAIN;
			goto func_return;
		}
		cipher_info->base->cipher_ctx_init(ssl->dec_ctx,cipher_info);
	}
	if(ssl->enc_ctx == NULL){
		ssl->enc_ctx = jhd_tls_alloc(cipher_info->base->ctx_size);
		if(ssl->enc_ctx == NULL){
			jhd_tls_wait_mem(&c->read,cipher_info->base->ctx_size);
			ret = JHD_AGAIN;
			goto func_return;
		}
		cipher_info->base->cipher_ctx_init(ssl->enc_ctx,cipher_info);
	}

	p = ssl->in_offt;
	msg_len = ((p[2]<<8)|(p[3]))  +  4;
	if ((msg_len > ssl->in_msglen) || (p[0] != JHD_TLS_SSL_HS_CLIENT_KEY_EXCHANGE) || (p[1]!=0)) {
		log_err("%s", ( "bad client key exchange message" ));
		jhd_tls_ssl_send_alert_message(c, JHD_TLS_SSL_ALERT_LEVEL_FATAL, JHD_TLS_SSL_ALERT_MSG_DECODE_ERROR);
		goto func_error;
	}
	ssl->handshake->update_checksum(ssl,ssl->in_offt,msg_len);
	ssl->in_msglen -=(msg_len);
	ssl->in_offt +=(msg_len);

	end = p + msg_len;
	p +=4;
	if (ciphersuite_info->key_exchange == JHD_TLS_KEY_EXCHANGE_ECDHE_RSA || ciphersuite_info->key_exchange == JHD_TLS_KEY_EXCHANGE_ECDHE_ECDSA) {
		if (JHD_OK != jhd_tls_ecdh_read_public(&ssl->handshake->ecdh_ctx,&public_key, p, end - p)){
			log_err("jhd_tls_ecdh_read_public() == %d", ret);
			goto func_error;
		}
		if (JHD_OK != jhd_tls_ecdh_calc_secret(&ssl->handshake->ecdh_ctx,&public_key, &ssl->handshake->pmslen, ssl->handshake->premaster, JHD_TLS_MPI_MAX_SIZE)) {
			log_err("jhd_tls_ecdh_calc_secret() == %d", ret);
			goto func_error;
		}
	} else/* if (ciphersuite_info->key_exchange == JHD_TLS_KEY_EXCHANGE_RSA)*/ {
		if (JHD_OK != ssl_parse_encrypted_pms(ssl, p, end)){
			log_err( "ssl_parse_parse_encrypted_pms_secret() == %d", ret);
			goto func_error;
		}
	}
	jhd_tls_ssl_derive_keys(ssl);

	ssl->state++;
	ret = JHD_OK;
	func_return:
		jhd_tls_ecp_point_free(&public_key);
		log_notice("<= parse client key exchange(%s)",JHD_RETURN_STR(ret) );
		return ret;
	func_error:
		jhd_tls_ecp_point_free(&public_key);
		c->recv = jhd_connection_error_recv;
		log_notice("<= parse client key exchange(JHD_ERROR)" );
		return JHD_ERROR;
}

static int ssl_parse_certificate_verify(jhd_tls_ssl_context *ssl) {
	ssl->state++;
	return JHD_OK;

//	int ret = JHD_TLS_ERR_SSL_FEATURE_UNAVAILABLE;
//	size_t i, sig_len;
//	unsigned char hash[48];
//	unsigned char *hash_start = hash;
//	size_t hashlen;
//	jhd_tls_pk_type_t pk_alg;
//	jhd_tls_md_type_t md_alg;
//	JHD_TLS_SSL_DEBUG_MSG(2, ( "=> parse certificate verify" ));
//	if (ssl->session_negotiate->peer_cert == NULL) {
//		JHD_TLS_SSL_DEBUG_MSG(2, ( "<= skip parse certificate verify" ));
//		ssl->state++;
//		return (0);
//	}
//
//	/* Read the message without adding it to the checksum */
//	do {
//
//		do
//			ret = jhd_tls_ssl_read_record_layer(ssl);
//		while (ret == JHD_TLS_ERR_SSL_CONTINUE_PROCESSING);
//
//		if (ret != 0) {
//			JHD_TLS_SSL_DEBUG_RET(1, ( "jhd_tls_ssl_read_record_layer" ), ret);
//			return (ret);
//		}
//
//		ret = jhd_tls_ssl_handle_message_type(ssl);
//
//	} while ( JHD_TLS_ERR_SSL_NON_FATAL == ret ||
//	JHD_TLS_ERR_SSL_CONTINUE_PROCESSING == ret);
//
//	if (0 != ret) {
//		JHD_TLS_SSL_DEBUG_RET(1, ( "jhd_tls_ssl_handle_message_type" ), ret);
//		return (ret);
//	}
//
//	ssl->state++;
//
//	/* Process the message contents */
//	if (ssl->in_msgtype != JHD_TLS_SSL_MSG_HANDSHAKE || ssl->in_msg[0] != JHD_TLS_SSL_HS_CERTIFICATE_VERIFY) {
//		JHD_TLS_SSL_DEBUG_MSG(1, ( "bad certificate verify message" ));
//		return ( JHD_TLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY);
//	}
//
//	i = jhd_tls_ssl_hs_hdr_len(ssl);
//
//	/*
//	 *  struct {
//	 *     SignatureAndHashAlgorithm algorithm; -- TLS 1.2 only
//	 *     opaque signature<0..2^16-1>;
//	 *  } DigitallySigned;
//	 */
//	/*TLS1 TLS1_1 TLS1_2*/
//	if (ssl->minor_ver != JHD_TLS_SSL_MINOR_VERSION_3) {
//		md_alg = JHD_TLS_MD_NONE;
//		hashlen = 36;
//
//		/* For ECDSA, use SHA-1, not MD-5 + SHA-1 */
//		if (jhd_tls_pk_can_do(&ssl->session_negotiate->peer_cert->pk, JHD_TLS_PK_ECDSA)) {
//			hash_start += 16;
//			hashlen -= 16;
//			md_alg = JHD_TLS_MD_SHA1;
//		}
//	} else if (ssl->minor_ver == JHD_TLS_SSL_MINOR_VERSION_3/*TLS1_2*/) {
//		if (i + 2 > ssl->in_hslen) {
//			JHD_TLS_SSL_DEBUG_MSG(1, ( "bad certificate verify message" ));
//			return ( JHD_TLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY);
//		}
//
//		/*
//		 * Hash
//		 */
//		md_alg = jhd_tls_ssl_md_alg_from_hash(ssl->in_msg[i]);
//
//		if (md_alg == JHD_TLS_MD_NONE || jhd_tls_ssl_set_calc_verify_md(ssl, ssl->in_msg[i])) {
//			JHD_TLS_SSL_DEBUG_MSG(1, ( "peer not adhering to requested sig_alg" " for verify message" ));
//			return ( JHD_TLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY);
//		}
//
//#if !defined(JHD_TLS_MD_SHA1)
//		if (JHD_TLS_MD_SHA1 == md_alg)
//			hash_start += 16;
//#endif
//
//		/* Info from md_alg will be used instead */
//		hashlen = 0;
//
//		i++;
//
//		/*
//		 * Signature
//		 */
//		if ((pk_alg = jhd_tls_ssl_pk_alg_from_sig(ssl->in_msg[i])) == JHD_TLS_PK_NONE) {
//			JHD_TLS_SSL_DEBUG_MSG(1, ( "peer not adhering to requested sig_alg" " for verify message" ));
//			return ( JHD_TLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY);
//		}
//
//		/*
//		 * Check the certificate's key type matches the signature alg
//		 */
//		if (!jhd_tls_pk_can_do(&ssl->session_negotiate->peer_cert->pk, pk_alg)) {
//			JHD_TLS_SSL_DEBUG_MSG(1, ( "sig_alg doesn't match cert key" ));
//			return ( JHD_TLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY);
//		}
//
//		i++;
//	} else {
//		JHD_TLS_SSL_DEBUG_MSG(1, ( "should never happen" ));
//		return ( JHD_TLS_ERR_SSL_INTERNAL_ERROR);
//	}
//
//	if (i + 2 > ssl->in_hslen) {
//		JHD_TLS_SSL_DEBUG_MSG(1, ( "bad certificate verify message" ));
//		return ( JHD_TLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY);
//	}
//
//	sig_len = (ssl->in_msg[i] << 8) | ssl->in_msg[i + 1];
//	i += 2;
//
//	if (i + sig_len != ssl->in_hslen) {
//		JHD_TLS_SSL_DEBUG_MSG(1, ( "bad certificate verify message" ));
//		return ( JHD_TLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY);
//	}
//
//	/* Calculate hash and verify signature */
//	ssl->handshake->calc_verify(ssl, hash);
//
//	if ((ret = jhd_tls_pk_verify(&ssl->session_negotiate->peer_cert->pk, md_alg, hash_start, hashlen, ssl->in_msg + i, sig_len)) != 0) {
//		JHD_TLS_SSL_DEBUG_RET(1, "jhd_tls_pk_verify", ret);
//		return (ret);
//	}
//
//	jhd_tls_ssl_update_handshake_status(ssl);
//
//	JHD_TLS_SSL_DEBUG_MSG(2, ( "<= parse certificate verify" ));
//
//	return (ret);
}
/*
 * SSL handshake -- server side -- single step
 */
int jhd_tls_ssl_handshake_server_step(jhd_connection_t *c) {
	int ret = JHD_OK;
	jhd_tls_ssl_context *ssl=c->ssl;
	switch (ssl->state) {
		case JHD_TLS_SSL_HELLO_REQUEST:
			ssl->state = JHD_TLS_SSL_CLIENT_HELLO;
			break;
			/*
			 *  <==   ClientHello
			 */
		case JHD_TLS_SSL_CLIENT_HELLO:
			ret = ssl_parse_client_hello(c);
			break;
			/*
			 *  ==>   ServerHello
			 *        Certificate
			 *      ( ServerKeyExchange  )
			 *      ( CertificateRequest )
			 *        ServerHelloDone
			 */
		case JHD_TLS_SSL_SERVER_HELLO:
			ret = ssl_write_server_hello(c);
			break;

		case JHD_TLS_SSL_SERVER_CERTIFICATE:
			ret = jhd_tls_ssl_write_certificate(c);
			break;

		case JHD_TLS_SSL_SERVER_KEY_EXCHANGE:
			ret = ssl_write_server_key_exchange(c);
			break;

		case JHD_TLS_SSL_CERTIFICATE_REQUEST:
			ret = ssl_write_certificate_request(c);
			break;

		case JHD_TLS_SSL_SERVER_HELLO_DONE:
			ret = ssl_write_server_hello_done(c);
			break;

			/*
			 *  <== ( Certificate/Alert  )
			 *        ClientKeyExchange
			 *      ( CertificateVerify  )
			 *        ChangeCipherSpec
			 *        Finished
			 */
		case JHD_TLS_SSL_CLIENT_CERTIFICATE:
			ret = jhd_tls_ssl_parse_certificate(c);
			break;

		case JHD_TLS_SSL_CLIENT_KEY_EXCHANGE:
			ret = ssl_parse_client_key_exchange(c);
			break;

		case JHD_TLS_SSL_CERTIFICATE_VERIFY:
			ret = ssl_parse_certificate_verify(ssl);
			break;

		case JHD_TLS_SSL_CLIENT_CHANGE_CIPHER_SPEC:
			ret = jhd_tls_ssl_parse_change_cipher_spec(c);
			break;

		case JHD_TLS_SSL_CLIENT_FINISHED:
			ret = jhd_tls_ssl_parse_finished(c);
			break;

			/*
			 *  ==> ( NewSessionTicket )
			 *        ChangeCipherSpec
			 *        Finished
			 */
		case JHD_TLS_SSL_SERVER_CHANGE_CIPHER_SPEC:
			ret = jhd_tls_ssl_write_change_cipher_spec(c);
			break;

		case JHD_TLS_SSL_SERVER_FINISHED:
			ret = jhd_tls_ssl_write_finished(c);
			break;
		case JHD_TLS_SSL_HANDSHAKE_WRAPUP:
			jhd_tls_ssl_handshake_wrapup(c);
			break;

		default:
			log_emerg("invalid state %d", ssl->state);
			return JHD_ERROR;
	}
	return (ret);
}

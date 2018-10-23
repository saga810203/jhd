#ifndef JHD_TLS_SSL_INTERNAL_H
#define JHD_TLS_SSL_INTERNAL_H

#include <tls/jhd_tls_cipher.h>
#include <tls/jhd_tls_ssl.h>
#include <tls/jhd_tls_md5.h>
#include <tls/jhd_tls_sha1.h>
#include <tls/jhd_tls_sha256.h>
#include <tls/jhd_tls_sha512.h>




#if ( defined(__ARMCC_VERSION) || defined(_MSC_VER) ) && \
    !defined(inline) && !defined(__cplusplus)
#define inline __inline
#endif

/* Determine minimum supported version */
#define JHD_TLS_SSL_MIN_MAJOR_VERSION           JHD_TLS_SSL_MAJOR_VERSION_3


#define JHD_TLS_SSL_MIN_MINOR_VERSION           JHD_TLS_SSL_MINOR_VERSION_1




/* Determine maximum supported version */
#define JHD_TLS_SSL_MAX_MAJOR_VERSION           JHD_TLS_SSL_MAJOR_VERSION_3


#define JHD_TLS_SSL_MAX_MINOR_VERSION           JHD_TLS_SSL_MINOR_VERSION_3


#define JHD_TLS_SSL_INITIAL_HANDSHAKE           0
#define JHD_TLS_SSL_RENEGOTIATION_IN_PROGRESS   1   /* In progress */
#define JHD_TLS_SSL_RENEGOTIATION_DONE          2   /* Done or aborted */
#define JHD_TLS_SSL_RENEGOTIATION_PENDING       3   /* Requested (server only) */

/*
 * DTLS retransmission states, see RFC 6347 4.2.4
 *
 * The SENDING state is merged in PREPARING for initial sends,
 * but is distinct for resends.
 *
 * Note: initial state is wrong for server, but is not used anyway.
 */
#define JHD_TLS_SSL_RETRANS_PREPARING       0
#define JHD_TLS_SSL_RETRANS_SENDING         1
#define JHD_TLS_SSL_RETRANS_WAITING         2
#define JHD_TLS_SSL_RETRANS_FINISHED        3



#define JHD_TLS_SSL_MAC_ADD                 48  /* SHA-384 used for HMAC */



#define JHD_TLS_SSL_PADDING_ADD            256


#define JHD_TLS_SSL_PAYLOAD_LEN ( JHD_TLS_SSL_MAX_CONTENT_LEN    \
                        + JHD_TLS_MAX_IV_LENGTH                  \
                        + JHD_TLS_SSL_MAC_ADD                    \
                        + JHD_TLS_SSL_PADDING_ADD                \
                        )

/*
 * Check that we obey the standard's message size bounds
 */

#if JHD_TLS_SSL_MAX_CONTENT_LEN > 16384
#error Bad configuration - record content too large.
#endif

#if JHD_TLS_SSL_PAYLOAD_LEN > 16384 + 2048
#error Bad configuration - protected record payload too large.
#endif

/* Note: Even though the TLS record header is only 5 bytes
 long, we're internally using 8 bytes to store the
 implicit sequence number. */
#define JHD_TLS_SSL_HEADER_LEN 13

#define JHD_TLS_SSL_BUFFER_LEN  \
    ( ( JHD_TLS_SSL_HEADER_LEN ) + ( JHD_TLS_SSL_PAYLOAD_LEN ) )

/*
 * TLS extension flags (for extensions with outgoing ServerHello content
 * that need it (e.g. for RENEGOTIATION_INFO the server already knows because
 * of state of the renegotiation flag, so no indicator is required)
 */
#define JHD_TLS_TLS_EXT_SUPPORTED_POINT_FORMATS_PRESENT (1 << 0)
#define JHD_TLS_TLS_EXT_ECJPAKE_KKPP_OK                 (1 << 1)



/*
 * Abstraction for a grid of allowed signature-hash-algorithm pairs.
 */
struct jhd_tls_ssl_sig_hash_set_t {
	/* At the moment, we only need to remember a single suitable
	 * hash algorithm per signature algorithm. As long as that's
	 * the case - and we don't need a general lookup function -
	 * we can implement the sig-hash-set as a map from signatures
	 * to hash algorithms. */
	const jhd_tls_md_info_t* rsa;
	const jhd_tls_md_info_t* ecdsa;
};


/*
 * This structure contains the parameters only needed during handshake.
 */
struct jhd_tls_ssl_handshake_params {
	jhd_tls_ssl_sig_hash_set_t hash_algs; /*!<  Set of suitable sig-hash pairs */
	jhd_tls_ecdh_context ecdh_ctx; /*!<  ECDH key exchange       */
	unsigned int curves_flag;
	jhd_tls_ssl_key_cert *key_cert; /*!< chosen key/cert pair (server)  */
	jhd_tls_md5_context fin_md5;
	jhd_tls_sha1_context fin_sha1;
	jhd_tls_sha256_context fin_sha256;
	jhd_tls_sha512_context fin_sha512;
	void (*update_checksum)(jhd_tls_ssl_context *, const unsigned char *, size_t);
	void (*calc_verify)(jhd_tls_ssl_context *, unsigned char *);
	void (*calc_finished)(jhd_tls_ssl_context *, unsigned char *, int);
	void (*tls_prf)(const unsigned char *, size_t, const char *, const unsigned char *, size_t, unsigned char *, size_t);
	size_t pmslen; /*!<  premaster length        */
	unsigned char randbytes[64]; /*!<  random bytes            */
	unsigned char premaster[JHD_TLS_PREMASTER_SIZE];
	/*!<  premaster secret        */
	unsigned char max_major_ver; /*!< max. major version client*/
	unsigned char max_minor_ver; /*!< max. minor version client*/
	int cli_exts; /*!< client extension presence*/
	int extended_ms; /*!< use Extended Master Secret? */

	jhd_tls_x509_crt *peer_cert; /*!< peer X.509 cert chain */
	const jhd_tls_ssl_ciphersuite_t *ciphersuite_info;
	unsigned char master[48]; /*!< the master secret  */
	unsigned char mfl_code; /*!< MaxFragmentLength negotiated by peer */
	int trunc_hmac; /*!< flag for truncated hmac activation   */
	int encrypt_then_mac; /*!< flag for EtM activation                */
	unsigned char  client_auth; /*!<  flag for client auth.   */
	const unsigned char *server_name_buf;

/* parse_cert use*/
	int msg_len;
	jhd_tls_x509_crt *curr_cert;
	size_t i;


};


/*
 * List of certificate + private key pairs
 */
struct jhd_tls_ssl_key_cert {
	jhd_tls_x509_crt *cert; /*!< cert                       */
	jhd_tls_pk_context *key; /*!< private key                */
	jhd_tls_ssl_key_cert *next; /*!< next key/cert pair         */
};



#if !defined(JHD_TLS_INLINE)

/* Find an entry in a signature-hash set matching a given hash algorithm. */
const jhd_tls_md_info_t* jhd_tls_ssl_sig_hash_set_find(jhd_tls_ssl_sig_hash_set_t *set,const jhd_tls_pk_info_t *sig_alg);
/* Add a signature-hash-pair to a signature-hash set */
void jhd_tls_ssl_sig_hash_set_add(jhd_tls_ssl_sig_hash_set_t *set, const jhd_tls_pk_info_t *sig_alg,const jhd_tls_md_info_t* md_info);

/* Allow exactly one hash algorithm for each signature. */
void jhd_tls_ssl_sig_hash_set_const_hash(jhd_tls_ssl_sig_hash_set_t *set,const jhd_tls_md_info_t* md_info);

#else

#define jhd_tls_ssl_sig_hash_set_find(set,sig_alg)   ((sig_alg)== &jhd_tls_rsa_info ? ((set)->rsa):((sig_alg) == &jhd_tls_ecdsa_info ? ((set)->ecdsa):(NULL)))						\

/* Add a signature-hash-pair to a signature-hash set */
#define jhd_tls_ssl_sig_hash_set_add(set,sig_alg,md_info)  												\
	if((sig_alg)== &jhd_tls_rsa_info) {																	\
		if((set)->rsa == NULL){(set)->rsa = (md_info);}										\
	}else if((sig_alg)== &jhd_tls_ecdsa_info){																\
		if((set)->ecdsa == NULL){(set)->ecdsa = (md_info);}									\
	}

#define jhd_tls_ssl_sig_hash_set_const_hash(set,md_info) (set)->rsa = (md_info);(set)->ecdsa =(md_info)



#endif

/**
 * \brief           Free referenced items in an SSL handshake context and clear
 *                  memory
 *
 * \param ssl       SSL context
 */
void jhd_tls_ssl_handshake_free(jhd_tls_ssl_context *ssl);

int jhd_tls_ssl_handshake_client_step(jhd_connection_t *c);
int jhd_tls_ssl_handshake_server_step(jhd_connection_t *c);
void jhd_tls_ssl_handshake_wrapup(jhd_connection_t *c);

int jhd_tls_ssl_send_fatal_handshake_failure(jhd_connection_t *c);

void jhd_tls_ssl_reset_checksum(jhd_tls_ssl_context *ssl);
void jhd_tls_ssl_derive_keys(jhd_tls_ssl_context *ssl);




int jhd_tls_ssl_fetch_input(jhd_connection_t *c, size_t nb_want);


int jhd_tls_ssl_flush_output(jhd_connection_t *c);

int jhd_tls_ssl_parse_certificate(jhd_connection_t *c);
int jhd_tls_ssl_write_certificate(jhd_connection_t *c);

int jhd_tls_ssl_parse_change_cipher_spec(jhd_connection_t *c);
int jhd_tls_ssl_write_change_cipher_spec(jhd_connection_t *c);

int jhd_tls_ssl_parse_finished(jhd_connection_t *c);
int jhd_tls_ssl_write_finished(jhd_connection_t *c);

void jhd_tls_ssl_optimize_checksum(jhd_tls_ssl_context *ssl, const jhd_tls_ssl_ciphersuite_t *ciphersuite_info);



#if !defined(JHD_TLS_INLINE)
unsigned char jhd_tls_ssl_sig_from_pk(jhd_tls_pk_context *pk);
unsigned char jhd_tls_ssl_sig_from_pk_alg(const jhd_tls_pk_info_t *pk_info);
const jhd_tls_pk_info_t* jhd_tls_ssl_pk_alg_from_sig(unsigned char sig);
const jhd_tls_md_info_t* jhd_tls_ssl_md_info_from_hash(unsigned char hash);
unsigned char jhd_tls_ssl_hash_from_md_info(const jhd_tls_md_info_t *md_info);
#else
#define jhd_tls_ssl_sig_from_pk(pk) ((pk)->pk_info == &jhd_tls_rsa_info ? ( JHD_TLS_SSL_SIG_RSA):((pk)->pk_info == &jhd_tls_ecdsa_info?(JHD_TLS_SSL_SIG_ECDSA):(JHD_TLS_SSL_SIG_ANON)))

#define jhd_tls_ssl_sig_from_pk_alg(type)   (type->pk_flag)

#define jhd_tls_ssl_pk_alg_from_sig(sig) 	(														\
	(sig)==JHD_TLS_SSL_SIG_RSA?(&jhd_tls_rsa_info):(												\
		(sig)==JHD_TLS_SSL_SIG_ECDSA?(&jhd_tls_ecdsa_info):NULL)									\
)


#define jhd_tls_ssl_md_info_from_hash(hash)                                    					\
(            																										\
	(hash)== JHD_TLS_SSL_HASH_MD5?(&jhd_tls_md5_info):(        											\
		(hash)== JHD_TLS_SSL_HASH_SHA1?(&jhd_tls_sha1_info):(      										\
			(hash)== JHD_TLS_SSL_HASH_SHA224?(&jhd_tls_sha224_info):(  									\
				(hash)== JHD_TLS_SSL_HASH_SHA256?(&jhd_tls_sha256_info):(  								\
					(hash)== JHD_TLS_SSL_HASH_SHA384?(&jhd_tls_sha384_info):(  							\
						(hash)== JHD_TLS_SSL_HASH_SHA512?(&jhd_tls_sha512_info): ((const jhd_tls_md_info_t* )NULL)   \
					)																					\
				)																						\
			)																							\
		)																								\
	)																									\
)

#define jhd_tls_ssl_hash_from_md_info(md) (md->hash_flag)



#endif



int jhd_tls_ssl_set_calc_verify_md(jhd_tls_ssl_context *ssl, int md);

int jhd_tls_ssl_check_curve(const jhd_tls_ssl_context *ssl, jhd_tls_ecp_group_id grp_id);





static inline jhd_tls_pk_context *jhd_tls_ssl_own_key(jhd_tls_ssl_context *ssl) {
	jhd_tls_ssl_key_cert *key_cert;

	if (ssl->handshake != NULL && ssl->handshake->key_cert != NULL)
		key_cert = ssl->handshake->key_cert;
	else
		key_cert = ssl->conf->key_cert;

	return (key_cert == NULL ? NULL : key_cert->key);
}

static inline jhd_tls_x509_crt *jhd_tls_ssl_own_cert(jhd_tls_ssl_context *ssl) {
	jhd_tls_ssl_key_cert *key_cert;

	if (ssl->handshake != NULL && ssl->handshake->key_cert != NULL)
		key_cert = ssl->handshake->key_cert;
	else
		key_cert = ssl->conf->key_cert;

	return (key_cert == NULL ? NULL : key_cert->cert);
}

/*
 * Check usage of a certificate wrt extensions:
 * keyUsage, extendedKeyUsage (later), and nSCertType (later).
 *
 * Warning: cert_endpoint is the endpoint of the cert (ie, of our peer when we
 * check a cert we received from them)!
 *
 * Return 0 if everything is OK, -1 if not.
 */
int jhd_tls_ssl_check_cert_usage(const jhd_tls_x509_crt *cert, const jhd_tls_ssl_ciphersuite_t *ciphersuite, int cert_endpoint, uint32_t *flags);


#define jhd_tls_ssl_hdr_len(ssl)  (5)
//static inline size_t jhd_tls_ssl_hdr_len(const jhd_tls_ssl_context *ssl) {
////#if defined(JHD_TLS_SSL_PROTO_DTLS)
////    if( ssl->conf->transport == JHD_TLS_SSL_TRANSPORT_DATAGRAM )
////        return( 13 );
////#else
////    ((void) ssl);
////#endif
////    return( 5 );
//return 5;
//}
#define jhd_tls_ssl_hs_hdr_len(ssl) (4)
//static inline size_t jhd_tls_ssl_hs_hdr_len(const jhd_tls_ssl_context *ssl) {
////#if defined(JHD_TLS_SSL_PROTO_DTLS)
////    if( ssl->conf->transport == JHD_TLS_SSL_TRANSPORT_DATAGRAM )
////        return( 12 );
////#else
////    ((void) ssl);
////#endif
////    return( 4 );
//
//return 4;
//}

/* constant-time buffer comparison */
static inline int jhd_tls_ssl_safer_memcmp(const void *a, const void *b, size_t n) {
	size_t i;
	volatile const unsigned char *A = (volatile const unsigned char *) a;
	volatile const unsigned char *B = (volatile const unsigned char *) b;
	volatile unsigned char diff = 0;

	for (i = 0; i < n; i++) {
		/* Read volatile data in order before computing diff.
		 * This avoids IAR compiler warning:
		 * 'the order of volatile accesses is undefined ..' */
		unsigned char x = A[i], y = B[i];
		diff |= x ^ y;
	}

	return (diff);
}


void jhd_tls_ssl_get_key_exchange_md_ssl_tls(unsigned char *output,const unsigned char *randbytes,const unsigned char *data,const size_t data_len);



void jhd_tls_ssl_get_key_exchange_md_tls1_2(unsigned char *hash, size_t *hashlen,const unsigned char *randbytes,const unsigned char *data,const size_t data_len,const jhd_tls_md_info_t* md_info);


int jhd_tls_ssl_cbc_with_etm_eq_tls10_encrypt_buf(jhd_tls_ssl_context *ssl);

int jhd_tls_ssl_cbc_without_etm_eq_tls10_encrypt_buf(jhd_tls_ssl_context *ssl);

int jhd_tls_ssl_cbc_with_etm_gteq_tls11_encrypt_buf(jhd_tls_ssl_context *ssl);

int jhd_tls_ssl_cbc_without_etm_gteq_tls11_encrypt_buf(jhd_tls_ssl_context *ssl);







int jhd_tls_ssl_cbc_with_etm_eq_tls10_decrypt_buf(jhd_tls_ssl_context *ssl);

int jhd_tls_ssl_cbc_without_etm_eq_tls10_decrypt_buf(jhd_tls_ssl_context *ssl);

int jhd_tls_ssl_cbc_with_etm_gteq_tls11_decrypt_buf(jhd_tls_ssl_context *ssl);

int jhd_tls_ssl_cbc_without_etm_gteq_tls11_decrypt_buf(jhd_tls_ssl_context *ssl);


int jhd_tls_ssl_gcm_encrypt_buf(jhd_tls_ssl_context *ssl);

int jhd_tls_ssl_ccm_encrypt_buf(jhd_tls_ssl_context *ssl);

int jhd_tls_ssl_gcm_decrypt_buf(jhd_tls_ssl_context *ssl);

int jhd_tls_ssl_ccm_decrypt_buf(jhd_tls_ssl_context *ssl);


#ifdef JHD_LOG_ASSERT_ENABLE

int jhd_tls_ssl_do_encrypt(jhd_tls_ssl_context *ssl);
int jhd_tls_ssl_do_decrypt(jhd_tls_ssl_context *ssl);

#else

#define jhd_tls_ssl_do_encrypt(SSL) (SSL)->encrypt_func(SSL)
#define jhd_tls_ssl_do_decrypt(SSL) (SSL)->decrypt_func(SSL)

#endif


#endif /* ssl_internal.h */

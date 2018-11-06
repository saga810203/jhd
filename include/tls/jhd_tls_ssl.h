#ifndef JHD_TLS_SSL_H
#define JHD_TLS_SSL_H
#include <tls/jhd_tls_config.h>
#include <tls/jhd_tls_bignum.h>
#include <tls/jhd_tls_ecp.h>
#include <tls/jhd_tls_ctr_drbg.h>
#include <tls/jhd_tls_ssl_ciphersuites.h>
#include <tls/jhd_tls_x509_crt.h>
#include <tls/jhd_tls_ecdh.h>
#include <jhd_connection.h>

/*
 * SSL Error codes
 */
#define JHD_TLS_ERR_SSL_FEATURE_UNAVAILABLE               -0x7080  /**< The requested feature is not available. */
#define JHD_TLS_ERR_SSL_BAD_INPUT_DATA                    -0x7100  /**< Bad input parameters to function. */
#define JHD_TLS_ERR_SSL_INVALID_MAC                       -0x7180  /**< Verification of the message MAC failed. */
#define JHD_TLS_ERR_SSL_INVALID_RECORD                    -0x7200  /**< An invalid SSL record was received. */
#define JHD_TLS_ERR_SSL_CONN_EOF                          -0x7280  /**< The connection indicated an EOF. */
#define JHD_TLS_ERR_SSL_UNKNOWN_CIPHER                    -0x7300  /**< An unknown cipher was received. */
#define JHD_TLS_ERR_SSL_NO_CIPHER_CHOSEN                  -0x7380  /**< The server has no ciphersuites in common with the client. */
#define JHD_TLS_ERR_SSL_NO_RNG                            -0x7400  /**< No RNG was provided to the SSL module. */
#define JHD_TLS_ERR_SSL_NO_CLIENT_CERTIFICATE             -0x7480  /**< No client certification received from the client, but required by the authentication mode. */
#define JHD_TLS_ERR_SSL_CERTIFICATE_TOO_LARGE             -0x7500  /**< Our own certificate(s) is/are too large to send in an SSL message. */
#define JHD_TLS_ERR_SSL_CERTIFICATE_REQUIRED              -0x7580  /**< The own certificate is not set, but needed by the server. */
#define JHD_TLS_ERR_SSL_PRIVATE_KEY_REQUIRED              -0x7600  /**< The own private key or pre-shared key is not set, but needed. */
#define JHD_TLS_ERR_SSL_CA_CHAIN_REQUIRED                 -0x7680  /**< No CA Chain is set, but required to operate. */
#define JHD_TLS_ERR_SSL_UNEXPECTED_MESSAGE                -0x7700  /**< An unexpected message was received from our peer. */
#define JHD_TLS_ERR_SSL_FATAL_ALERT_MESSAGE               -0x7780  /**< A fatal alert message was received from our peer. */
#define JHD_TLS_ERR_SSL_PEER_VERIFY_FAILED                -0x7800  /**< Verification of our peer failed. */
#define JHD_TLS_ERR_SSL_PEER_CLOSE_NOTIFY                 -0x7880  /**< The peer notified us that the connection is going to be closed. */
#define JHD_TLS_ERR_SSL_BAD_HS_CLIENT_HELLO               -0x7900  /**< Processing of the ClientHello handshake message failed. */
#define JHD_TLS_ERR_SSL_BAD_HS_SERVER_HELLO               -0x7980  /**< Processing of the ServerHello handshake message failed. */
#define JHD_TLS_ERR_SSL_BAD_HS_CERTIFICATE                -0x7A00  /**< Processing of the Certificate handshake message failed. */
#define JHD_TLS_ERR_SSL_BAD_HS_CERTIFICATE_REQUEST        -0x7A80  /**< Processing of the CertificateRequest handshake message failed. */
#define JHD_TLS_ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE        -0x7B00  /**< Processing of the ServerKeyExchange handshake message failed. */
#define JHD_TLS_ERR_SSL_BAD_HS_SERVER_HELLO_DONE          -0x7B80  /**< Processing of the ServerHelloDone handshake message failed. */
#define JHD_TLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE        -0x7C00  /**< Processing of the ClientKeyExchange handshake message failed. */
#define JHD_TLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE_RP     -0x7C80  /**< Processing of the ClientKeyExchange handshake message failed in DHM / ECDH Read Public. */
#define JHD_TLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE_CS     -0x7D00  /**< Processing of the ClientKeyExchange handshake message failed in DHM / ECDH Calculate Secret. */
#define JHD_TLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY         -0x7D80  /**< Processing of the CertificateVerify handshake message failed. */
#define JHD_TLS_ERR_SSL_BAD_HS_CHANGE_CIPHER_SPEC         -0x7E00  /**< Processing of the ChangeCipherSpec handshake message failed. */
#define JHD_TLS_ERR_SSL_BAD_HS_FINISHED                   -0x7E80  /**< Processing of the Finished handshake message failed. */
#define JHD_TLS_ERR_SSL_ALLOC_FAILED                      -0x7F00  /**< Memory allocation failed */
#define JHD_TLS_ERR_SSL_HW_ACCEL_FAILED                   -0x7F80  /**< Hardware acceleration function returned with error */
#define JHD_TLS_ERR_SSL_HW_ACCEL_FALLTHROUGH              -0x6F80  /**< Hardware acceleration function skipped / left alone data */
#define JHD_TLS_ERR_SSL_COMPRESSION_FAILED                -0x6F00  /**< Processing of the compression / decompression failed */
#define JHD_TLS_ERR_SSL_BAD_HS_PROTOCOL_VERSION           -0x6E80  /**< Handshake protocol not within min/max boundaries */
#define JHD_TLS_ERR_SSL_BAD_HS_NEW_SESSION_TICKET         -0x6E00  /**< Processing of the NewSessionTicket handshake message failed. */
#define JHD_TLS_ERR_SSL_SESSION_TICKET_EXPIRED            -0x6D80  /**< Session ticket has expired. */
#define JHD_TLS_ERR_SSL_PK_TYPE_MISMATCH                  -0x6D00  /**< Public key type mismatch (eg, asked for RSA key exchange and presented EC key) */
#define JHD_TLS_ERR_SSL_UNKNOWN_IDENTITY                  -0x6C80  /**< Unknown identity received (eg, PSK identity) */
#define JHD_TLS_ERR_SSL_INTERNAL_ERROR                    -0x6C00  /**< Internal error (eg, unexpected failure in lower-level module) */
#define JHD_TLS_ERR_SSL_COUNTER_WRAPPING                  -0x6B80  /**< A counter would wrap (eg, too many messages exchanged). */
#define JHD_TLS_ERR_SSL_WAITING_SERVER_HELLO_RENEGO       -0x6B00  /**< Unexpected message at ServerHello in renegotiation. */
#define JHD_TLS_ERR_SSL_HELLO_VERIFY_REQUIRED             -0x6A80  /**< DTLS client must retry for hello verification */
#define JHD_TLS_ERR_SSL_BUFFER_TOO_SMALL                  -0x6A00  /**< A buffer is too small to receive or write a message */
#define JHD_TLS_ERR_SSL_NO_USABLE_CIPHERSUITE             -0x6980  /**< None of the common ciphersuites is usable (eg, no suitable certificate, see debug messages). */
#define JHD_TLS_ERR_SSL_WANT_READ                         -0x6900  /**< No data of requested type currently available on underlying transport. */
#define JHD_TLS_ERR_SSL_WANT_WRITE                        -0x6880  /**< Connection requires a write call. */
#define JHD_TLS_ERR_SSL_TIMEOUT                           -0x6800  /**< The operation timed out. */
#define JHD_TLS_ERR_SSL_CLIENT_RECONNECT                  -0x6780  /**< The client initiated a reconnect from the same port. */
#define JHD_TLS_ERR_SSL_UNEXPECTED_RECORD                 -0x6700  /**< Record header looks valid but is not expected. */
#define JHD_TLS_ERR_SSL_NON_FATAL                         -0x6680  /**< The alert message received indicates a non-fatal error. */
#define JHD_TLS_ERR_SSL_INVALID_VERIFY_HASH               -0x6600  /**< Couldn't set the hash for verifying CertificateVerify */
#define JHD_TLS_ERR_SSL_CONTINUE_PROCESSING               -0x6580  /**< Internal-only message signaling that further message-processing should be done */
#define JHD_TLS_ERR_SSL_ASYNC_IN_PROGRESS                 -0x6500  /**< The asynchronous operation is not completed yet. */

/*
 * Various constants
 */
#define JHD_TLS_SSL_MAJOR_VERSION_3             3
#define JHD_TLS_SSL_MINOR_VERSION_0             0   /*!< SSL v3.0 */
#define JHD_TLS_SSL_MINOR_VERSION_1             1   /*!< TLS v1.0 */
#define JHD_TLS_SSL_MINOR_VERSION_2             2   /*!< TLS v1.1 */
#define JHD_TLS_SSL_MINOR_VERSION_3             3   /*!< TLS v1.2 */

//#define JHD_TLS_SSL_TRANSPORT_STREAM            0   /*!< TLS      */
//#define JHD_TLS_SSL_TRANSPORT_DATAGRAM          1   /*!< DTLS     */

#define JHD_TLS_SSL_MAX_HOST_NAME_LEN           255 /*!< Maximum host name defined in RFC 1035 */

/* RFC 6066 section 4, see also mfl_code_to_length in ssl_tls.c
 * NONE must be zero so that memset()ing structure to zero works */
#define JHD_TLS_SSL_MAX_FRAG_LEN_NONE           0   /*!< don't use this extension   */
#define JHD_TLS_SSL_MAX_FRAG_LEN_512            1   /*!< MaxFragmentLength 2^9      */
#define JHD_TLS_SSL_MAX_FRAG_LEN_1024           2   /*!< MaxFragmentLength 2^10     */
#define JHD_TLS_SSL_MAX_FRAG_LEN_2048           3   /*!< MaxFragmentLength 2^11     */
#define JHD_TLS_SSL_MAX_FRAG_LEN_4096           4   /*!< MaxFragmentLength 2^12     */
#define JHD_TLS_SSL_MAX_FRAG_LEN_INVALID        5   /*!< first invalid value        */

#define JHD_TLS_SSL_IS_CLIENT                   0
#define JHD_TLS_SSL_IS_SERVER                   1

#define JHD_TLS_SSL_IS_NOT_FALLBACK             0
#define JHD_TLS_SSL_IS_FALLBACK                 1

#define JHD_TLS_SSL_EXTENDED_MS_DISABLED        0
#define JHD_TLS_SSL_EXTENDED_MS_ENABLED         1

#define JHD_TLS_SSL_ETM_DISABLED                0
#define JHD_TLS_SSL_ETM_ENABLED                 1

#define JHD_TLS_SSL_COMPRESS_NULL               0
#define JHD_TLS_SSL_COMPRESS_DEFLATE            1

#define JHD_TLS_SSL_VERIFY_NONE                 0
#define JHD_TLS_SSL_VERIFY_OPTIONAL             1
#define JHD_TLS_SSL_VERIFY_REQUIRED             2
#define JHD_TLS_SSL_VERIFY_UNSET                3 /* Used only for sni_authmode */

#define JHD_TLS_SSL_LEGACY_RENEGOTIATION        0
#define JHD_TLS_SSL_SECURE_RENEGOTIATION        1

#define JHD_TLS_SSL_RENEGOTIATION_DISABLED      0
#define JHD_TLS_SSL_RENEGOTIATION_ENABLED       1

#define JHD_TLS_SSL_ANTI_REPLAY_DISABLED        0
#define JHD_TLS_SSL_ANTI_REPLAY_ENABLED         1

#define JHD_TLS_SSL_RENEGOTIATION_NOT_ENFORCED  -1
#define JHD_TLS_SSL_RENEGO_MAX_RECORDS_DEFAULT  16

#define JHD_TLS_SSL_LEGACY_NO_RENEGOTIATION     0
#define JHD_TLS_SSL_LEGACY_ALLOW_RENEGOTIATION  1
#define JHD_TLS_SSL_LEGACY_BREAK_HANDSHAKE      2

#define JHD_TLS_SSL_TRUNC_HMAC_DISABLED         0
#define JHD_TLS_SSL_TRUNC_HMAC_ENABLED          1
#define JHD_TLS_SSL_TRUNCATED_HMAC_LEN          10  /* 80 bits, rfc 6066 section 7 */


#define JHD_TLS_SSL_ARC4_ENABLED                0
#define JHD_TLS_SSL_ARC4_DISABLED               1

#define JHD_TLS_SSL_PRESET_DEFAULT              0
#define JHD_TLS_SSL_PRESET_SUITEB               2

#define JHD_TLS_SSL_CERT_REQ_CA_LIST_ENABLED       1
#define JHD_TLS_SSL_CERT_REQ_CA_LIST_DISABLED      0

/*
 * Default range for DTLS retransmission timer value, in milliseconds.
 * RFC 6347 4.2.4.1 says from 1 second to 60 seconds.
 */
//#define JHD_TLS_SSL_DTLS_TIMEOUT_DFL_MIN    1000
//#define JHD_TLS_SSL_DTLS_TIMEOUT_DFL_MAX   60000
/**
 * \name SECTION: Module settings
 *
 * The configuration options you can set for this module are in this section.
 * Either change them in config.h or define them on the compiler command line.
 * \{
 */

#if !defined(JHD_TLS_SSL_DEFAULT_TICKET_LIFETIME)
#define JHD_TLS_SSL_DEFAULT_TICKET_LIFETIME     86400 /**< Lifetime of session tickets (if enabled) */
#endif

/*
 * Maxium fragment length in bytes,
 * determines the size of each of the two internal I/O buffers.
 *
 * Note: the RFC defines the default size of SSL / TLS messages. If you
 * change the value here, other clients / servers may not be able to
 * communicate with you anymore. Only change this value if you control
 * both sides of the connection and have it reduced at both sides, or
 * if you're using the Max Fragment Length extension and you know all your
 * peers are using it too!
 */
#if !defined(JHD_TLS_SSL_MAX_CONTENT_LEN)
#define JHD_TLS_SSL_MAX_CONTENT_LEN         16384   /**< Size of the input / output buffer */
#endif

/* \} name SECTION: Module settings */

/*
 * Length of the verify data for secure renegotiation
 */
#define JHD_TLS_SSL_VERIFY_DATA_MAX_LEN 12

/*
 * Supported Signature and Hash algorithms (For TLS 1.2)
 * RFC 5246 section 7.4.1.4.1
 */




/*
 * Client Certificate Types
 * RFC 5246 section 7.4.4 plus RFC 4492 section 5.5
 */
#define JHD_TLS_SSL_CERT_TYPE_RSA_SIGN       1
#define JHD_TLS_SSL_CERT_TYPE_ECDSA_SIGN    64

/*
 * Message, alert and handshake types
 */
#define JHD_TLS_SSL_MSG_CHANGE_CIPHER_SPEC     20
#define JHD_TLS_SSL_MSG_ALERT                  21
#define JHD_TLS_SSL_MSG_HANDSHAKE              22
#define JHD_TLS_SSL_MSG_APPLICATION_DATA       23

#define JHD_TLS_SSL_ALERT_LEVEL_WARNING         1
#define JHD_TLS_SSL_ALERT_LEVEL_FATAL           2

#define JHD_TLS_SSL_ALERT_MSG_CLOSE_NOTIFY           0  /* 0x00 */
#define JHD_TLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE    10  /* 0x0A */
#define JHD_TLS_SSL_ALERT_MSG_BAD_RECORD_MAC        20  /* 0x14 */
#define JHD_TLS_SSL_ALERT_MSG_DECRYPTION_FAILED     21  /* 0x15 */
#define JHD_TLS_SSL_ALERT_MSG_RECORD_OVERFLOW       22  /* 0x16 */
#define JHD_TLS_SSL_ALERT_MSG_DECOMPRESSION_FAILURE 30  /* 0x1E */
#define JHD_TLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE     40  /* 0x28 */
#define JHD_TLS_SSL_ALERT_MSG_NO_CERT               41  /* 0x29 */
#define JHD_TLS_SSL_ALERT_MSG_BAD_CERT              42  /* 0x2A */
#define JHD_TLS_SSL_ALERT_MSG_UNSUPPORTED_CERT      43  /* 0x2B */
#define JHD_TLS_SSL_ALERT_MSG_CERT_REVOKED          44  /* 0x2C */
#define JHD_TLS_SSL_ALERT_MSG_CERT_EXPIRED          45  /* 0x2D */
#define JHD_TLS_SSL_ALERT_MSG_CERT_UNKNOWN          46  /* 0x2E */
#define JHD_TLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER     47  /* 0x2F */
#define JHD_TLS_SSL_ALERT_MSG_UNKNOWN_CA            48  /* 0x30 */
#define JHD_TLS_SSL_ALERT_MSG_ACCESS_DENIED         49  /* 0x31 */
#define JHD_TLS_SSL_ALERT_MSG_DECODE_ERROR          50  /* 0x32 */
#define JHD_TLS_SSL_ALERT_MSG_DECRYPT_ERROR         51  /* 0x33 */
#define JHD_TLS_SSL_ALERT_MSG_EXPORT_RESTRICTION    60  /* 0x3C */
#define JHD_TLS_SSL_ALERT_MSG_PROTOCOL_VERSION      70  /* 0x46 */
#define JHD_TLS_SSL_ALERT_MSG_INSUFFICIENT_SECURITY 71  /* 0x47 */
#define JHD_TLS_SSL_ALERT_MSG_INTERNAL_ERROR        80  /* 0x50 */
#define JHD_TLS_SSL_ALERT_MSG_INAPROPRIATE_FALLBACK 86  /* 0x56 */
#define JHD_TLS_SSL_ALERT_MSG_USER_CANCELED         90  /* 0x5A */
#define JHD_TLS_SSL_ALERT_MSG_NO_RENEGOTIATION     100  /* 0x64 */
#define JHD_TLS_SSL_ALERT_MSG_UNSUPPORTED_EXT      110  /* 0x6E */
#define JHD_TLS_SSL_ALERT_MSG_UNRECOGNIZED_NAME    112  /* 0x70 */
#define JHD_TLS_SSL_ALERT_MSG_UNKNOWN_PSK_IDENTITY 115  /* 0x73 */
#define JHD_TLS_SSL_ALERT_MSG_NO_APPLICATION_PROTOCOL 120 /* 0x78 */

#define JHD_TLS_SSL_HS_HELLO_REQUEST            0
#define JHD_TLS_SSL_HS_CLIENT_HELLO             1
#define JHD_TLS_SSL_HS_SERVER_HELLO             2
#define JHD_TLS_SSL_HS_HELLO_VERIFY_REQUEST     3
#define JHD_TLS_SSL_HS_NEW_SESSION_TICKET       4
#define JHD_TLS_SSL_HS_CERTIFICATE             11
#define JHD_TLS_SSL_HS_SERVER_KEY_EXCHANGE     12
#define JHD_TLS_SSL_HS_CERTIFICATE_REQUEST     13
#define JHD_TLS_SSL_HS_SERVER_HELLO_DONE       14
#define JHD_TLS_SSL_HS_CERTIFICATE_VERIFY      15
#define JHD_TLS_SSL_HS_CLIENT_KEY_EXCHANGE     16
#define JHD_TLS_SSL_HS_FINISHED                20

/*
 * TLS extensions
 */
#define JHD_TLS_TLS_EXT_SERVERNAME                   0
#define JHD_TLS_TLS_EXT_SERVERNAME_HOSTNAME          0

#define JHD_TLS_TLS_EXT_MAX_FRAGMENT_LENGTH          1

#define JHD_TLS_TLS_EXT_TRUNCATED_HMAC               4

#define JHD_TLS_TLS_EXT_SUPPORTED_ELLIPTIC_CURVES   10
#define JHD_TLS_TLS_EXT_SUPPORTED_POINT_FORMATS     11

#define JHD_TLS_TLS_EXT_SIG_ALG                     13

#define JHD_TLS_TLS_EXT_ALPN                        16

#define JHD_TLS_TLS_EXT_ENCRYPT_THEN_MAC            22 /* 0x16 */
#define JHD_TLS_TLS_EXT_EXTENDED_MASTER_SECRET  0x0017 /* 23 */

#define JHD_TLS_TLS_EXT_SESSION_TICKET              35

#define JHD_TLS_TLS_EXT_ECJPAKE_KKPP               256 /* experimental */

#define JHD_TLS_TLS_EXT_RENEGOTIATION_INFO      0xFF01

/*
 * Size defines
 */
#if !defined(JHD_TLS_PSK_MAX_LEN)
#define JHD_TLS_PSK_MAX_LEN            32 /* 256 bits */
#endif

/* Dummy type used only for its size */
union jhd_tls_ssl_premaster_secret {
	unsigned char _pms_rsa[48]; /* RFC 5246 8.1.1 */
	unsigned char _pms_ecdh[JHD_TLS_ECP_MAX_BYTES]; /* RFC 4492 5.10 */
};

#define JHD_TLS_PREMASTER_SIZE     sizeof( union jhd_tls_ssl_premaster_secret )

/*
 * SSL state machine
 */
typedef enum {
	JHD_TLS_SSL_HELLO_REQUEST,
	JHD_TLS_SSL_CLIENT_HELLO,
	JHD_TLS_SSL_SERVER_HELLO,
	JHD_TLS_SSL_SERVER_CERTIFICATE,
	JHD_TLS_SSL_SERVER_KEY_EXCHANGE,
	JHD_TLS_SSL_CERTIFICATE_REQUEST,
	JHD_TLS_SSL_SERVER_HELLO_DONE,
	JHD_TLS_SSL_CLIENT_CERTIFICATE,
	JHD_TLS_SSL_CLIENT_KEY_EXCHANGE,
	JHD_TLS_SSL_CERTIFICATE_VERIFY,
	JHD_TLS_SSL_CLIENT_CHANGE_CIPHER_SPEC,
	JHD_TLS_SSL_CLIENT_FINISHED,
	JHD_TLS_SSL_SERVER_CHANGE_CIPHER_SPEC,
	JHD_TLS_SSL_SERVER_FINISHED,
	JHD_TLS_SSL_HANDSHAKE_WRAPUP,
	JHD_TLS_SSL_HANDSHAKE_OVER,
	JHD_TLS_SSL_SERVER_NEW_SESSION_TICKET,
	JHD_TLS_SSL_SERVER_HELLO_VERIFY_REQUEST_SENT,
} jhd_tls_ssl_states;




/* Defined below */
typedef struct jhd_tls_ssl_context jhd_tls_ssl_context;
typedef struct jhd_tls_ssl_config jhd_tls_ssl_config;

/* Defined in ssl_internal.h */
typedef struct jhd_tls_ssl_handshake_params jhd_tls_ssl_handshake_params;
typedef struct jhd_tls_ssl_sig_hash_set_t jhd_tls_ssl_sig_hash_set_t;

typedef struct jhd_tls_ssl_key_cert jhd_tls_ssl_key_cert;


typedef int (*jhd_tls_ssl_crypt_pt)(jhd_tls_ssl_context *ssl);

/**
 * SSL/TLS configuration to be shared between jhd_tls_ssl_context structures.
 */
struct jhd_tls_ssl_config {
	jhd_tls_ssl_key_cert *key_cert; /*!< own certificate/key pair(s)        */
	const char **alpn_list; /*!< ordered list of protocols          */
	unsigned int server_side :1; /*!< 0: client, 1: server               */
	unsigned int mfl_code :3; /*!< desired fragment length            */
};

struct jhd_tls_ssl_context {
	const jhd_tls_ssl_config *conf; /*!< configuration information          */
	unsigned char state; /*!< SSL handshake: current state     */
	unsigned char major_ver; /*!< equal to  JHD_TLS_SSL_MAJOR_VERSION_3    */
	unsigned char minor_ver; /*!< either 0 (SSL3) or 1 (TLS1.0)    */
	jhd_tls_ssl_handshake_params *handshake;


	uint16_t minlen; /*!<  min. ciphertext length  */
	uint16_t maxlen;
	uint8_t maclen; /*!<  MAC length              */
	unsigned char iv_enc[16]; /*!<  IV (encryption)         */
	unsigned char iv_dec[16]; /*!<  IV (decryption)         */
	unsigned char in_ctr[8];
	unsigned char out_ctr[8];
	unsigned char *enc_hmac;
	unsigned char *dec_hmac;
	const jhd_tls_md_info_t *md_info;
	const jhd_tls_cipher_info_t *cipher_info;
	void *enc_ctx;
	void *dec_ctx;

	/*
	 * Record layer (incoming data)
	 */
	unsigned char *in_hdr; /*!< start of record header           */
	unsigned char *in_iv; /*!< ivlen-byte IV                    */
	unsigned char *in_msg; /*!< message contents (in_iv+ivlen)   */
	unsigned char *in_offt; /*!< read offset in application data  */


	uint16_t  in_msglen; /*!< record header: message length    */
	uint16_t  in_left; /*!< amount of data read so far       */
	int nb_zero; /*!< # of 0-length encrypted messages */
	/*
	 * Record layer (outgoing data)
	 */
	unsigned char *out_hdr; /*!< start of record header           */
	unsigned char *out_iv; /*!< ivlen-byte IV                    */
	unsigned char *out_msg; /*!< message contents (out_iv+ivlen)  */




	unsigned char *out_offt;


	uint16_t out_msglen; /*!< record header: message length    */

	const char *hostname; /*!< expected peer CN for verification
	 (and SNI if available)                 */
	const char *alpn_chosen; /*!<  negotiated protocol                   */

	jhd_tls_ssl_crypt_pt encrypt_func;
	jhd_tls_ssl_crypt_pt decrypt_func;

#if defined(JHD_LOG_LEVEL_NOTICE) || defined(JHD_LOG_ASSERT_ENABLE)
	const jhd_tls_ssl_ciphersuite_t *ciphersuite_info;
#endif
#if defined(JHD_LOG_LEVEL_DEBUG) || defined(JHD_LOG_ASSERT_ENABLE)
	int encrypt_then_mac;
	unsigned char dec_key[64];
	unsigned char enc_key[64];
#endif


};




/**
 * \brief               Return the name of the ciphersuite associated with the
 *                      given ID
 *
 * \param ciphersuite_id SSL ciphersuite ID
 *
 * \return              a string containing the ciphersuite name
 */
const char *jhd_tls_ssl_get_ciphersuite_name(const int ciphersuite_id);

/**
 * \brief               Return the ID of the ciphersuite associated with the
 *                      given name
 *
 * \param ciphersuite_name SSL ciphersuite name
 *
 * \return              the ID with the ciphersuite or 0 if not found
 */
int jhd_tls_ssl_get_ciphersuite_id(const char *ciphersuite_name);

#if !defined(JHD_TLS_INLINE)

/**
 * \brief          Initialize an SSL context
 *                 Just makes the context ready for jhd_tls_ssl_setup() or
 *                 jhd_tls_ssl_free()
 *
 * \param ssl      SSL context
 */
void jhd_tls_ssl_init(jhd_tls_ssl_context *ssl);
int jhd_tls_ssl_is_server_side(jhd_tls_ssl_context * ssl);
#else
#define jhd_tls_ssl_init(ssl) memset((void*)ssl,0,sizeof(jhd_tls_ssl_context))
#define jhd_tls_ssl_is_server_side(ssl) ((ssl)->conf->server_side)
#endif


int jhd_tls_ssl_context_alloc(jhd_tls_ssl_context **pssl,const jhd_tls_ssl_config *conf,jhd_event_t *ev);

#if !defined(JHD_TLS_INLINE)
/**
 * \brief          Set the current endpoint type
 *
 * \param conf     SSL configuration
 * \param endpoint must be JHD_TLS_SSL_IS_CLIENT or JHD_TLS_SSL_IS_SERVER
 */
void jhd_tls_ssl_conf_set_server_side(jhd_tls_ssl_config *conf, jhd_tls_bool server_side);
#else
#define jhd_tls_ssl_conf_set_server_side(conf,server_side)  ((jhd_tls_ssl_config *)conf)->server_side = ((server_side)?1:0)
#endif

/**
 * \brief          Set the verification callback (Optional).
 *
 *                 If set, the verify callback is called for each
 *                 certificate in the chain. For implementation
 *                 information, please see \c jhd_tls_x509_crt_verify()
 *
 * \param conf     SSL configuration
 * \param f_vrfy   verification function
 * \param p_vrfy   verification parameter
 */
void jhd_tls_ssl_conf_verify(jhd_tls_ssl_config *conf, int (*f_vrfy)(void *, jhd_tls_x509_crt *, int, uint32_t *), void *p_vrfy);




/**
 * \brief          Set own certificate chain and private key
 *
 * \note           own_cert should contain in order from the bottom up your
 *                 certificate chain. The top certificate (self-signed)
 *                 can be omitted.
 *
 * \note           On server, this function can be called multiple times to
 *                 provision more than one cert/key pair (eg one ECDSA, one
 *                 RSA with SHA-256, one RSA with SHA-1). An adequate
 *                 certificate will be selected according to the client's
 *                 advertised capabilities. In case mutliple certificates are
 *                 adequate, preference is given to the one set by the first
 *                 call to this function, then second, etc.
 *
 * \note           On client, only the first call has any effect. That is,
 *                 only one client certificate can be provisioned. The
 *                 server's preferences in its CertficateRequest message will
 *                 be ignored and our only cert will be sent regardless of
 *                 whether it matches those preferences - the server can then
 *                 decide what it wants to do with it.
 *
 * \param conf     SSL configuration
 * \param own_cert own public certificate chain
 * \param pk_key   own private key
 *
 * \return         0 on success or JHD_TLS_ERR_SSL_ALLOC_FAILED
 */
int jhd_tls_ssl_conf_own_cert(jhd_tls_ssl_config *conf, jhd_tls_x509_crt *own_cert, jhd_tls_pk_context *pk_key);


/**
 * \brief          Set or reset the hostname to check against the received
 *                 server certificate. It sets the ServerName TLS extension,
 *                 too, if that extension is enabled. (client-side only)
 *
 * \param ssl      SSL context
 * \param hostname the server hostname, may be NULL to clear hostname

 * \note           Maximum hostname length JHD_TLS_SSL_MAX_HOST_NAME_LEN.
 *
 * \return         0 if successful, JHD_TLS_ERR_SSL_ALLOC_FAILED on
 *                 allocation failure, JHD_TLS_ERR_SSL_BAD_INPUT_DATA on
 *                 too long input hostname.
 *
 *                 Hostname set to the one provided on success (cleared
 *                 when NULL). On allocation failure hostname is cleared.
 *                 On too long input failure, old hostname is unchanged.
 */
int jhd_tls_ssl_set_hostname(jhd_tls_ssl_context *ssl, const char *hostname);

/**
 * \brief          Set server side ServerName TLS extension callback
 *                 (optional, server-side only).
 *
 *                 If set, the ServerName callback is called whenever the
 *                 server receives a ServerName TLS extension from the client
 *                 during a handshake. The ServerName callback has the
 *                 following parameters: (void *parameter, jhd_tls_ssl_context *ssl,
 *                 const unsigned char *hostname, size_t len). If a suitable
 *                 certificate is found, the callback must set the
 *                 certificate(s) and key(s) to use with \c
 *                 jhd_tls_ssl_set_hs_own_cert() (can be called repeatedly),
 *                 and may optionally adjust the CA and associated CRL with \c
 *                 jhd_tls_ssl_set_hs_ca_chain() as well as the client
 *                 authentication mode with \c jhd_tls_ssl_set_hs_authmode(),
 *                 then must return 0. If no matching name is found, the
 *                 callback must either set a default cert, or
 *                 return non-zero to abort the handshake at this point.
 *
 * \param conf     SSL configuration
 * \param f_sni    verification function
 * \param p_sni    verification parameter
 */
void jhd_tls_ssl_conf_sni(jhd_tls_ssl_config *conf, int (*f_sni)(void *, jhd_tls_ssl_context *, const unsigned char *, size_t), void *p_sni);

/**
 * \brief          Set the supported Application Layer Protocols.
 *
 * \param conf     SSL configuration
 * \param protos   Pointer to a NULL-terminated list of supported protocols,
 *                 in decreasing preference order. The pointer to the list is
 *                 recorded by the library for later reference as required, so
 *                 the lifetime of the table must be atleast as long as the
 *                 lifetime of the SSL configuration structure.
 *
 * \return         0 on success, or JHD_TLS_ERR_SSL_BAD_INPUT_DATA.
 */
int jhd_tls_ssl_conf_alpn_protocols(jhd_tls_ssl_config *conf, const char **protos);

/**
 * \brief          Get the name of the negotiated Application Layer Protocol.
 *                 This function should be called after the handshake is
 *                 completed.
 *
 * \param ssl      SSL context
 *
 * \return         Protcol name, or NULL if no protocol was negotiated.
 */
const char *jhd_tls_ssl_get_alpn_protocol(const jhd_tls_ssl_context *ssl);

/**
 * \brief          Set the maximum fragment length to emit and/or negotiate
 *                 (Default: JHD_TLS_SSL_MAX_CONTENT_LEN, usually 2^14 bytes)
 *                 (Server: set maximum fragment length to emit,
 *                 usually negotiated by the client during handshake
 *                 (Client: set maximum fragment length to emit *and*
 *                 negotiate with the server during handshake)
 *
 * \param conf     SSL configuration
 * \param mfl_code Code for maximum fragment length (allowed values:
 *                 JHD_TLS_SSL_MAX_FRAG_LEN_512,  JHD_TLS_SSL_MAX_FRAG_LEN_1024,
 *                 JHD_TLS_SSL_MAX_FRAG_LEN_2048, JHD_TLS_SSL_MAX_FRAG_LEN_4096)
 *
 * \return         0 if successful or JHD_TLS_ERR_SSL_BAD_INPUT_DATA
 */
int jhd_tls_ssl_conf_max_frag_len(jhd_tls_ssl_config *conf, unsigned char mfl_code);

void jhd_tls_tls1_prf(const unsigned char *secret, size_t slen, const char *label, const unsigned char *random, size_t rlen, unsigned char *dstbuf, size_t dlen) ;
/**
 * \brief          Return the number of application data bytes
 *                 remaining to be read from the current record.
 *
 * \param ssl      SSL context
 *
 * \return         How many bytes are available in the application
 *                 data record read buffer.
 *
 * \note           When working over a datagram transport, this is
 *                 useful to detect the current datagram's boundary
 *                 in case \c jhd_tls_ssl_read has written the maximal
 *                 amount of data fitting into the input buffer.
 *
 */
size_t jhd_tls_ssl_get_bytes_avail(const jhd_tls_ssl_context *ssl);


/**
 * \brief          Return the current SSL version (SSLv3/TLSv1/etc)
 *
 * \param ssl      SSL context
 *
 * \return         a string containing the SSL version
 */
const char *jhd_tls_ssl_get_version(const jhd_tls_ssl_context *ssl);


/**
 * \brief          Return the maximum fragment length (payload, in bytes).
 *                 This is the value negotiated with peer if any,
 *                 or the locally configured value.
 *
 * \note           With DTLS, \c jhd_tls_ssl_write() will return an error if
 *                 called with a larger length value.
 *                 With TLS, \c jhd_tls_ssl_write() will fragment the input if
 *                 necessary and return the number of bytes written; it is up
 *                 to the caller to call \c jhd_tls_ssl_write() again in
 *                 order to send the remaining bytes if any.
 *
 * \param ssl      SSL context
 *
 * \return         Current maximum fragment length.
 */
size_t jhd_tls_ssl_get_max_frag_len(const jhd_tls_ssl_context *ssl);

/**
 * \brief          Read at most 'len' application data bytes
 *
 * \param ssl      SSL context
 * \param buf      buffer that will hold the data
 * \param len      maximum number of bytes to read
 *
 * \return         One of the following:
 *                 - 0 if the read end of the underlying transport was closed,
 *                 - the (positive) number of bytes read, or
 *                 - a negative error code on failure.
 *
 *                 If JHD_TLS_ERR_SSL_WANT_READ is returned, no application data
 *                 is available from the underlying transport. In this case,
 *                 the function needs to be called again at some later stage.
 *
 *                 If JHD_TLS_ERR_SSL_WANT_WRITE is returned, a write is pending
 *                 but the underlying transport isn't available for writing. In this
 *                 case, the function needs to be called again at some later stage.
 *
 *                 When this function return JHD_TLS_ERR_SSL_CLIENT_RECONNECT
 *                 (which can only happen server-side), it means that a client
 *                 is initiating a new connection using the same source port.
 *                 You can either treat that as a connection close and wait
 *                 for the client to resend a ClientHello, or directly
 *                 continue with \c jhd_tls_ssl_handshake() with the same
 *                 context (as it has beeen reset internally). Either way, you
 *                 should make sure this is seen by the application as a new
 *                 connection: application state, if any, should be reset, and
 *                 most importantly the identity of the client must be checked
 *                 again. WARNING: not validating the identity of the client
 *                 again, or not transmitting the new identity to the
 *                 application layer, would allow authentication bypass!
 *
 * \note           If this function returns something other than a positive value
 *                 or JHD_TLS_ERR_SSL_WANT_READ/WRITE or JHD_TLS_ERR_SSL_CLIENT_RECONNECT,
 *                 you must stop using the SSL context for reading or writing,
 *                 and either free it or call \c jhd_tls_ssl_session_reset() on it
 *                 before re-using it for a new connection; the current connection
 *                 must be closed.
 *
 * \note           Remarks regarding event-driven DTLS:
 *                 - If the function returns JHD_TLS_ERR_SSL_WANT_READ, no datagram
 *                   from the underlying transport layer is currently being processed,
 *                   and it is safe to idle until the timer or the underlying transport
 *                   signal a new event.
 *                 - This function may return JHD_TLS_ERR_SSL_WANT_READ even if data was
 *                   initially available on the underlying transport, as this data may have
 *                   been only e.g. duplicated messages or a renegotiation request.
 *                   Therefore, you must be prepared to receive JHD_TLS_ERR_SSL_WANT_READ even
 *                   when reacting to an incoming-data event from the underlying transport.
 *                 - On success, the datagram of the underlying transport that is currently
 *                   being processed may contain further DTLS records. You should call
 *                   \c jhd_tls_ssl_check_pending to check for remaining records.
 *
 */
ssize_t jhd_tls_ssl_read(jhd_connection_t *c, unsigned char *buf, size_t len);

/**
 * \brief          Try to write exactly 'len' application data bytes
 *
 * \warning        This function will do partial writes in some cases. If the
 *                 return value is non-negative but less than length, the
 *                 function must be called again with updated arguments:
 *                 buf + ret, len - ret (if ret is the return value) until
 *                 it returns a value equal to the last 'len' argument.
 *
 * \param ssl      SSL context
 * \param buf      buffer holding the data
 * \param len      how many bytes must be written
 *
 * \return         the number of bytes actually written (may be less than len),
 *                 or JHD_TLS_ERR_SSL_WANT_WRITE or JHD_TLS_ERR_SSL_WANT_READ,
 *                 or another negative error code.
 *
 * \note           If this function returns something other than a positive value
 *                 or JHD_TLS_ERR_SSL_WANT_READ/WRITE, you must stop using
 *                 the SSL context for reading or writing, and either free it or
 *                 call \c jhd_tls_ssl_session_reset() on it before re-using it
 *                 for a new connection; the current connection must be closed.
 *
 * \note           When this function returns JHD_TLS_ERR_SSL_WANT_WRITE/READ,
 *                 it must be called later with the *same* arguments,
 *                 until it returns a positive value. When the function returns
 *                 JHD_TLS_ERR_SSL_WANT_WRITE there may be some partial
 *                 data in the output buffer, however this is not yet sent.
 *
 * \note           If the requested length is greater than the maximum
 *                 fragment length (either the built-in limit or the one set
 *                 or negotiated with the peer), then:
 *                 - with TLS, less bytes than requested are written.
 *                 - with DTLS, JHD_TLS_ERR_SSL_BAD_INPUT_DATA is returned.
 *                 \c jhd_tls_ssl_get_max_frag_len() may be used to query the
 *                 active maximum fragment length.
 */
ssize_t jhd_tls_ssl_write(jhd_connection_t *c, unsigned char *buf, size_t len);

ssize_t jhd_tls_ssl_write_512(jhd_connection_t *c, unsigned char *buf, size_t len);
ssize_t jhd_tls_ssl_write_1024(jhd_connection_t *c, unsigned char *buf, size_t len);
ssize_t jhd_tls_ssl_write_2048(jhd_connection_t *c, unsigned char *buf, size_t len);
ssize_t jhd_tls_ssl_write_4096(jhd_connection_t *c, unsigned char *buf, size_t len);

/**
 * \brief           Send an alert message
 *
 * \param ssl       SSL context
 * \param level     The alert level of the message
 *                  (JHD_TLS_SSL_ALERT_LEVEL_WARNING or JHD_TLS_SSL_ALERT_LEVEL_FATAL)
 * \param message   The alert message (SSL_ALERT_MSG_*)
 *
 * \return          0 if successful, or a specific SSL error code.
 *
 * \note           If this function returns something other than 0 or
 *                 JHD_TLS_ERR_SSL_WANT_READ/WRITE, you must stop using
 *                 the SSL context for reading or writing, and either free it or
 *                 call \c jhd_tls_ssl_session_reset() on it before re-using it
 *                 for a new connection; the current connection must be closed.
 */
int jhd_tls_ssl_send_alert_message(jhd_connection_t  *c, unsigned char level, unsigned char message);
#if !defined(JHD_TLS_INLINE)
/**
 * \brief          Notify the peer that the connection is being closed
 *
 * \param ssl      SSL context
 *
 * \return          0 if successful, or a specific SSL error code.
 *
 * \note           If this function returns something other than 0 or
 *                 JHD_TLS_ERR_SSL_WANT_READ/WRITE, you must stop using
 *                 the SSL context for reading or writing, and either free it or
 *                 call \c jhd_tls_ssl_session_reset() on it before re-using it
 *                 for a new connection; the current connection must be closed.
 */
int jhd_tls_ssl_close_notify(jhd_connection_t *c);
#else
#define jhd_tls_ssl_close_notify(c)  ((((jhd_tls_ssl_context*)((c)->ssl))->state == JHD_TLS_SSL_HANDSHAKE_OVER)?jhd_tls_ssl_send_alert_message(c,JHD_TLS_SSL_ALERT_LEVEL_WARNING, JHD_TLS_SSL_ALERT_MSG_CLOSE_NOTIFY):JHD_OK)
#endif
/**
 * \brief          Free referenced items in an SSL context and clear memory
 *
 * \param ssl      SSL context
 */
void jhd_tls_ssl_free(jhd_tls_ssl_context *ssl);

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
void jhd_tls_ssl_config_init(jhd_tls_ssl_config *conf);
#else
#define jhd_tls_ssl_config_init(conf) memset( (void*)conf, 0, sizeof( jhd_tls_ssl_config ) )
#endif

/**
 * \brief          Load reasonnable default SSL configuration values.
 *                 (You need to call jhd_tls_ssl_config_init() first.)
 *
 * \param conf     SSL configuration context
 * \param endpoint JHD_TLS_SSL_IS_CLIENT or JHD_TLS_SSL_IS_SERVER
 *
 * \note           See \c jhd_tls_ssl_conf_transport() for notes on DTLS.
 *
 * \return         0 if successful, or
 *                 JHD_TLS_ERR_XXX_ALLOC_FAILED on memory allocation error.
 */
int jhd_tls_ssl_config_defaults(jhd_tls_ssl_config *conf, jhd_tls_bool server_side);

/**
 * \brief          Free an SSL configuration context
 *
 * \param conf     SSL configuration context
 */
void jhd_tls_ssl_config_free(jhd_tls_ssl_config *conf);

int jhd_tls_ssl_flush(jhd_connection_t *c,jhd_tls_ssl_context *ssl);


void jhd_tls_ssl_context_free(jhd_tls_ssl_context **pssl);









#define  JHD_TLS_SSL_READ_SSL_RECORD_CONTENT  																				\
	if(ssl->in_left < 5){																									\
		if ((ret = jhd_tls_ssl_fetch_input(c, 5/* ssl record header(5),+  handshark header(4) */)) != JHD_OK) {				\
			goto func_return;																								\
		}																													\
		if (ssl->in_hdr[0] != JHD_TLS_SSL_MSG_HANDSHAKE) {																	\
			log_err("invalid ssl record type:%u",ssl->in_hdr[0]);															\
			goto func_error;																								\
		}																													\
		ssl->in_msglen = (ssl->in_hdr[3] << 8) | ssl->in_hdr[4];															\
		if (ssl->in_msglen > JHD_TLS_SSL_MAX_CONTENT_LEN) {																	\
			log_err( "invalid ssl record  length:%u",ssl->in_msglen);														\
			goto func_error;																								\
		}																													\
		log_debug("read ssl record legth:%u",ssl->in_msglen);																\
	}else{																													\
		ssl->in_msglen = (ssl->in_hdr[3] << 8) | ssl->in_hdr[4];															\
	}																														\
	if ((ret = jhd_tls_ssl_fetch_input(c, 5 + ssl->in_msglen)) != JHD_OK) {													\
		ssl->in_msglen = 0 ;																								\
		goto func_return;																									\
	}																														\
	log_buf_debug("readed ssl record===>",ssl->in_hdr,ssl->in_msglen+5);																	\
	ssl->in_left = 0;

#define JHD_TLS_SSL_SET_SSL_RECORD(ssl,mt,len)    				\
		(ssl)->out_hdr[0] = mt;									\
		(ssl)->out_hdr[1] = (ssl)->major_ver;					\
		(ssl)->out_hdr[2] = (ssl)->minor_ver;					\
		(ssl)->out_hdr[3] = (unsigned char) ((len) >> 8);		\
		(ssl)->out_hdr[4] = (unsigned char) (len);				\
		log_debug("write ssl record(%02X,%02X,%02X,%02X,%02X)",(ssl)->out_hdr[0],(ssl)->out_hdr[1],(ssl)->out_hdr[2],(ssl)->out_hdr[3],(ssl)->out_hdr[4]);

#define JHD_TLS_SSL_SET_HANDSHAKE(ssl,mt,len)    				\
		(ssl)->out_msg[0] = mt;									\
		(ssl)->out_msg[1] = (unsigned char) (0);				\
		(ssl)->out_msg[2] = (unsigned char) ((len) >> 8);		\
		(ssl)->out_msg[3] = (unsigned char) (len);	    		\
		(ssl)->handshake->update_checksum(ssl, (ssl)->out_msg,len + 4);\
		log_debug("write ssl handshake(%02X,%02X,%02X,%02X)",(ssl)->out_msg[0],(ssl)->out_msg[1],(ssl)->out_msg[2],(ssl)->out_msg[3]);


extern int jhd_tls_ssl_preset_default_hashes[];

#endif /* ssl.h */

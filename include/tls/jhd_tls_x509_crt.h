#ifndef JHD_TLS_X509_CRT_H
#define JHD_TLS_X509_CRT_H

#include <tls/jhd_tls_config.h>
#include <tls/jhd_tls_x509.h>
#include <tls/jhd_tls_md.h>
/**
 * \addtogroup x509_module
 * \{
 */

/**
 * \name Structures and functions for parsing and writing X.509 certificates
 * \{
 */

/**
 * Container for an X.509 certificate. The certificate may be chained.
 */
typedef struct jhd_tls_x509_crt {
	jhd_tls_x509_buf raw; /**< The raw certificate data (DER). */
	jhd_tls_x509_buf tbs; /**< The raw certificate body (DER). The part that is To Be Signed. */

	int version; /**< The X.509 version. (1=v1, 2=v2, 3=v3) */
	jhd_tls_x509_buf serial; /**< Unique id for certificate issued by a specific CA. */
	jhd_tls_x509_buf sig_oid; /**< Signature algorithm, e.g. sha1RSA */

	jhd_tls_x509_buf issuer_raw; /**< The raw issuer data (DER). Used for quick comparison. */
	jhd_tls_x509_buf subject_raw; /**< The raw subject data (DER). Used for quick comparison. */

	jhd_tls_x509_name issuer; /**< The parsed issuer data (named information object). */
	jhd_tls_x509_name subject; /**< The parsed subject data (named information object). */

	jhd_tls_x509_time valid_from; /**< Start time of certificate validity. */
	jhd_tls_x509_time valid_to; /**< End time of certificate validity. */

	jhd_tls_pk_context pk; /**< Container for the public key context. */

	jhd_tls_x509_buf issuer_id; /**< Optional X.509 v2/v3 issuer unique identifier. */
	jhd_tls_x509_buf subject_id; /**< Optional X.509 v2/v3 subject unique identifier. */
	jhd_tls_x509_buf v3_ext; /**< Optional X.509 v3 extensions.  */
	jhd_tls_x509_sequence subject_alt_names; /**< Optional list of Subject Alternative Names (Only dNSName supported). */

	int ext_types; /**< Bit string containing detected and parsed extensions */
	int ca_istrue; /**< Optional Basic Constraint extension value: 1 if this certificate belongs to a CA, 0 otherwise. */
	int max_pathlen; /**< Optional Basic Constraint extension value: The maximum path length to the root certificate. Path length is 1 higher than RFC 5280 'meaning', so 1+ */

	unsigned int key_usage; /**< Optional key usage extension value: See the values in x509.h */

	jhd_tls_x509_sequence ext_key_usage; /**< Optional list of extended key usage OIDs. */

	unsigned char ns_cert_type; /**< Optional Netscape certificate type extension value: See the values in x509.h */

	jhd_tls_x509_buf sig; /**< Signature: hash of the tbs part signed with the private key. */
	const jhd_tls_md_info_t *sig_md; /**< Internal representation of the MD algorithm of the signature algorithm, e.g. JHD_TLS_MD_SHA256 */
	const jhd_tls_pk_info_t *sig_pk; /**< Internal representation of the Public Key algorithm of the signature algorithm, e.g. JHD_TLS_PK_RSA */
//	void *sig_opts; /**< Signature options to be passed to jhd_tls_pk_verify_ext(), e.g. for RSASSA-PSS */

	struct jhd_tls_x509_crt *next; /**< Next certificate in the CA-chain. */
} jhd_tls_x509_crt;

/**
 * Build flag from an algorithm/curve identifier (pk, md, ecp)
 * Since 0 is always XXX_NONE, ignore it.
 */
#define JHD_TLS_X509_ID_FLAG( id )   ( 1 << ( id - 1 ) )

/**
 * Security profile for certificate verification.
 *
 * All lists are bitfields, built by ORing flags from JHD_TLS_X509_ID_FLAG().
 */
typedef struct {
	uint32_t allowed_mds; /**< MDs for signatures         */
	uint32_t allowed_pks; /**< PK algs for signatures     */
	uint32_t allowed_curves; /**< Elliptic curves for ECDSA  */
	uint32_t rsa_min_bitlen; /**< Minimum size for RSA keys  */
} jhd_tls_x509_crt_profile;

#define JHD_TLS_X509_CRT_VERSION_1              0
#define JHD_TLS_X509_CRT_VERSION_2              1
#define JHD_TLS_X509_CRT_VERSION_3              2

#define JHD_TLS_X509_RFC5280_MAX_SERIAL_LEN 32
#define JHD_TLS_X509_RFC5280_UTC_TIME_LEN   15

#if !defined( JHD_TLS_X509_MAX_FILE_PATH_LEN )
#define JHD_TLS_X509_MAX_FILE_PATH_LEN 512
#endif

/**
 * Container for writing a certificate (CRT)
 */
typedef struct jhd_tls_x509write_cert {
	int version;
	jhd_tls_mpi serial;
	jhd_tls_pk_context *subject_key;
	jhd_tls_pk_context *issuer_key;
	jhd_tls_asn1_named_data *subject;
	jhd_tls_asn1_named_data *issuer;
	jhd_tls_md_info_t *md_info;
	char not_before[JHD_TLS_X509_RFC5280_UTC_TIME_LEN + 1];
	char not_after[JHD_TLS_X509_RFC5280_UTC_TIME_LEN + 1];
	jhd_tls_asn1_named_data *extensions;
} jhd_tls_x509write_cert;


/**
 * Default security profile. Should provide a good balance between security
 * and compatibility with current deployments.
 */
extern const jhd_tls_x509_crt_profile jhd_tls_x509_crt_profile_default;

/**
 * Expected next default profile. Recommended for new deployments.
 * Currently targets a 128-bit security level, except for RSA-2048.
 */
extern const jhd_tls_x509_crt_profile jhd_tls_x509_crt_profile_next;

/**
 * NSA Suite B profile.
 */
extern const jhd_tls_x509_crt_profile jhd_tls_x509_crt_profile_suiteb;

/**
 * \brief          Parse a single DER formatted certificate and add it
 *                 to the chained list.
 *
 * \param chain    points to the start of the chain
 * \param buf      buffer holding the certificate DER data
 * \param buflen   size of the buffer
 *
 * \return         0 if successful, or a specific X509 or PEM error code
 */
int jhd_tls_x509_crt_parse_der(jhd_tls_x509_crt *chain, const unsigned char *buf, size_t buflen,void *event);

jhd_tls_x509_crt * jhd_tls_x509_crt_parse(const unsigned char *buf, size_t buflen);



/**
 * \brief          Returns an informational string about the
 *                 certificate.
 *
 * \param buf      Buffer to write to
 * \param size     Maximum size of buffer
 * \param prefix   A line prefix
 * \param crt      The X509 certificate to represent
 *
 * \return         The length of the string written (not including the
 *                 terminated nul byte), or a negative error code.
 */
int jhd_tls_x509_crt_info(char *buf, size_t size, const char *prefix, const jhd_tls_x509_crt *crt);

/**
 * \brief          Returns an informational string about the
 *                 verification status of a certificate.
 *
 * \param buf      Buffer to write to
 * \param size     Maximum size of buffer
 * \param prefix   A line prefix
 * \param flags    Verification flags created by jhd_tls_x509_crt_verify()
 *
 * \return         The length of the string written (not including the
 *                 terminated nul byte), or a negative error code.
 */
int jhd_tls_x509_crt_verify_info(char *buf, size_t size, const char *prefix, uint32_t flags);

///**
// * \brief          Verify the certificate signature
// *
// *                 The verify callback is a user-supplied callback that
// *                 can clear / modify / add flags for a certificate. If set,
// *                 the verification callback is called for each
// *                 certificate in the chain (from the trust-ca down to the
// *                 presented crt). The parameters for the callback are:
// *                 (void *parameter, jhd_tls_x509_crt *crt, int certificate_depth,
// *                 int *flags). With the flags representing current flags for
// *                 that specific certificate and the certificate depth from
// *                 the bottom (Peer cert depth = 0).
// *
// *                 All flags left after returning from the callback
// *                 are also returned to the application. The function should
// *                 return 0 for anything (including invalid certificates)
// *                 other than fatal error, as a non-zero return code
// *                 immediately aborts the verification process. For fatal
// *                 errors, a specific error code should be used (different
// *                 from JHD_TLS_ERR_X509_CERT_VERIFY_FAILED which should not
// *                 be returned at this point), or JHD_TLS_ERR_X509_FATAL_ERROR
// *                 can be used if no better code is available.
// *
// * \note           In case verification failed, the results can be displayed
// *                 using \c jhd_tls_x509_crt_verify_info()
// *
// * \note           Same as \c jhd_tls_x509_crt_verify_with_profile() with the
// *                 default security profile.
// *
// * \note           It is your responsibility to provide up-to-date CRLs for
// *                 all trusted CAs. If no CRL is provided for the CA that was
// *                 used to sign the certificate, CRL verification is skipped
// *                 silently, that is *without* setting any flag.
// *
// * \note           The \c trust_ca list can contain two types of certificates:
// *                 (1) those of trusted root CAs, so that certificates
// *                 chaining up to those CAs will be trusted, and (2)
// *                 self-signed end-entity certificates to be trusted (for
// *                 specific peers you know) - in that case, the self-signed
// *                 certificate doesn't need to have the CA bit set.
// *
// * \param crt      a certificate (chain) to be verified
// * \param trust_ca the list of trusted CAs (see note above)
// * \param ca_crl   the list of CRLs for trusted CAs (see note above)
// * \param cn       expected Common Name (can be set to
// *                 NULL if the CN must not be verified)
// * \param flags    result of the verification
// * \param f_vrfy   verification function
// * \param p_vrfy   verification parameter
// *
// * \return         0 (and flags set to 0) if the chain was verified and valid,
// *                 JHD_TLS_ERR_X509_CERT_VERIFY_FAILED if the chain was verified
// *                 but found to be invalid, in which case *flags will have one
// *                 or more JHD_TLS_X509_BADCERT_XXX or JHD_TLS_X509_BADCRL_XXX
// *                 flags set, or another error (and flags set to 0xffffffff)
// *                 in case of a fatal error encountered during the
// *                 verification process.
// */
//int jhd_tls_x509_crt_verify(jhd_tls_x509_crt *crt, jhd_tls_x509_crt *trust_ca, uint32_t *flags);
//
///**
// * \brief          Verify the certificate signature according to profile
// *
// * \note           Same as \c jhd_tls_x509_crt_verify(), but with explicit
// *                 security profile.
// *
// * \note           The restrictions on keys (RSA minimum size, allowed curves
// *                 for ECDSA) apply to all certificates: trusted root,
// *                 intermediate CAs if any, and end entity certificate.
// *
// * \param crt      a certificate (chain) to be verified
// * \param trust_ca the list of trusted CAs
// * \param ca_crl   the list of CRLs for trusted CAs
// * \param profile  security profile for verification
// * \param cn       expected Common Name (can be set to
// *                 NULL if the CN must not be verified)
// * \param flags    result of the verification
// * \param f_vrfy   verification function
// * \param p_vrfy   verification parameter
// *
// * \return         0 if successful or JHD_TLS_ERR_X509_CERT_VERIFY_FAILED
// *                 in which case *flags will have one or more
// *                 JHD_TLS_X509_BADCERT_XXX or JHD_TLS_X509_BADCRL_XXX flags
// *                 set,
// *                 or another error in case of a fatal error encountered
// *                 during the verification process.
// */
//int jhd_tls_x509_crt_verify_with_profile(jhd_tls_x509_crt *crt, jhd_tls_x509_crt *trust_ca,const jhd_tls_x509_crt_profile *profile,uint32_t *flags);


/**
 * \brief          Check usage of certificate against keyUsage extension.
 *
 * \param crt      Leaf certificate used.
 * \param usage    Intended usage(s) (eg JHD_TLS_X509_KU_KEY_ENCIPHERMENT
 *                 before using the certificate to perform an RSA key
 *                 exchange).
 *
 * \note           Except for decipherOnly and encipherOnly, a bit set in the
 *                 usage argument means this bit MUST be set in the
 *                 certificate. For decipherOnly and encipherOnly, it means
 *                 that bit MAY be set.
 *
 * \return         0 is these uses of the certificate are allowed,
 *                 JHD_TLS_ERR_X509_BAD_INPUT_DATA if the keyUsage extension
 *                 is present but does not match the usage argument.
 *
 * \note           You should only call this function on leaf certificates, on
 *                 (intermediate) CAs the keyUsage extension is automatically
 *                 checked by \c jhd_tls_x509_crt_verify().
 */
int jhd_tls_x509_crt_check_key_usage(const jhd_tls_x509_crt *crt, unsigned int usage);



/**
 * \brief           Check usage of certificate against extendedKeyUsage.
 *
 * \param crt       Leaf certificate used.
 * \param usage_oid Intended usage (eg JHD_TLS_OID_SERVER_AUTH or
 *                  JHD_TLS_OID_CLIENT_AUTH).
 * \param usage_len Length of usage_oid (eg given by JHD_TLS_OID_SIZE()).
 *
 * \return          0 if this use of the certificate is allowed,
 *                  JHD_TLS_ERR_X509_BAD_INPUT_DATA if not.
 *
 * \note            Usually only makes sense on leaf certificates.
 */
int jhd_tls_x509_crt_check_extended_key_usage(const jhd_tls_x509_crt *crt, const char *usage_oid, size_t usage_len);
int jhd_tls_x509_crt_verify_name(const jhd_tls_x509_crt *crt, const unsigned char *hostname,size_t len);


#if !defined(JHD_TLS_INLINE)
/**
 * \brief          Initialize a certificate (chain)
 *
 * \param crt      Certificate chain to initialize
 */
void jhd_tls_x509_crt_init(jhd_tls_x509_crt *crt);
#else
#define jhd_tls_x509_crt_init(crt) memset((void*)crt,0,sizeof(jhd_tls_x509_crt))
#endif

/**
 * \brief          Unallocate all certificate data
 *
 * \param crt      Certificate chain to free
 */
void jhd_tls_x509_crt_free(jhd_tls_x509_crt *crt);
void jhd_tls_x509_crt_free_by_master(jhd_tls_x509_crt *crt);

/* \} name */
/* \} addtogroup x509_module */

#endif /* jhd_tls_x509_crt.h */

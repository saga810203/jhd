#ifndef JHD_TLS_ECDSA_H
#define JHD_TLS_ECDSA_H

#include <tls/jhd_tls_ecp.h>
#include <tls/jhd_tls_md.h>

/*
 * RFC-4492 page 20:
 *
 *     Ecdsa-Sig-Value ::= SEQUENCE {
 *         r       INTEGER,
 *         s       INTEGER
 *     }
 *
 * Size is at most
 *    1 (tag) + 1 (len) + 1 (initial 0) + ECP_MAX_BYTES for each of r and s,
 *    twice that + 1 (tag) + 2 (len) for the sequence
 * (assuming ECP_MAX_BYTES is less than 126 for r and s,
 * and less than 124 (total len <= 255) for the sequence)
 */
#if JHD_TLS_ECP_MAX_BYTES > 124
#error "JHD_TLS_ECP_MAX_BYTES bigger than expected, please fix JHD_TLS_ECDSA_MAX_LEN"
#endif
/** The maximal size of an ECDSA signature in Bytes. */
#define JHD_TLS_ECDSA_MAX_LEN  ( 3 + 2 * ( 3 + JHD_TLS_ECP_MAX_BYTES ) )
#define JHD_TLS_ECDSA_ENCODE_CTX_LEN 1016
/**
 * \brief           The ECDSA context structure.
 */
//typedef jhd_tls_ecp_keypair jhd_tls_ecdsa_context;
typedef struct{
		jhd_tls_ecp_group *grp; /*!<  Elliptic curve and base point     */
		char encode_ctx[1016];
} jhd_tls_ecdsa_context;


///**
// * \brief           This function computes the ECDSA signature of a
// *                  previously-hashed message.
// *
// * \note            The deterministic version is usually preferred.
// *
// * \note            If the bitlength of the message hash is larger than the
// *                  bitlength of the group order, then the hash is truncated
// *                  as defined in <em>Standards for Efficient Cryptography Group
// *                  (SECG): SEC1 Elliptic Curve Cryptography</em>, section
// *                  4.1.3, step 5.
// *
// * \see             ecp.h
// *
// * \param grp       The ECP group.
// * \param r         The first output integer.
// * \param s         The second output integer.
// * \param d         The private signing key.
// * \param buf       The message hash.
// * \param blen      The length of \p buf.
// * \param f_rng     The RNG function.
// * \param p_rng     The RNG context.
// *
// * \return          \c 0 on success.
// * \return          An \c JHD_TLS_ERR_ECP_XXX
// *                  or \c JHD_TLS_MPI_XXX error code on failure.
// */
//int jhd_tls_ecdsa_sign(jhd_tls_ecp_group *grp, jhd_tls_mpi *r, jhd_tls_mpi *s, const jhd_tls_mpi *d, const unsigned char *buf, size_t blen,jhd_tls_md_type_t md_alg);




/**
 * \brief           This function computes the ECDSA signature of a
 *                  previously-hashed message, deterministic version.
 *
 *                  For more information, see <em>RFC-6979: Deterministic
 *                  Usage of the Digital Signature Algorithm (DSA) and Elliptic
 *                  Curve Digital Signature Algorithm (ECDSA)</em>.
 *
 * \note            If the bitlength of the message hash is larger than the
 *                  bitlength of the group order, then the hash is truncated as
 *                  defined in <em>Standards for Efficient Cryptography Group
 *                  (SECG): SEC1 Elliptic Curve Cryptography</em>, section
 *                  4.1.3, step 5.
 *
 * \see             ecp.h
 *
 * \param grp       The ECP group.
 * \param r         The first output integer.
 * \param s         The second output integer.
 * \param d         The private signing key.
 * \param buf       The message hash.
 * \param blen      The length of \p buf.
 * \param md_alg    The MD algorithm used to hash the message.
 *
 * \return          \c 0 on success.
 * \return          An \c JHD_TLS_ERR_ECP_XXX or \c JHD_TLS_MPI_XXX
 *                  error code on failure.
 */
int jhd_tls_ecdsa_sign_det(jhd_tls_ecp_group *grp, jhd_tls_mpi *r, jhd_tls_mpi *s, const jhd_tls_mpi *d, const unsigned char *buf, size_t blen,
		const jhd_tls_md_info_t *md_info);


/**
 * \brief           This function verifies the ECDSA signature of a
 *                  previously-hashed message.
 *
 * \note            If the bitlength of the message hash is larger than the
 *                  bitlength of the group order, then the hash is truncated as
 *                  defined in <em>Standards for Efficient Cryptography Group
 *                  (SECG): SEC1 Elliptic Curve Cryptography</em>, section
 *                  4.1.4, step 3.
 *
 * \see             ecp.h
 *
 * \param grp       The ECP group.
 * \param buf       The message hash.
 * \param blen      The length of \p buf.
 * \param Q         The public key to use for verification.
 * \param r         The first integer of the signature.
 * \param s         The second integer of the signature.
 *
 * \return          \c 0 on success.
 * \return          #JHD_TLS_ERR_ECP_BAD_INPUT_DATA if the signature
 *                  is invalid.
 * \return          An \c JHD_TLS_ERR_ECP_XXX or \c JHD_TLS_MPI_XXX
 *                  error code on failure for any other reason.
 */
int jhd_tls_ecdsa_verify(jhd_tls_ecp_group *grp, const unsigned char *buf, size_t blen, const jhd_tls_ecp_point *Q, const jhd_tls_mpi *r, const jhd_tls_mpi *s);

/**
 * \brief           This function computes the ECDSA signature and writes it
 *                  to a buffer, serialized as defined in <em>RFC-4492:
 *                  Elliptic Curve Cryptography (ECC) Cipher Suites for
 *                  Transport Layer Security (TLS)</em>.
 *
 * \warning         It is not thread-safe to use the same context in
 *                  multiple threads.
 *
 * \note            The deterministic version is used if
 *                  #JHD_TLS_ECDSA_DETERMINISTIC is defined. For more
 *                  information, see <em>RFC-6979: Deterministic Usage
 *                  of the Digital Signature Algorithm (DSA) and Elliptic
 *                  Curve Digital Signature Algorithm (ECDSA)</em>.
 *
 * \note            The \p sig buffer must be at least twice as large as the
 *                  size of the curve used, plus 9. For example, 73 Bytes if
 *                  a 256-bit curve is used. A buffer length of
 *                  #JHD_TLS_ECDSA_MAX_LEN is always safe.
 *
 * \note            If the bitlength of the message hash is larger than the
 *                  bitlength of the group order, then the hash is truncated as
 *                  defined in <em>Standards for Efficient Cryptography Group
 *                  (SECG): SEC1 Elliptic Curve Cryptography</em>, section
 *                  4.1.3, step 5.
 *
 * \see             ecp.h
 *
 * \param ctx       The ECDSA context.
 * \param md_alg    The message digest that was used to hash the message.
 * \param hash      The message hash.
 * \param hlen      The length of the hash.
 * \param sig       The buffer that holds the signature.
 * \param slen      The length of the signature written.
 * \param f_rng     The RNG function.
 * \param p_rng     The RNG context.
 *
 * \return          \c 0 on success.
 * \return          An \c JHD_TLS_ERR_ECP_XXX, \c JHD_TLS_ERR_MPI_XXX or
 *                  \c JHD_TLS_ERR_ASN1_XXX error code on failure.
 */
int jhd_tls_ecdsa_write_signature(void *ctx, const jhd_tls_md_info_t *md_info, const unsigned char *hash, size_t hlen, unsigned char *sig,
        size_t *slen);

/**
 * \brief           This function reads and verifies an ECDSA signature.
 *
 * \note            If the bitlength of the message hash is larger than the
 *                  bitlength of the group order, then the hash is truncated as
 *                  defined in <em>Standards for Efficient Cryptography Group
 *                  (SECG): SEC1 Elliptic Curve Cryptography</em>, section
 *                  4.1.4, step 3.
 *
 * \see             ecp.h
 *
 * \param ctx       The ECDSA context.
 * \param hash      The message hash.
 * \param hlen      The size of the hash.
 * \param sig       The signature to read and verify.
 * \param slen      The size of \p sig.
 *
 * \return          \c 0 on success.
 * \return          #JHD_TLS_ERR_ECP_BAD_INPUT_DATA if signature is invalid.
 * \return          #JHD_TLS_ERR_ECP_SIG_LEN_MISMATCH if there is a valid
 *                  signature in \p sig, but its length is less than \p siglen.
 * \return          An \c JHD_TLS_ERR_ECP_XXX or \c JHD_TLS_ERR_MPI_XXX
 *                  error code on failure for any other reason.
 */
int jhd_tls_ecdsa_read_signature(void *ctx,const jhd_tls_md_info_t *md_info, const unsigned char *hash, size_t hlen, const unsigned char *sig, size_t slen);

/**
 * \brief          This function generates an ECDSA keypair on the given curve.
 *
 * \see            ecp.h
 *
 * \param ctx      The ECDSA context to store the keypair in.
 * \param gid      The elliptic curve to use. One of the various
 *                 \c JHD_TLS_ECP_DP_XXX macros depending on configuration.
 * \param f_rng    The RNG function.
 * \param p_rng    The RNG context.
 *
 * \return         \c 0 on success.
 * \return         An \c JHD_TLS_ERR_ECP_XXX code on failure.
 */
int jhd_tls_ecdsa_genkey(jhd_tls_ecdsa_context *ctx, jhd_tls_ecp_group_id gid);

/**
 * \brief           This function sets an ECDSA context from an EC key pair.
 *
 * \see             ecp.h
 *
 * \param ctx       The ECDSA context to set.
 * \param key       The EC key to use.
 *
 * \return          \c 0 on success.
 * \return          An \c JHD_TLS_ERR_ECP_XXX code on failure.
 */
int jhd_tls_ecdsa_from_keypair(jhd_tls_ecdsa_context *ctx, const jhd_tls_ecp_keypair *key);
int jhd_tls_ecdsa_to_keypair(const jhd_tls_ecdsa_context *ctx, jhd_tls_ecp_keypair *key);

///**
// * \brief           This function initializes an ECDSA context.
// *
// * \param ctx       The ECDSA context to initialize.
// */
//void jhd_tls_ecdsa_init(jhd_tls_ecdsa_context *ctx);
//
///**
// * \brief           This function frees an ECDSA context.
// *
// * \param ctx       The ECDSA context to free.
// */
//void jhd_tls_ecdsa_free(jhd_tls_ecdsa_context *ctx);
#ifdef JHD_LOG_LEVEL_INFO
int jhd_tls_ecdsa_context_check(const jhd_tls_ecdsa_context *ecdsa,jhd_tls_ecp_keypair *kp);
#endif
#endif /* ecdsa.h */

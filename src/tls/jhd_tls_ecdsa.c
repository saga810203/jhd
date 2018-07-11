/*
 *  Elliptic curve DSA
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

/*
 * References:
 *
 * SEC1 http://www.secg.org/index.php?action=secg,docs_secg
 */

#if !defined(JHD_TLS_CONFIG_FILE)
#include <tls/jhd_tls_config.h>
#else
#include JHD_TLS_CONFIG_FILE
#endif

#if defined(JHD_TLS_ECDSA_C)

#include <tls/jhd_tls_ecdsa.h>
#include <tls/jhd_tls_asn1write.h>

#include <string.h>

#if defined(JHD_TLS_ECDSA_DETERMINISTIC)
#include <tls/jhd_tls_hmac_drbg.h>
#endif

/*
 * Derive a suitable integer for group grp from a buffer of length len
 * SEC1 4.1.3 step 5 aka SEC1 4.1.4 step 3
 */
static int derive_mpi( const jhd_tls_ecp_group *grp, jhd_tls_mpi *x,
                       const unsigned char *buf, size_t blen )
{
    int ret;
    size_t n_size = ( grp->nbits + 7 ) / 8;
    size_t use_size = blen > n_size ? n_size : blen;

    JHD_TLS_MPI_CHK( jhd_tls_mpi_read_binary( x, buf, use_size ) );
    if( use_size * 8 > grp->nbits )
        JHD_TLS_MPI_CHK( jhd_tls_mpi_shift_r( x, use_size * 8 - grp->nbits ) );

    /* While at it, reduce modulo N */
    if( jhd_tls_mpi_cmp_mpi( x, &grp->N ) >= 0 )
        JHD_TLS_MPI_CHK( jhd_tls_mpi_sub_mpi( x, x, &grp->N ) );

cleanup:
    return( ret );
}

#if !defined(JHD_TLS_ECDSA_SIGN_ALT)
/*
 * Compute ECDSA signature of a hashed message (SEC1 4.1.3)
 * Obviously, compared to SEC1 4.1.3, we skip step 4 (hash message)
 */
int jhd_tls_ecdsa_sign( jhd_tls_ecp_group *grp, jhd_tls_mpi *r, jhd_tls_mpi *s,
                const jhd_tls_mpi *d, const unsigned char *buf, size_t blen,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    int ret, key_tries, sign_tries, blind_tries;
    jhd_tls_ecp_point R;
    jhd_tls_mpi k, e, t;

    /* Fail cleanly on curves such as Curve25519 that can't be used for ECDSA */
    if( grp->N.p == NULL )
        return( JHD_TLS_ERR_ECP_BAD_INPUT_DATA );

    /* Make sure d is in range 1..n-1 */
    if( jhd_tls_mpi_cmp_int( d, 1 ) < 0 || jhd_tls_mpi_cmp_mpi( d, &grp->N ) >= 0 )
        return( JHD_TLS_ERR_ECP_INVALID_KEY );

    jhd_tls_ecp_point_init( &R );
    jhd_tls_mpi_init( &k ); jhd_tls_mpi_init( &e ); jhd_tls_mpi_init( &t );

    sign_tries = 0;
    do
    {
        /*
         * Steps 1-3: generate a suitable ephemeral keypair
         * and set r = xR mod n
         */
        key_tries = 0;
        do
        {
            JHD_TLS_MPI_CHK( jhd_tls_ecp_gen_keypair( grp, &k, &R, f_rng, p_rng ) );
            JHD_TLS_MPI_CHK( jhd_tls_mpi_mod_mpi( r, &R.X, &grp->N ) );

            if( key_tries++ > 10 )
            {
                ret = JHD_TLS_ERR_ECP_RANDOM_FAILED;
                goto cleanup;
            }
        }
        while( jhd_tls_mpi_cmp_int( r, 0 ) == 0 );

        /*
         * Step 5: derive MPI from hashed message
         */
        JHD_TLS_MPI_CHK( derive_mpi( grp, &e, buf, blen ) );

        /*
         * Generate a random value to blind inv_mod in next step,
         * avoiding a potential timing leak.
         */
        blind_tries = 0;
        do
        {
            size_t n_size = ( grp->nbits + 7 ) / 8;
            JHD_TLS_MPI_CHK( jhd_tls_mpi_fill_random( &t, n_size, f_rng, p_rng ) );
            JHD_TLS_MPI_CHK( jhd_tls_mpi_shift_r( &t, 8 * n_size - grp->nbits ) );

            /* See jhd_tls_ecp_gen_keypair() */
            if( ++blind_tries > 30 )
                return( JHD_TLS_ERR_ECP_RANDOM_FAILED );
        }
        while( jhd_tls_mpi_cmp_int( &t, 1 ) < 0 ||
               jhd_tls_mpi_cmp_mpi( &t, &grp->N ) >= 0 );

        /*
         * Step 6: compute s = (e + r * d) / k = t (e + rd) / (kt) mod n
         */
        JHD_TLS_MPI_CHK( jhd_tls_mpi_mul_mpi( s, r, d ) );
        JHD_TLS_MPI_CHK( jhd_tls_mpi_add_mpi( &e, &e, s ) );
        JHD_TLS_MPI_CHK( jhd_tls_mpi_mul_mpi( &e, &e, &t ) );
        JHD_TLS_MPI_CHK( jhd_tls_mpi_mul_mpi( &k, &k, &t ) );
        JHD_TLS_MPI_CHK( jhd_tls_mpi_inv_mod( s, &k, &grp->N ) );
        JHD_TLS_MPI_CHK( jhd_tls_mpi_mul_mpi( s, s, &e ) );
        JHD_TLS_MPI_CHK( jhd_tls_mpi_mod_mpi( s, s, &grp->N ) );

        if( sign_tries++ > 10 )
        {
            ret = JHD_TLS_ERR_ECP_RANDOM_FAILED;
            goto cleanup;
        }
    }
    while( jhd_tls_mpi_cmp_int( s, 0 ) == 0 );

cleanup:
    jhd_tls_ecp_point_free( &R );
    jhd_tls_mpi_free( &k ); jhd_tls_mpi_free( &e ); jhd_tls_mpi_free( &t );

    return( ret );
}
#endif /* JHD_TLS_ECDSA_SIGN_ALT */

#if defined(JHD_TLS_ECDSA_DETERMINISTIC)
/*
 * Deterministic signature wrapper
 */
int jhd_tls_ecdsa_sign_det( jhd_tls_ecp_group *grp, jhd_tls_mpi *r, jhd_tls_mpi *s,
                    const jhd_tls_mpi *d, const unsigned char *buf, size_t blen,
                    jhd_tls_md_type_t md_alg )
{
    int ret;
    jhd_tls_hmac_drbg_context rng_ctx;
    unsigned char data[2 * JHD_TLS_ECP_MAX_BYTES];
    size_t grp_len = ( grp->nbits + 7 ) / 8;
    const jhd_tls_md_info_t *md_info;
    jhd_tls_mpi h;

    if( ( md_info = jhd_tls_md_info_from_type( md_alg ) ) == NULL )
        return( JHD_TLS_ERR_ECP_BAD_INPUT_DATA );

    jhd_tls_mpi_init( &h );
    jhd_tls_hmac_drbg_init( &rng_ctx );

    /* Use private key and message hash (reduced) to initialize HMAC_DRBG */
    JHD_TLS_MPI_CHK( jhd_tls_mpi_write_binary( d, data, grp_len ) );
    JHD_TLS_MPI_CHK( derive_mpi( grp, &h, buf, blen ) );
    JHD_TLS_MPI_CHK( jhd_tls_mpi_write_binary( &h, data + grp_len, grp_len ) );
    jhd_tls_hmac_drbg_seed_buf( &rng_ctx, md_info, data, 2 * grp_len );

    ret = jhd_tls_ecdsa_sign( grp, r, s, d, buf, blen,
                      jhd_tls_hmac_drbg_random, &rng_ctx );

cleanup:
    jhd_tls_hmac_drbg_free( &rng_ctx );
    jhd_tls_mpi_free( &h );

    return( ret );
}
#endif /* JHD_TLS_ECDSA_DETERMINISTIC */

#if !defined(JHD_TLS_ECDSA_VERIFY_ALT)
/*
 * Verify ECDSA signature of hashed message (SEC1 4.1.4)
 * Obviously, compared to SEC1 4.1.3, we skip step 2 (hash message)
 */
int jhd_tls_ecdsa_verify( jhd_tls_ecp_group *grp,
                  const unsigned char *buf, size_t blen,
                  const jhd_tls_ecp_point *Q, const jhd_tls_mpi *r, const jhd_tls_mpi *s)
{
    int ret;
    jhd_tls_mpi e, s_inv, u1, u2;
    jhd_tls_ecp_point R;

    jhd_tls_ecp_point_init( &R );
    jhd_tls_mpi_init( &e ); jhd_tls_mpi_init( &s_inv ); jhd_tls_mpi_init( &u1 ); jhd_tls_mpi_init( &u2 );

    /* Fail cleanly on curves such as Curve25519 that can't be used for ECDSA */
    if( grp->N.p == NULL )
        return( JHD_TLS_ERR_ECP_BAD_INPUT_DATA );

    /*
     * Step 1: make sure r and s are in range 1..n-1
     */
    if( jhd_tls_mpi_cmp_int( r, 1 ) < 0 || jhd_tls_mpi_cmp_mpi( r, &grp->N ) >= 0 ||
        jhd_tls_mpi_cmp_int( s, 1 ) < 0 || jhd_tls_mpi_cmp_mpi( s, &grp->N ) >= 0 )
    {
        ret = JHD_TLS_ERR_ECP_VERIFY_FAILED;
        goto cleanup;
    }

    /*
     * Additional precaution: make sure Q is valid
     */
    JHD_TLS_MPI_CHK( jhd_tls_ecp_check_pubkey( grp, Q ) );

    /*
     * Step 3: derive MPI from hashed message
     */
    JHD_TLS_MPI_CHK( derive_mpi( grp, &e, buf, blen ) );

    /*
     * Step 4: u1 = e / s mod n, u2 = r / s mod n
     */
    JHD_TLS_MPI_CHK( jhd_tls_mpi_inv_mod( &s_inv, s, &grp->N ) );

    JHD_TLS_MPI_CHK( jhd_tls_mpi_mul_mpi( &u1, &e, &s_inv ) );
    JHD_TLS_MPI_CHK( jhd_tls_mpi_mod_mpi( &u1, &u1, &grp->N ) );

    JHD_TLS_MPI_CHK( jhd_tls_mpi_mul_mpi( &u2, r, &s_inv ) );
    JHD_TLS_MPI_CHK( jhd_tls_mpi_mod_mpi( &u2, &u2, &grp->N ) );

    /*
     * Step 5: R = u1 G + u2 Q
     *
     * Since we're not using any secret data, no need to pass a RNG to
     * jhd_tls_ecp_mul() for countermesures.
     */
    JHD_TLS_MPI_CHK( jhd_tls_ecp_muladd( grp, &R, &u1, &grp->G, &u2, Q ) );

    if( jhd_tls_ecp_is_zero( &R ) )
    {
        ret = JHD_TLS_ERR_ECP_VERIFY_FAILED;
        goto cleanup;
    }

    /*
     * Step 6: convert xR to an integer (no-op)
     * Step 7: reduce xR mod n (gives v)
     */
    JHD_TLS_MPI_CHK( jhd_tls_mpi_mod_mpi( &R.X, &R.X, &grp->N ) );

    /*
     * Step 8: check if v (that is, R.X) is equal to r
     */
    if( jhd_tls_mpi_cmp_mpi( &R.X, r ) != 0 )
    {
        ret = JHD_TLS_ERR_ECP_VERIFY_FAILED;
        goto cleanup;
    }

cleanup:
    jhd_tls_ecp_point_free( &R );
    jhd_tls_mpi_free( &e ); jhd_tls_mpi_free( &s_inv ); jhd_tls_mpi_free( &u1 ); jhd_tls_mpi_free( &u2 );

    return( ret );
}
#endif /* JHD_TLS_ECDSA_VERIFY_ALT */

/*
 * Convert a signature (given by context) to ASN.1
 */
static int ecdsa_signature_to_asn1( const jhd_tls_mpi *r, const jhd_tls_mpi *s,
                                    unsigned char *sig, size_t *slen )
{
    int ret;
    unsigned char buf[JHD_TLS_ECDSA_MAX_LEN];
    unsigned char *p = buf + sizeof( buf );
    size_t len = 0;

    JHD_TLS_ASN1_CHK_ADD( len, jhd_tls_asn1_write_mpi( &p, buf, s ) );
    JHD_TLS_ASN1_CHK_ADD( len, jhd_tls_asn1_write_mpi( &p, buf, r ) );

    JHD_TLS_ASN1_CHK_ADD( len, jhd_tls_asn1_write_len( &p, buf, len ) );
    JHD_TLS_ASN1_CHK_ADD( len, jhd_tls_asn1_write_tag( &p, buf,
                                       JHD_TLS_ASN1_CONSTRUCTED | JHD_TLS_ASN1_SEQUENCE ) );

    memcpy( sig, p, len );
    *slen = len;

    return( 0 );
}

/*
 * Compute and write signature
 */
int jhd_tls_ecdsa_write_signature( jhd_tls_ecdsa_context *ctx, jhd_tls_md_type_t md_alg,
                           const unsigned char *hash, size_t hlen,
                           unsigned char *sig, size_t *slen,
                           int (*f_rng)(void *, unsigned char *, size_t),
                           void *p_rng )
{
    int ret;
    jhd_tls_mpi r, s;

    jhd_tls_mpi_init( &r );
    jhd_tls_mpi_init( &s );

#if defined(JHD_TLS_ECDSA_DETERMINISTIC)
    (void) f_rng;
    (void) p_rng;

    JHD_TLS_MPI_CHK( jhd_tls_ecdsa_sign_det( &ctx->grp, &r, &s, &ctx->d,
                             hash, hlen, md_alg ) );
#else
    (void) md_alg;

    JHD_TLS_MPI_CHK( jhd_tls_ecdsa_sign( &ctx->grp, &r, &s, &ctx->d,
                         hash, hlen, f_rng, p_rng ) );
#endif

    JHD_TLS_MPI_CHK( ecdsa_signature_to_asn1( &r, &s, sig, slen ) );

cleanup:
    jhd_tls_mpi_free( &r );
    jhd_tls_mpi_free( &s );

    return( ret );
}

#if ! defined(JHD_TLS_DEPRECATED_REMOVED) && \
    defined(JHD_TLS_ECDSA_DETERMINISTIC)
int jhd_tls_ecdsa_write_signature_det( jhd_tls_ecdsa_context *ctx,
                               const unsigned char *hash, size_t hlen,
                               unsigned char *sig, size_t *slen,
                               jhd_tls_md_type_t md_alg )
{
    return( jhd_tls_ecdsa_write_signature( ctx, md_alg, hash, hlen, sig, slen,
                                   NULL, NULL ) );
}
#endif

/*
 * Read and check signature
 */
int jhd_tls_ecdsa_read_signature( jhd_tls_ecdsa_context *ctx,
                          const unsigned char *hash, size_t hlen,
                          const unsigned char *sig, size_t slen )
{
    int ret;
    unsigned char *p = (unsigned char *) sig;
    const unsigned char *end = sig + slen;
    size_t len;
    jhd_tls_mpi r, s;

    jhd_tls_mpi_init( &r );
    jhd_tls_mpi_init( &s );

    if( ( ret = jhd_tls_asn1_get_tag( &p, end, &len,
                    JHD_TLS_ASN1_CONSTRUCTED | JHD_TLS_ASN1_SEQUENCE ) ) != 0 )
    {
        ret += JHD_TLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }

    if( p + len != end )
    {
        ret = JHD_TLS_ERR_ECP_BAD_INPUT_DATA +
              JHD_TLS_ERR_ASN1_LENGTH_MISMATCH;
        goto cleanup;
    }

    if( ( ret = jhd_tls_asn1_get_mpi( &p, end, &r ) ) != 0 ||
        ( ret = jhd_tls_asn1_get_mpi( &p, end, &s ) ) != 0 )
    {
        ret += JHD_TLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }

    if( ( ret = jhd_tls_ecdsa_verify( &ctx->grp, hash, hlen,
                              &ctx->Q, &r, &s ) ) != 0 )
        goto cleanup;

    /* At this point we know that the buffer starts with a valid signature.
     * Return 0 if the buffer just contains the signature, and a specific
     * error code if the valid signature is followed by more data. */
    if( p != end )
        ret = JHD_TLS_ERR_ECP_SIG_LEN_MISMATCH;

cleanup:
    jhd_tls_mpi_free( &r );
    jhd_tls_mpi_free( &s );

    return( ret );
}

#if !defined(JHD_TLS_ECDSA_GENKEY_ALT)
/*
 * Generate key pair
 */
int jhd_tls_ecdsa_genkey( jhd_tls_ecdsa_context *ctx, jhd_tls_ecp_group_id gid,
                  int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    return( jhd_tls_ecp_group_load( &ctx->grp, gid ) ||
            jhd_tls_ecp_gen_keypair( &ctx->grp, &ctx->d, &ctx->Q, f_rng, p_rng ) );
}
#endif /* JHD_TLS_ECDSA_GENKEY_ALT */

/*
 * Set context from an jhd_tls_ecp_keypair
 */
int jhd_tls_ecdsa_from_keypair( jhd_tls_ecdsa_context *ctx, const jhd_tls_ecp_keypair *key )
{
    int ret;

    if( ( ret = jhd_tls_ecp_group_copy( &ctx->grp, &key->grp ) ) != 0 ||
        ( ret = jhd_tls_mpi_copy( &ctx->d, &key->d ) ) != 0 ||
        ( ret = jhd_tls_ecp_copy( &ctx->Q, &key->Q ) ) != 0 )
    {
        jhd_tls_ecdsa_free( ctx );
    }

    return( ret );
}

/*
 * Initialize context
 */
void jhd_tls_ecdsa_init( jhd_tls_ecdsa_context *ctx )
{
    jhd_tls_ecp_keypair_init( ctx );
}

/*
 * Free context
 */
void jhd_tls_ecdsa_free( jhd_tls_ecdsa_context *ctx )
{
    jhd_tls_ecp_keypair_free( ctx );
}

#endif /* JHD_TLS_ECDSA_C */

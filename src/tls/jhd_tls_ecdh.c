/*
 *  Elliptic curve Diffie-Hellman
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
 * RFC 4492
 */

#if !defined(JHD_TLS_CONFIG_FILE)
#include <tls/jhd_tls_config.h>
#else
#include JHD_TLS_CONFIG_FILE
#endif

#if defined(JHD_TLS_ECDH_C)

#include <tls/jhd_tls_ecdh.h>

#include <string.h>

#if !defined(JHD_TLS_ECDH_GEN_PUBLIC_ALT)
/*
 * Generate public key: simple wrapper around jhd_tls_ecp_gen_keypair
 */
int jhd_tls_ecdh_gen_public( jhd_tls_ecp_group *grp, jhd_tls_mpi *d, jhd_tls_ecp_point *Q,
                     int (*f_rng)(void *, unsigned char *, size_t),
                     void *p_rng )
{
    return jhd_tls_ecp_gen_keypair( grp, d, Q, f_rng, p_rng );
}
#endif /* JHD_TLS_ECDH_GEN_PUBLIC_ALT */

#if !defined(JHD_TLS_ECDH_COMPUTE_SHARED_ALT)
/*
 * Compute shared secret (SEC1 3.3.1)
 */
int jhd_tls_ecdh_compute_shared( jhd_tls_ecp_group *grp, jhd_tls_mpi *z,
                         const jhd_tls_ecp_point *Q, const jhd_tls_mpi *d,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng )
{
    int ret;
    jhd_tls_ecp_point P;

    jhd_tls_ecp_point_init( &P );

    /*
     * Make sure Q is a valid pubkey before using it
     */
    JHD_TLS_MPI_CHK( jhd_tls_ecp_check_pubkey( grp, Q ) );

    JHD_TLS_MPI_CHK( jhd_tls_ecp_mul( grp, &P, d, Q, f_rng, p_rng ) );

    if( jhd_tls_ecp_is_zero( &P ) )
    {
        ret = JHD_TLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }

    JHD_TLS_MPI_CHK( jhd_tls_mpi_copy( z, &P.X ) );

cleanup:
    jhd_tls_ecp_point_free( &P );

    return( ret );
}
#endif /* JHD_TLS_ECDH_COMPUTE_SHARED_ALT */

/*
 * Initialize context
 */
void jhd_tls_ecdh_init( jhd_tls_ecdh_context *ctx )
{
    memset( ctx, 0, sizeof( jhd_tls_ecdh_context ) );
}

/*
 * Free context
 */
void jhd_tls_ecdh_free( jhd_tls_ecdh_context *ctx )
{
    if( ctx == NULL )
        return;

    jhd_tls_ecp_group_free( &ctx->grp );
    jhd_tls_ecp_point_free( &ctx->Q   );
    jhd_tls_ecp_point_free( &ctx->Qp  );
    jhd_tls_ecp_point_free( &ctx->Vi  );
    jhd_tls_ecp_point_free( &ctx->Vf  );
    jhd_tls_mpi_free( &ctx->d  );
    jhd_tls_mpi_free( &ctx->z  );
    jhd_tls_mpi_free( &ctx->_d );
}

/*
 * Setup and write the ServerKeyExhange parameters (RFC 4492)
 *      struct {
 *          ECParameters    curve_params;
 *          ECPoint         public;
 *      } ServerECDHParams;
 */
int jhd_tls_ecdh_make_params( jhd_tls_ecdh_context *ctx, size_t *olen,
                      unsigned char *buf, size_t blen,
                      int (*f_rng)(void *, unsigned char *, size_t),
                      void *p_rng )
{
    int ret;
    size_t grp_len, pt_len;

    if( ctx == NULL || ctx->grp.pbits == 0 )
        return( JHD_TLS_ERR_ECP_BAD_INPUT_DATA );

    if( ( ret = jhd_tls_ecdh_gen_public( &ctx->grp, &ctx->d, &ctx->Q, f_rng, p_rng ) )
                != 0 )
        return( ret );

    if( ( ret = jhd_tls_ecp_tls_write_group( &ctx->grp, &grp_len, buf, blen ) )
                != 0 )
        return( ret );

    buf += grp_len;
    blen -= grp_len;

    if( ( ret = jhd_tls_ecp_tls_write_point( &ctx->grp, &ctx->Q, ctx->point_format,
                                     &pt_len, buf, blen ) ) != 0 )
        return( ret );

    *olen = grp_len + pt_len;
    return( 0 );
}

/*
 * Read the ServerKeyExhange parameters (RFC 4492)
 *      struct {
 *          ECParameters    curve_params;
 *          ECPoint         public;
 *      } ServerECDHParams;
 */
int jhd_tls_ecdh_read_params( jhd_tls_ecdh_context *ctx,
                      const unsigned char **buf, const unsigned char *end )
{
    int ret;

    if( ( ret = jhd_tls_ecp_tls_read_group( &ctx->grp, buf, end - *buf ) ) != 0 )
        return( ret );

    if( ( ret = jhd_tls_ecp_tls_read_point( &ctx->grp, &ctx->Qp, buf, end - *buf ) )
                != 0 )
        return( ret );

    return( 0 );
}

/*
 * Get parameters from a keypair
 */
int jhd_tls_ecdh_get_params( jhd_tls_ecdh_context *ctx, const jhd_tls_ecp_keypair *key,
                     jhd_tls_ecdh_side side )
{
    int ret;

    if( ( ret = jhd_tls_ecp_group_copy( &ctx->grp, &key->grp ) ) != 0 )
        return( ret );

    /* If it's not our key, just import the public part as Qp */
    if( side == JHD_TLS_ECDH_THEIRS )
        return( jhd_tls_ecp_copy( &ctx->Qp, &key->Q ) );

    /* Our key: import public (as Q) and private parts */
    if( side != JHD_TLS_ECDH_OURS )
        return( JHD_TLS_ERR_ECP_BAD_INPUT_DATA );

    if( ( ret = jhd_tls_ecp_copy( &ctx->Q, &key->Q ) ) != 0 ||
        ( ret = jhd_tls_mpi_copy( &ctx->d, &key->d ) ) != 0 )
        return( ret );

    return( 0 );
}

/*
 * Setup and export the client public value
 */
int jhd_tls_ecdh_make_public( jhd_tls_ecdh_context *ctx, size_t *olen,
                      unsigned char *buf, size_t blen,
                      int (*f_rng)(void *, unsigned char *, size_t),
                      void *p_rng )
{
    int ret;

    if( ctx == NULL || ctx->grp.pbits == 0 )
        return( JHD_TLS_ERR_ECP_BAD_INPUT_DATA );

    if( ( ret = jhd_tls_ecdh_gen_public( &ctx->grp, &ctx->d, &ctx->Q, f_rng, p_rng ) )
                != 0 )
        return( ret );

    return jhd_tls_ecp_tls_write_point( &ctx->grp, &ctx->Q, ctx->point_format,
                                olen, buf, blen );
}

/*
 * Parse and import the client's public value
 */
int jhd_tls_ecdh_read_public( jhd_tls_ecdh_context *ctx,
                      const unsigned char *buf, size_t blen )
{
    int ret;
    const unsigned char *p = buf;

    if( ctx == NULL )
        return( JHD_TLS_ERR_ECP_BAD_INPUT_DATA );

    if( ( ret = jhd_tls_ecp_tls_read_point( &ctx->grp, &ctx->Qp, &p, blen ) ) != 0 )
        return( ret );

    if( (size_t)( p - buf ) != blen )
        return( JHD_TLS_ERR_ECP_BAD_INPUT_DATA );

    return( 0 );
}

/*
 * Derive and export the shared secret
 */
int jhd_tls_ecdh_calc_secret( jhd_tls_ecdh_context *ctx, size_t *olen,
                      unsigned char *buf, size_t blen,
                      int (*f_rng)(void *, unsigned char *, size_t),
                      void *p_rng )
{
    int ret;

    if( ctx == NULL )
        return( JHD_TLS_ERR_ECP_BAD_INPUT_DATA );

    if( ( ret = jhd_tls_ecdh_compute_shared( &ctx->grp, &ctx->z, &ctx->Qp, &ctx->d,
                                     f_rng, p_rng ) ) != 0 )
    {
        return( ret );
    }

    if( jhd_tls_mpi_size( &ctx->z ) > blen )
        return( JHD_TLS_ERR_ECP_BAD_INPUT_DATA );

    *olen = ctx->grp.pbits / 8 + ( ( ctx->grp.pbits % 8 ) != 0 );
    return jhd_tls_mpi_write_binary( &ctx->z, buf, *olen );
}

#endif /* JHD_TLS_ECDH_C */

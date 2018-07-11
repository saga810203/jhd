/**
 * \file ecjpake.h
 *
 * \brief Elliptic curve J-PAKE
 */
/*
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
#ifndef JHD_TLS_ECJPAKE_H
#define JHD_TLS_ECJPAKE_H

/*
 * J-PAKE is a password-authenticated key exchange that allows deriving a
 * strong shared secret from a (potentially low entropy) pre-shared
 * passphrase, with forward secrecy and mutual authentication.
 * https://en.wikipedia.org/wiki/Password_Authenticated_Key_Exchange_by_Juggling
 *
 * This file implements the Elliptic Curve variant of J-PAKE,
 * as defined in Chapter 7.4 of the Thread v1.0 Specification,
 * available to members of the Thread Group http://threadgroup.org/
 *
 * As the J-PAKE algorithm is inherently symmetric, so is our API.
 * Each party needs to send its first round message, in any order, to the
 * other party, then each sends its second round message, in any order.
 * The payloads are serialized in a way suitable for use in TLS, but could
 * also be use outside TLS.
 */

#include <tls/jhd_tls_ecp.h>
#include "jhd_tls_md.h"


/**
 * Roles in the EC J-PAKE exchange
 */
typedef enum {
    JHD_TLS_ECJPAKE_CLIENT = 0,         /**< Client                         */
    JHD_TLS_ECJPAKE_SERVER,             /**< Server                         */
} jhd_tls_ecjpake_role;

#if !defined(JHD_TLS_ECJPAKE_ALT)
/**
 * EC J-PAKE context structure.
 *
 * J-PAKE is a symmetric protocol, except for the identifiers used in
 * Zero-Knowledge Proofs, and the serialization of the second message
 * (KeyExchange) as defined by the Thread spec.
 *
 * In order to benefit from this symmetry, we choose a different naming
 * convetion from the Thread v1.0 spec. Correspondance is indicated in the
 * description as a pair C: client name, S: server name
 */
typedef struct
{
    const jhd_tls_md_info_t *md_info;   /**< Hash to use                    */
    jhd_tls_ecp_group grp;              /**< Elliptic curve                 */
    jhd_tls_ecjpake_role role;          /**< Are we client or server?       */
    int point_format;                   /**< Format for point export        */

    jhd_tls_ecp_point Xm1;              /**< My public key 1   C: X1, S: X3 */
    jhd_tls_ecp_point Xm2;              /**< My public key 2   C: X2, S: X4 */
    jhd_tls_ecp_point Xp1;              /**< Peer public key 1 C: X3, S: X1 */
    jhd_tls_ecp_point Xp2;              /**< Peer public key 2 C: X4, S: X2 */
    jhd_tls_ecp_point Xp;               /**< Peer public key   C: Xs, S: Xc */

    jhd_tls_mpi xm1;                    /**< My private key 1  C: x1, S: x3 */
    jhd_tls_mpi xm2;                    /**< My private key 2  C: x2, S: x4 */

    jhd_tls_mpi s;                      /**< Pre-shared secret (passphrase) */
} jhd_tls_ecjpake_context;

#else  /* JHD_TLS_ECJPAKE_ALT */
#include "ecjpake_alt.h"
#endif /* JHD_TLS_ECJPAKE_ALT */

/**
 * \brief           Initialize a context
 *                  (just makes it ready for setup() or free()).
 *
 * \param ctx       context to initialize
 */
void jhd_tls_ecjpake_init( jhd_tls_ecjpake_context *ctx );

/**
 * \brief           Set up a context for use
 *
 * \note            Currently the only values for hash/curve allowed by the
 *                  standard are JHD_TLS_MD_SHA256/JHD_TLS_ECP_DP_SECP256R1.
 *
 * \param ctx       context to set up
 * \param role      Our role: client or server
 * \param hash      hash function to use (JHD_TLS_MD_XXX)
 * \param curve     elliptic curve identifier (JHD_TLS_ECP_DP_XXX)
 * \param secret    pre-shared secret (passphrase)
 * \param len       length of the shared secret
 *
 * \return          0 if successfull,
 *                  a negative error code otherwise
 */
int jhd_tls_ecjpake_setup( jhd_tls_ecjpake_context *ctx,
                           jhd_tls_ecjpake_role role,
                           jhd_tls_md_type_t hash,
                           jhd_tls_ecp_group_id curve,
                           const unsigned char *secret,
                           size_t len );

/**
 * \brief           Check if a context is ready for use
 *
 * \param ctx       Context to check
 *
 * \return          0 if the context is ready for use,
 *                  JHD_TLS_ERR_ECP_BAD_INPUT_DATA otherwise
 */
int jhd_tls_ecjpake_check( const jhd_tls_ecjpake_context *ctx );

/**
 * \brief           Generate and write the first round message
 *                  (TLS: contents of the Client/ServerHello extension,
 *                  excluding extension type and length bytes)
 *
 * \param ctx       Context to use
 * \param buf       Buffer to write the contents to
 * \param len       Buffer size
 * \param olen      Will be updated with the number of bytes written
 * \param f_rng     RNG function
 * \param p_rng     RNG parameter
 *
 * \return          0 if successfull,
 *                  a negative error code otherwise
 */
int jhd_tls_ecjpake_write_round_one( jhd_tls_ecjpake_context *ctx,
                            unsigned char *buf, size_t len, size_t *olen,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng );

/**
 * \brief           Read and process the first round message
 *                  (TLS: contents of the Client/ServerHello extension,
 *                  excluding extension type and length bytes)
 *
 * \param ctx       Context to use
 * \param buf       Pointer to extension contents
 * \param len       Extension length
 *
 * \return          0 if successfull,
 *                  a negative error code otherwise
 */
int jhd_tls_ecjpake_read_round_one( jhd_tls_ecjpake_context *ctx,
                                    const unsigned char *buf,
                                    size_t len );

/**
 * \brief           Generate and write the second round message
 *                  (TLS: contents of the Client/ServerKeyExchange)
 *
 * \param ctx       Context to use
 * \param buf       Buffer to write the contents to
 * \param len       Buffer size
 * \param olen      Will be updated with the number of bytes written
 * \param f_rng     RNG function
 * \param p_rng     RNG parameter
 *
 * \return          0 if successfull,
 *                  a negative error code otherwise
 */
int jhd_tls_ecjpake_write_round_two( jhd_tls_ecjpake_context *ctx,
                            unsigned char *buf, size_t len, size_t *olen,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng );

/**
 * \brief           Read and process the second round message
 *                  (TLS: contents of the Client/ServerKeyExchange)
 *
 * \param ctx       Context to use
 * \param buf       Pointer to the message
 * \param len       Message length
 *
 * \return          0 if successfull,
 *                  a negative error code otherwise
 */
int jhd_tls_ecjpake_read_round_two( jhd_tls_ecjpake_context *ctx,
                                    const unsigned char *buf,
                                    size_t len );

/**
 * \brief           Derive the shared secret
 *                  (TLS: Pre-Master Secret)
 *
 * \param ctx       Context to use
 * \param buf       Buffer to write the contents to
 * \param len       Buffer size
 * \param olen      Will be updated with the number of bytes written
 * \param f_rng     RNG function
 * \param p_rng     RNG parameter
 *
 * \return          0 if successfull,
 *                  a negative error code otherwise
 */
int jhd_tls_ecjpake_derive_secret( jhd_tls_ecjpake_context *ctx,
                            unsigned char *buf, size_t len, size_t *olen,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng );

/**
 * \brief           Free a context's content
 *
 * \param ctx       context to free
 */
void jhd_tls_ecjpake_free( jhd_tls_ecjpake_context *ctx );



#if defined(JHD_TLS_SELF_TEST)

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if a test failed
 */
int jhd_tls_ecjpake_self_test( int verbose );

#endif /* JHD_TLS_SELF_TEST */




#endif /* ecjpake.h */

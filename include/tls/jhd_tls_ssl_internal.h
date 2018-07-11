/**
 * \file ssl_internal.h
 *
 * \brief Internal functions shared by the SSL modules
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
#ifndef JHD_TLS_SSL_INTERNAL_H
#define JHD_TLS_SSL_INTERNAL_H

#include <tls/jhd_tls_cipher.h>
#include <tls/jhd_tls_ssl.h>

#if defined(JHD_TLS_MD5_C)
#include <tls/jhd_tls_md5.h>
#endif

#if defined(JHD_TLS_SHA1_C)
#include <tls/jhd_tls_sha1.h>
#endif

#if defined(JHD_TLS_SHA256_C)
#include <tls/jhd_tls_sha256.h>
#endif

#if defined(JHD_TLS_SHA512_C)
#include <tls/jhd_tls_sha512.h>
#endif

#if defined(JHD_TLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
#include "ecjpake.h"
#endif

#if ( defined(__ARMCC_VERSION) || defined(_MSC_VER) ) && \
    !defined(inline) && !defined(__cplusplus)
#define inline __inline
#endif

/* Determine minimum supported version */
#define JHD_TLS_SSL_MIN_MAJOR_VERSION           JHD_TLS_SSL_MAJOR_VERSION_3

#if defined(JHD_TLS_SSL_PROTO_SSL3)
#define JHD_TLS_SSL_MIN_MINOR_VERSION           JHD_TLS_SSL_MINOR_VERSION_0
#else
#if defined(JHD_TLS_SSL_PROTO_TLS1)
#define JHD_TLS_SSL_MIN_MINOR_VERSION           JHD_TLS_SSL_MINOR_VERSION_1
#else
#if defined(JHD_TLS_SSL_PROTO_TLS1_1)
#define JHD_TLS_SSL_MIN_MINOR_VERSION           JHD_TLS_SSL_MINOR_VERSION_2
#else
#if defined(JHD_TLS_SSL_PROTO_TLS1_2)
#define JHD_TLS_SSL_MIN_MINOR_VERSION           JHD_TLS_SSL_MINOR_VERSION_3
#endif /* JHD_TLS_SSL_PROTO_TLS1_2 */
#endif /* JHD_TLS_SSL_PROTO_TLS1_1 */
#endif /* JHD_TLS_SSL_PROTO_TLS1   */
#endif /* JHD_TLS_SSL_PROTO_SSL3   */

#define JHD_TLS_SSL_MIN_VALID_MINOR_VERSION JHD_TLS_SSL_MINOR_VERSION_1
#define JHD_TLS_SSL_MIN_VALID_MAJOR_VERSION JHD_TLS_SSL_MAJOR_VERSION_3

/* Determine maximum supported version */
#define JHD_TLS_SSL_MAX_MAJOR_VERSION           JHD_TLS_SSL_MAJOR_VERSION_3

#if defined(JHD_TLS_SSL_PROTO_TLS1_2)
#define JHD_TLS_SSL_MAX_MINOR_VERSION           JHD_TLS_SSL_MINOR_VERSION_3
#else
#if defined(JHD_TLS_SSL_PROTO_TLS1_1)
#define JHD_TLS_SSL_MAX_MINOR_VERSION           JHD_TLS_SSL_MINOR_VERSION_2
#else
#if defined(JHD_TLS_SSL_PROTO_TLS1)
#define JHD_TLS_SSL_MAX_MINOR_VERSION           JHD_TLS_SSL_MINOR_VERSION_1
#else
#if defined(JHD_TLS_SSL_PROTO_SSL3)
#define JHD_TLS_SSL_MAX_MINOR_VERSION           JHD_TLS_SSL_MINOR_VERSION_0
#endif /* JHD_TLS_SSL_PROTO_SSL3   */
#endif /* JHD_TLS_SSL_PROTO_TLS1   */
#endif /* JHD_TLS_SSL_PROTO_TLS1_1 */
#endif /* JHD_TLS_SSL_PROTO_TLS1_2 */

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

/*
 * Allow extra bytes for record, authentication and encryption overhead:
 * counter (8) + header (5) + IV(16) + MAC (16-48) + padding (0-256)
 * and allow for a maximum of 1024 of compression expansion if
 * enabled.
 */
#if defined(JHD_TLS_ZLIB_SUPPORT)
#define JHD_TLS_SSL_COMPRESSION_ADD          1024
#else
#define JHD_TLS_SSL_COMPRESSION_ADD             0
#endif

#if defined(JHD_TLS_ARC4_C) || defined(JHD_TLS_CIPHER_MODE_CBC)
/* Ciphersuites using HMAC */
#if defined(JHD_TLS_SHA512_C)
#define JHD_TLS_SSL_MAC_ADD                 48  /* SHA-384 used for HMAC */
#elif defined(JHD_TLS_SHA256_C)
#define JHD_TLS_SSL_MAC_ADD                 32  /* SHA-256 used for HMAC */
#else
#define JHD_TLS_SSL_MAC_ADD                 20  /* SHA-1   used for HMAC */
#endif
#else
/* AEAD ciphersuites: GCM and CCM use a 128 bits tag */
#define JHD_TLS_SSL_MAC_ADD                 16
#endif

#if defined(JHD_TLS_CIPHER_MODE_CBC)
#define JHD_TLS_SSL_PADDING_ADD            256
#else
#define JHD_TLS_SSL_PADDING_ADD              0
#endif

#define JHD_TLS_SSL_PAYLOAD_LEN ( JHD_TLS_SSL_MAX_CONTENT_LEN    \
                        + JHD_TLS_SSL_COMPRESSION_ADD            \
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

#ifdef __cplusplus
extern "C" {
#endif

#if defined(JHD_TLS_SSL_PROTO_TLS1_2) && \
    defined(JHD_TLS_KEY_EXCHANGE__WITH_CERT__ENABLED)
/*
 * Abstraction for a grid of allowed signature-hash-algorithm pairs.
 */
struct jhd_tls_ssl_sig_hash_set_t
{
    /* At the moment, we only need to remember a single suitable
     * hash algorithm per signature algorithm. As long as that's
     * the case - and we don't need a general lookup function -
     * we can implement the sig-hash-set as a map from signatures
     * to hash algorithms. */
    jhd_tls_md_type_t rsa;
    jhd_tls_md_type_t ecdsa;
};
#endif /* JHD_TLS_SSL_PROTO_TLS1_2 &&
          JHD_TLS_KEY_EXCHANGE__WITH_CERT__ENABLED */

/*
 * This structure contains the parameters only needed during handshake.
 */
struct jhd_tls_ssl_handshake_params
{
    /*
     * Handshake specific crypto variables
     */

#if defined(JHD_TLS_SSL_PROTO_TLS1_2) && \
    defined(JHD_TLS_KEY_EXCHANGE__WITH_CERT__ENABLED)
    jhd_tls_ssl_sig_hash_set_t hash_algs;             /*!<  Set of suitable sig-hash pairs */
#endif
#if defined(JHD_TLS_DHM_C)
    jhd_tls_dhm_context dhm_ctx;                /*!<  DHM key exchange        */
#endif
#if defined(JHD_TLS_ECDH_C)
    jhd_tls_ecdh_context ecdh_ctx;              /*!<  ECDH key exchange       */
#endif
#if defined(JHD_TLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
    jhd_tls_ecjpake_context ecjpake_ctx;        /*!< EC J-PAKE key exchange */
#if defined(JHD_TLS_SSL_CLI_C)
    unsigned char *ecjpake_cache;               /*!< Cache for ClientHello ext */
    size_t ecjpake_cache_len;                   /*!< Length of cached data */
#endif
#endif /* JHD_TLS_KEY_EXCHANGE_ECJPAKE_ENABLED */
#if defined(JHD_TLS_ECDH_C) || defined(JHD_TLS_ECDSA_C) || \
    defined(JHD_TLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
    const jhd_tls_ecp_curve_info **curves;      /*!<  Supported elliptic curves */
#endif
#if defined(JHD_TLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
    unsigned char *psk;                 /*!<  PSK from the callback         */
    size_t psk_len;                     /*!<  Length of PSK from callback   */
#endif
#if defined(JHD_TLS_X509_CRT_PARSE_C)
    jhd_tls_ssl_key_cert *key_cert;     /*!< chosen key/cert pair (server)  */
#if defined(JHD_TLS_SSL_SERVER_NAME_INDICATION)
    int sni_authmode;                   /*!< authmode from SNI callback     */
    jhd_tls_ssl_key_cert *sni_key_cert; /*!< key/cert list from SNI         */
    jhd_tls_x509_crt *sni_ca_chain;     /*!< trusted CAs from SNI callback  */
    jhd_tls_x509_crl *sni_ca_crl;       /*!< trusted CAs CRLs from SNI      */
#endif /* JHD_TLS_SSL_SERVER_NAME_INDICATION */
#endif /* JHD_TLS_X509_CRT_PARSE_C */

#if defined(JHD_TLS_SSL_PROTO_DTLS)
    unsigned int out_msg_seq;           /*!<  Outgoing handshake sequence number */
    unsigned int in_msg_seq;            /*!<  Incoming handshake sequence number */

    unsigned char *verify_cookie;       /*!<  Cli: HelloVerifyRequest cookie
                                              Srv: unused                    */
    unsigned char verify_cookie_len;    /*!<  Cli: cookie length
                                              Srv: flag for sending a cookie */

    unsigned char *hs_msg;              /*!<  Reassembled handshake message  */

    uint32_t retransmit_timeout;        /*!<  Current value of timeout       */
    unsigned char retransmit_state;     /*!<  Retransmission state           */
    jhd_tls_ssl_flight_item *flight;            /*!<  Current outgoing flight        */
    jhd_tls_ssl_flight_item *cur_msg;           /*!<  Current message in flight      */
    unsigned int in_flight_start_seq;   /*!<  Minimum message sequence in the
                                              flight being received          */
    jhd_tls_ssl_transform *alt_transform_out;   /*!<  Alternative transform for
                                              resending messages             */
    unsigned char alt_out_ctr[8];       /*!<  Alternative record epoch/counter
                                              for resending messages         */
#endif /* JHD_TLS_SSL_PROTO_DTLS */

    /*
     * Checksum contexts
     */
#if defined(JHD_TLS_SSL_PROTO_SSL3) || defined(JHD_TLS_SSL_PROTO_TLS1) || \
    defined(JHD_TLS_SSL_PROTO_TLS1_1)
       jhd_tls_md5_context fin_md5;
      jhd_tls_sha1_context fin_sha1;
#endif
#if defined(JHD_TLS_SSL_PROTO_TLS1_2)
#if defined(JHD_TLS_SHA256_C)
    jhd_tls_sha256_context fin_sha256;
#endif
#if defined(JHD_TLS_SHA512_C)
    jhd_tls_sha512_context fin_sha512;
#endif
#endif /* JHD_TLS_SSL_PROTO_TLS1_2 */

    void (*update_checksum)(jhd_tls_ssl_context *, const unsigned char *, size_t);
    void (*calc_verify)(jhd_tls_ssl_context *, unsigned char *);
    void (*calc_finished)(jhd_tls_ssl_context *, unsigned char *, int);
    int  (*tls_prf)(const unsigned char *, size_t, const char *,
                    const unsigned char *, size_t,
                    unsigned char *, size_t);

    size_t pmslen;                      /*!<  premaster length        */

    unsigned char randbytes[64];        /*!<  random bytes            */
    unsigned char premaster[JHD_TLS_PREMASTER_SIZE];
                                        /*!<  premaster secret        */

    int resume;                         /*!<  session resume indicator*/
    int max_major_ver;                  /*!< max. major version client*/
    int max_minor_ver;                  /*!< max. minor version client*/
    int cli_exts;                       /*!< client extension presence*/

#if defined(JHD_TLS_SSL_SESSION_TICKETS)
    int new_session_ticket;             /*!< use NewSessionTicket?    */
#endif /* JHD_TLS_SSL_SESSION_TICKETS */
#if defined(JHD_TLS_SSL_EXTENDED_MASTER_SECRET)
    int extended_ms;                    /*!< use Extended Master Secret? */
#endif

#if defined(JHD_TLS_SSL_ASYNC_PRIVATE)
    unsigned int async_in_progress : 1; /*!< an asynchronous operation is in progress */
#endif /* JHD_TLS_SSL_ASYNC_PRIVATE */

#if defined(JHD_TLS_SSL_ASYNC_PRIVATE)
    /** Asynchronous operation context. This field is meant for use by the
     * asynchronous operation callbacks (jhd_tls_ssl_config::f_async_sign_start,
     * jhd_tls_ssl_config::f_async_decrypt_start,
     * jhd_tls_ssl_config::f_async_resume, jhd_tls_ssl_config::f_async_cancel).
     * The library does not use it internally. */
    void *user_async_ctx;
#endif /* JHD_TLS_SSL_ASYNC_PRIVATE */
};

/*
 * This structure contains a full set of runtime transform parameters
 * either in negotiation or active.
 */
struct jhd_tls_ssl_transform
{
    /*
     * Session specific crypto layer
     */
    const jhd_tls_ssl_ciphersuite_t *ciphersuite_info;
                                        /*!<  Chosen cipersuite_info  */
    unsigned int keylen;                /*!<  symmetric key length (bytes)  */
    size_t minlen;                      /*!<  min. ciphertext length  */
    size_t ivlen;                       /*!<  IV length               */
    size_t fixed_ivlen;                 /*!<  Fixed part of IV (AEAD) */
    size_t maclen;                      /*!<  MAC length              */

    unsigned char iv_enc[16];           /*!<  IV (encryption)         */
    unsigned char iv_dec[16];           /*!<  IV (decryption)         */

#if defined(JHD_TLS_SSL_PROTO_SSL3)
    /* Needed only for SSL v3.0 secret */
    unsigned char mac_enc[20];          /*!<  SSL v3.0 secret (enc)   */
    unsigned char mac_dec[20];          /*!<  SSL v3.0 secret (dec)   */
#endif /* JHD_TLS_SSL_PROTO_SSL3 */

    jhd_tls_md_context_t md_ctx_enc;            /*!<  MAC (encryption)        */
    jhd_tls_md_context_t md_ctx_dec;            /*!<  MAC (decryption)        */

    jhd_tls_cipher_context_t cipher_ctx_enc;    /*!<  encryption context      */
    jhd_tls_cipher_context_t cipher_ctx_dec;    /*!<  decryption context      */

    /*
     * Session specific compression layer
     */
#if defined(JHD_TLS_ZLIB_SUPPORT)
    z_stream ctx_deflate;               /*!<  compression context     */
    z_stream ctx_inflate;               /*!<  decompression context   */
#endif
};

#if defined(JHD_TLS_X509_CRT_PARSE_C)
/*
 * List of certificate + private key pairs
 */
struct jhd_tls_ssl_key_cert
{
    jhd_tls_x509_crt *cert;                 /*!< cert                       */
    jhd_tls_pk_context *key;                /*!< private key                */
    jhd_tls_ssl_key_cert *next;             /*!< next key/cert pair         */
};
#endif /* JHD_TLS_X509_CRT_PARSE_C */

#if defined(JHD_TLS_SSL_PROTO_DTLS)
/*
 * List of handshake messages kept around for resending
 */
struct jhd_tls_ssl_flight_item
{
    unsigned char *p;       /*!< message, including handshake headers   */
    size_t len;             /*!< length of p                            */
    unsigned char type;     /*!< type of the message: handshake or CCS  */
    jhd_tls_ssl_flight_item *next;  /*!< next handshake message(s)              */
};
#endif /* JHD_TLS_SSL_PROTO_DTLS */

#if defined(JHD_TLS_SSL_PROTO_TLS1_2) && \
    defined(JHD_TLS_KEY_EXCHANGE__WITH_CERT__ENABLED)

/* Find an entry in a signature-hash set matching a given hash algorithm. */
jhd_tls_md_type_t jhd_tls_ssl_sig_hash_set_find( jhd_tls_ssl_sig_hash_set_t *set,
                                                 jhd_tls_pk_type_t sig_alg );
/* Add a signature-hash-pair to a signature-hash set */
void jhd_tls_ssl_sig_hash_set_add( jhd_tls_ssl_sig_hash_set_t *set,
                                   jhd_tls_pk_type_t sig_alg,
                                   jhd_tls_md_type_t md_alg );
/* Allow exactly one hash algorithm for each signature. */
void jhd_tls_ssl_sig_hash_set_const_hash( jhd_tls_ssl_sig_hash_set_t *set,
                                          jhd_tls_md_type_t md_alg );

/* Setup an empty signature-hash set */
static inline void jhd_tls_ssl_sig_hash_set_init( jhd_tls_ssl_sig_hash_set_t *set )
{
    jhd_tls_ssl_sig_hash_set_const_hash( set, JHD_TLS_MD_NONE );
}

#endif /* JHD_TLS_SSL_PROTO_TLS1_2) &&
          JHD_TLS_KEY_EXCHANGE__WITH_CERT__ENABLED */

/**
 * \brief           Free referenced items in an SSL transform context and clear
 *                  memory
 *
 * \param transform SSL transform context
 */
void jhd_tls_ssl_transform_free( jhd_tls_ssl_transform *transform );

/**
 * \brief           Free referenced items in an SSL handshake context and clear
 *                  memory
 *
 * \param ssl       SSL context
 */
void jhd_tls_ssl_handshake_free( jhd_tls_ssl_context *ssl );

int jhd_tls_ssl_handshake_client_step( jhd_tls_ssl_context *ssl );
int jhd_tls_ssl_handshake_server_step( jhd_tls_ssl_context *ssl );
void jhd_tls_ssl_handshake_wrapup( jhd_tls_ssl_context *ssl );

int jhd_tls_ssl_send_fatal_handshake_failure( jhd_tls_ssl_context *ssl );

void jhd_tls_ssl_reset_checksum( jhd_tls_ssl_context *ssl );
int jhd_tls_ssl_derive_keys( jhd_tls_ssl_context *ssl );

int jhd_tls_ssl_read_record_layer( jhd_tls_ssl_context *ssl );
int jhd_tls_ssl_handle_message_type( jhd_tls_ssl_context *ssl );
int jhd_tls_ssl_prepare_handshake_record( jhd_tls_ssl_context *ssl );
void jhd_tls_ssl_update_handshake_status( jhd_tls_ssl_context *ssl );

/**
 * \brief       Update record layer
 *
 *              This function roughly separates the implementation
 *              of the logic of (D)TLS from the implementation
 *              of the secure transport.
 *
 * \param  ssl  SSL context to use
 *
 * \return      0 or non-zero error code.
 *
 * \note        A clarification on what is called 'record layer' here
 *              is in order, as many sensible definitions are possible:
 *
 *              The record layer takes as input an untrusted underlying
 *              transport (stream or datagram) and transforms it into
 *              a serially multiplexed, secure transport, which
 *              conceptually provides the following:
 *
 *              (1) Three datagram based, content-agnostic transports
 *                  for handshake, alert and CCS messages.
 *              (2) One stream- or datagram-based transport
 *                  for application data.
 *              (3) Functionality for changing the underlying transform
 *                  securing the contents.
 *
 *              The interface to this functionality is given as follows:
 *
 *              a Updating
 *                [Currently implemented by jhd_tls_ssl_read_record]
 *
 *                Check if and on which of the four 'ports' data is pending:
 *                Nothing, a controlling datagram of type (1), or application
 *                data (2). In any case data is present, internal buffers
 *                provide access to the data for the user to process it.
 *                Consumption of type (1) datagrams is done automatically
 *                on the next update, invalidating that the internal buffers
 *                for previous datagrams, while consumption of application
 *                data (2) is user-controlled.
 *
 *              b Reading of application data
 *                [Currently manual adaption of ssl->in_offt pointer]
 *
 *                As mentioned in the last paragraph, consumption of data
 *                is different from the automatic consumption of control
 *                datagrams (1) because application data is treated as a stream.
 *
 *              c Tracking availability of application data
 *                [Currently manually through decreasing ssl->in_msglen]
 *
 *                For efficiency and to retain datagram semantics for
 *                application data in case of DTLS, the record layer
 *                provides functionality for checking how much application
 *                data is still available in the internal buffer.
 *
 *              d Changing the transformation securing the communication.
 *
 *              Given an opaque implementation of the record layer in the
 *              above sense, it should be possible to implement the logic
 *              of (D)TLS on top of it without the need to know anything
 *              about the record layer's internals. This is done e.g.
 *              in all the handshake handling functions, and in the
 *              application data reading function jhd_tls_ssl_read.
 *
 * \note        The above tries to give a conceptual picture of the
 *              record layer, but the current implementation deviates
 *              from it in some places. For example, our implementation of
 *              the update functionality through jhd_tls_ssl_read_record
 *              discards datagrams depending on the current state, which
 *              wouldn't fall under the record layer's responsibility
 *              following the above definition.
 *
 */
int jhd_tls_ssl_read_record( jhd_tls_ssl_context *ssl );
int jhd_tls_ssl_fetch_input( jhd_tls_ssl_context *ssl, size_t nb_want );

int jhd_tls_ssl_write_record( jhd_tls_ssl_context *ssl );
int jhd_tls_ssl_flush_output( jhd_tls_ssl_context *ssl );

int jhd_tls_ssl_parse_certificate( jhd_tls_ssl_context *ssl );
int jhd_tls_ssl_write_certificate( jhd_tls_ssl_context *ssl );

int jhd_tls_ssl_parse_change_cipher_spec( jhd_tls_ssl_context *ssl );
int jhd_tls_ssl_write_change_cipher_spec( jhd_tls_ssl_context *ssl );

int jhd_tls_ssl_parse_finished( jhd_tls_ssl_context *ssl );
int jhd_tls_ssl_write_finished( jhd_tls_ssl_context *ssl );

void jhd_tls_ssl_optimize_checksum( jhd_tls_ssl_context *ssl,
                            const jhd_tls_ssl_ciphersuite_t *ciphersuite_info );

#if defined(JHD_TLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
int jhd_tls_ssl_psk_derive_premaster( jhd_tls_ssl_context *ssl, jhd_tls_key_exchange_type_t key_ex );
#endif

#if defined(JHD_TLS_PK_C)
unsigned char jhd_tls_ssl_sig_from_pk( jhd_tls_pk_context *pk );
unsigned char jhd_tls_ssl_sig_from_pk_alg( jhd_tls_pk_type_t type );
jhd_tls_pk_type_t jhd_tls_ssl_pk_alg_from_sig( unsigned char sig );
#endif

jhd_tls_md_type_t jhd_tls_ssl_md_alg_from_hash( unsigned char hash );
unsigned char jhd_tls_ssl_hash_from_md_alg( int md );
int jhd_tls_ssl_set_calc_verify_md( jhd_tls_ssl_context *ssl, int md );

#if defined(JHD_TLS_ECP_C)
int jhd_tls_ssl_check_curve( const jhd_tls_ssl_context *ssl, jhd_tls_ecp_group_id grp_id );
#endif

#if defined(JHD_TLS_KEY_EXCHANGE__WITH_CERT__ENABLED)
int jhd_tls_ssl_check_sig_hash( const jhd_tls_ssl_context *ssl,
                                jhd_tls_md_type_t md );
#endif

#if defined(JHD_TLS_X509_CRT_PARSE_C)
static inline jhd_tls_pk_context *jhd_tls_ssl_own_key( jhd_tls_ssl_context *ssl )
{
    jhd_tls_ssl_key_cert *key_cert;

    if( ssl->handshake != NULL && ssl->handshake->key_cert != NULL )
        key_cert = ssl->handshake->key_cert;
    else
        key_cert = ssl->conf->key_cert;

    return( key_cert == NULL ? NULL : key_cert->key );
}

static inline jhd_tls_x509_crt *jhd_tls_ssl_own_cert( jhd_tls_ssl_context *ssl )
{
    jhd_tls_ssl_key_cert *key_cert;

    if( ssl->handshake != NULL && ssl->handshake->key_cert != NULL )
        key_cert = ssl->handshake->key_cert;
    else
        key_cert = ssl->conf->key_cert;

    return( key_cert == NULL ? NULL : key_cert->cert );
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
int jhd_tls_ssl_check_cert_usage( const jhd_tls_x509_crt *cert,
                          const jhd_tls_ssl_ciphersuite_t *ciphersuite,
                          int cert_endpoint,
                          uint32_t *flags );
#endif /* JHD_TLS_X509_CRT_PARSE_C */

void jhd_tls_ssl_write_version( int major, int minor, int transport,
                        unsigned char ver[2] );
void jhd_tls_ssl_read_version( int *major, int *minor, int transport,
                       const unsigned char ver[2] );

static inline size_t jhd_tls_ssl_hdr_len( const jhd_tls_ssl_context *ssl )
{
#if defined(JHD_TLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == JHD_TLS_SSL_TRANSPORT_DATAGRAM )
        return( 13 );
#else
    ((void) ssl);
#endif
    return( 5 );
}

static inline size_t jhd_tls_ssl_hs_hdr_len( const jhd_tls_ssl_context *ssl )
{
#if defined(JHD_TLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == JHD_TLS_SSL_TRANSPORT_DATAGRAM )
        return( 12 );
#else
    ((void) ssl);
#endif
    return( 4 );
}

#if defined(JHD_TLS_SSL_PROTO_DTLS)
void jhd_tls_ssl_send_flight_completed( jhd_tls_ssl_context *ssl );
void jhd_tls_ssl_recv_flight_completed( jhd_tls_ssl_context *ssl );
int jhd_tls_ssl_resend( jhd_tls_ssl_context *ssl );
#endif

/* Visible for testing purposes only */
#if defined(JHD_TLS_SSL_DTLS_ANTI_REPLAY)
int jhd_tls_ssl_dtls_replay_check( jhd_tls_ssl_context *ssl );
void jhd_tls_ssl_dtls_replay_update( jhd_tls_ssl_context *ssl );
#endif

/* constant-time buffer comparison */
static inline int jhd_tls_ssl_safer_memcmp( const void *a, const void *b, size_t n )
{
    size_t i;
    volatile const unsigned char *A = (volatile const unsigned char *) a;
    volatile const unsigned char *B = (volatile const unsigned char *) b;
    volatile unsigned char diff = 0;

    for( i = 0; i < n; i++ )
    {
        /* Read volatile data in order before computing diff.
         * This avoids IAR compiler warning:
         * 'the order of volatile accesses is undefined ..' */
        unsigned char x = A[i], y = B[i];
        diff |= x ^ y;
    }

    return( diff );
}

#if defined(JHD_TLS_SSL_PROTO_SSL3) || defined(JHD_TLS_SSL_PROTO_TLS1) || \
    defined(JHD_TLS_SSL_PROTO_TLS1_1)
int jhd_tls_ssl_get_key_exchange_md_ssl_tls( jhd_tls_ssl_context *ssl,
                                        unsigned char *output,
                                        unsigned char *data, size_t data_len );
#endif /* JHD_TLS_SSL_PROTO_SSL3 || JHD_TLS_SSL_PROTO_TLS1 || \
          JHD_TLS_SSL_PROTO_TLS1_1 */

#if defined(JHD_TLS_SSL_PROTO_TLS1) || defined(JHD_TLS_SSL_PROTO_TLS1_1) || \
    defined(JHD_TLS_SSL_PROTO_TLS1_2)
int jhd_tls_ssl_get_key_exchange_md_tls1_2( jhd_tls_ssl_context *ssl,
                                            unsigned char *hash, size_t *hashlen,
                                            unsigned char *data, size_t data_len,
                                            jhd_tls_md_type_t md_alg );
#endif /* JHD_TLS_SSL_PROTO_TLS1 || JHD_TLS_SSL_PROTO_TLS1_1 || \
          JHD_TLS_SSL_PROTO_TLS1_2 */

#ifdef __cplusplus
}
#endif

#endif /* ssl_internal.h */

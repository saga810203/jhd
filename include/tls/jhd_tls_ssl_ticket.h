/**
 * \file ssl_ticket.h
 *
 * \brief TLS server ticket callbacks implementation
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
#ifndef JHD_TLS_SSL_TICKET_H
#define JHD_TLS_SSL_TICKET_H

/*
 * This implementation of the session ticket callbacks includes key
 * management, rotating the keys periodically in order to preserve forward
 * secrecy, when JHD_TLS_HAVE_TIME is defined.
 */

#include <tls/jhd_tls_cipher.h>
#include <tls/jhd_tls_ssl.h>



/**
 * \brief   Information for session ticket protection
 */
typedef struct
{
    unsigned char name[4];          /*!< random key identifier              */
    uint32_t generation_time;       /*!< key generation timestamp (seconds) */
    jhd_tls_cipher_context_t ctx;   /*!< context for auth enc/decryption    */
}
jhd_tls_ssl_ticket_key;

/**
 * \brief   Context for session ticket handling functions
 */
typedef struct
{
    jhd_tls_ssl_ticket_key keys[2]; /*!< ticket protection keys             */
    unsigned char active;           /*!< index of the currently active key  */

    uint32_t ticket_lifetime;       /*!< lifetime of tickets in seconds     */

    /** Callback for getting (pseudo-)random numbers                        */
    int  (*f_rng)(void *, unsigned char *, size_t);
    void *p_rng;                    /*!< context for the RNG function       */

#if defined(JHD_TLS_THREADING_C)
    jhd_tls_threading_mutex_t mutex;
#endif
}
jhd_tls_ssl_ticket_context;

/**
 * \brief           Initialize a ticket context.
 *                  (Just make it ready for jhd_tls_ssl_ticket_setup()
 *                  or jhd_tls_ssl_ticket_free().)
 *
 * \param ctx       Context to be initialized
 */
void jhd_tls_ssl_ticket_init( jhd_tls_ssl_ticket_context *ctx );

/**
 * \brief           Prepare context to be actually used
 *
 * \param ctx       Context to be set up
 * \param f_rng     RNG callback function
 * \param p_rng     RNG callback context
 * \param cipher    AEAD cipher to use for ticket protection.
 *                  Recommended value: JHD_TLS_CIPHER_AES_256_GCM.
 * \param lifetime  Tickets lifetime in seconds
 *                  Recommended value: 86400 (one day).
 *
 * \note            It is highly recommended to select a cipher that is at
 *                  least as strong as the the strongest ciphersuite
 *                  supported. Usually that means a 256-bit key.
 *
 * \note            The lifetime of the keys is twice the lifetime of tickets.
 *                  It is recommended to pick a reasonnable lifetime so as not
 *                  to negate the benefits of forward secrecy.
 *
 * \return          0 if successful,
 *                  or a specific JHD_TLS_ERR_XXX error code
 */
int jhd_tls_ssl_ticket_setup( jhd_tls_ssl_ticket_context *ctx,
    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
    jhd_tls_cipher_type_t cipher,
    uint32_t lifetime );

/**
 * \brief           Implementation of the ticket write callback
 *
 * \note            See \c mbedlts_ssl_ticket_write_t for description
 */
jhd_tls_ssl_ticket_write_t jhd_tls_ssl_ticket_write;

/**
 * \brief           Implementation of the ticket parse callback
 *
 * \note            See \c mbedlts_ssl_ticket_parse_t for description
 */
jhd_tls_ssl_ticket_parse_t jhd_tls_ssl_ticket_parse;

/**
 * \brief           Free a context's content and zeroize it.
 *
 * \param ctx       Context to be cleaned up
 */
void jhd_tls_ssl_ticket_free( jhd_tls_ssl_ticket_context *ctx );



#endif /* ssl_ticket.h */

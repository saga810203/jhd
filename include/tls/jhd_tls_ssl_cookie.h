/**
 * \file ssl_cookie.h
 *
 * \brief DTLS cookie callbacks implementation
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
#ifndef JHD_TLS_SSL_COOKIE_H
#define JHD_TLS_SSL_COOKIE_H

#include <tls/jhd_tls_ssl.h>



/**
 * \name SECTION: Module settings
 *
 * The configuration options you can set for this module are in this section.
 * Either change them in config.h or define them on the compiler command line.
 * \{
 */
#ifndef JHD_TLS_SSL_COOKIE_TIMEOUT
#define JHD_TLS_SSL_COOKIE_TIMEOUT     60 /**< Default expiration delay of DTLS cookies, in seconds if HAVE_TIME, or in number of cookies issued */
#endif

/* \} name SECTION: Module settings */


/**
 * \brief          Context for the default cookie functions.
 */
typedef struct
{
    jhd_tls_md_context_t    hmac_ctx;   /*!< context for the HMAC portion   */
#if !defined(JHD_TLS_HAVE_TIME)
    unsigned long   serial;     /*!< serial number for expiration   */
#endif
    unsigned long   timeout;    /*!< timeout delay, in seconds if HAVE_TIME,
                                     or in number of tickets issued */

#if defined(JHD_TLS_THREADING_C)
    jhd_tls_threading_mutex_t mutex;
#endif
} jhd_tls_ssl_cookie_ctx;

/**
 * \brief          Initialize cookie context
 */
void jhd_tls_ssl_cookie_init( jhd_tls_ssl_cookie_ctx *ctx );

/**
 * \brief          Setup cookie context (generate keys)
 */
int jhd_tls_ssl_cookie_setup( jhd_tls_ssl_cookie_ctx *ctx,
                      int (*f_rng)(void *, unsigned char *, size_t),
                      void *p_rng );

/**
 * \brief          Set expiration delay for cookies
 *                 (Default JHD_TLS_SSL_COOKIE_TIMEOUT)
 *
 * \param ctx      Cookie contex
 * \param delay    Delay, in seconds if HAVE_TIME, or in number of cookies
 *                 issued in the meantime.
 *                 0 to disable expiration (NOT recommended)
 */
void jhd_tls_ssl_cookie_set_timeout( jhd_tls_ssl_cookie_ctx *ctx, unsigned long delay );

/**
 * \brief          Free cookie context
 */
void jhd_tls_ssl_cookie_free( jhd_tls_ssl_cookie_ctx *ctx );

/**
 * \brief          Generate cookie, see \c jhd_tls_ssl_cookie_write_t
 */
jhd_tls_ssl_cookie_write_t jhd_tls_ssl_cookie_write;

/**
 * \brief          Verify cookie, see \c jhd_tls_ssl_cookie_write_t
 */
jhd_tls_ssl_cookie_check_t jhd_tls_ssl_cookie_check;



#endif /* ssl_cookie.h */

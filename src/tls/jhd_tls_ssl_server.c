/*
 *  SSL server demonstration program
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

#if !defined(JHD_TLS_CONFIG_FILE)
#include <tls/jhd_tls_config.h>
#else
#include JHD_TLS_CONFIG_FILE
#endif

#if defined(JHD_TLS_PLATFORM_C)
#include "tls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define jhd_tls_time       time
#define jhd_tls_time_t     time_t
#define jhd_tls_fprintf    fprintf
#define jhd_tls_printf     printf
#endif

#if !defined(JHD_TLS_BIGNUM_C) || !defined(JHD_TLS_CERTS_C) ||    \
    !defined(JHD_TLS_ENTROPY_C) || !defined(JHD_TLS_SSL_TLS_C) || \
    !defined(JHD_TLS_SSL_SRV_C) || !defined(JHD_TLS_NET_C) ||     \
    !defined(JHD_TLS_RSA_C) || !defined(JHD_TLS_CTR_DRBG_C) ||    \
    !defined(JHD_TLS_X509_CRT_PARSE_C) || !defined(JHD_TLS_FS_IO) || \
    !defined(JHD_TLS_PEM_PARSE_C)
int main( void )
{
    jhd_tls_printf("JHD_TLS_BIGNUM_C and/or JHD_TLS_CERTS_C and/or JHD_TLS_ENTROPY_C "
           "and/or JHD_TLS_SSL_TLS_C and/or JHD_TLS_SSL_SRV_C and/or "
           "JHD_TLS_NET_C and/or JHD_TLS_RSA_C and/or "
           "JHD_TLS_CTR_DRBG_C and/or JHD_TLS_X509_CRT_PARSE_C "
           "and/or JHD_TLS_PEM_PARSE_C not defined.\n");
    return( 0 );
}
#else

#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#endif

#include "tls/entropy.h"
#include "tls/ctr_drbg.h"
#include "tls/certs.h"
#include "tls/x509.h"
#include "tls/ssl.h"
#include "tls/net_sockets.h"
#include "tls/error.h"
#include "tls/debug.h"

#if defined(JHD_TLS_SSL_CACHE_C)
#include "tls/ssl_cache.h"
#endif

#define HTTP_RESPONSE \
    "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" \
    "<h2>mbed TLS Test Server</h2>\r\n" \
    "<p>Successful connection using: %s</p>\r\n"

#define DEBUG_LEVEL 0

static void my_debug( void *ctx, int level,
                      const char *file, int line,
                      const char *str )
{
    ((void) level);

    jhd_tls_fprintf( (FILE *) ctx, "%s:%04d: %s", file, line, str );
    fflush(  (FILE *) ctx  );
}

int main( void )
{
    int ret, len;
    jhd_tls_net_context listen_fd, client_fd;
    unsigned char buf[1024];
    const char *pers = "ssl_server";

    jhd_tls_entropy_context entropy;
    jhd_tls_ctr_drbg_context ctr_drbg;
    jhd_tls_ssl_context ssl;
    jhd_tls_ssl_config conf;
    jhd_tls_x509_crt srvcert;
    jhd_tls_pk_context pkey;
#if defined(JHD_TLS_SSL_CACHE_C)
    jhd_tls_ssl_cache_context cache;
#endif

    jhd_tls_net_init( &listen_fd );
    jhd_tls_net_init( &client_fd );
    jhd_tls_ssl_init( &ssl );
    jhd_tls_ssl_config_init( &conf );
#if defined(JHD_TLS_SSL_CACHE_C)
    jhd_tls_ssl_cache_init( &cache );
#endif
    jhd_tls_x509_crt_init( &srvcert );
    jhd_tls_pk_init( &pkey );
    jhd_tls_entropy_init( &entropy );
    jhd_tls_ctr_drbg_init( &ctr_drbg );

#if defined(JHD_TLS_DEBUG_C)
    jhd_tls_debug_set_threshold( DEBUG_LEVEL );
#endif

    /*
     * 1. Load the certificates and private RSA key
     */
    jhd_tls_printf( "\n  . Loading the server cert. and key..." );
    fflush( stdout );

    /*
     * This demonstration program uses embedded test certificates.
     * Instead, you may want to use jhd_tls_x509_crt_parse_file() to read the
     * server and CA certificates, as well as jhd_tls_pk_parse_keyfile().
     */
    ret = jhd_tls_x509_crt_parse( &srvcert, (const unsigned char *) jhd_tls_test_srv_crt,
                          jhd_tls_test_srv_crt_len );
    if( ret != 0 )
    {
        jhd_tls_printf( " failed\n  !  jhd_tls_x509_crt_parse returned %d\n\n", ret );
        goto exit;
    }

    ret = jhd_tls_x509_crt_parse( &srvcert, (const unsigned char *) jhd_tls_test_cas_pem,
                          jhd_tls_test_cas_pem_len );
    if( ret != 0 )
    {
        jhd_tls_printf( " failed\n  !  jhd_tls_x509_crt_parse returned %d\n\n", ret );
        goto exit;
    }

    ret =  jhd_tls_pk_parse_key( &pkey, (const unsigned char *) jhd_tls_test_srv_key,
                         jhd_tls_test_srv_key_len, NULL, 0 );
    if( ret != 0 )
    {
        jhd_tls_printf( " failed\n  !  jhd_tls_pk_parse_key returned %d\n\n", ret );
        goto exit;
    }

    jhd_tls_printf( " ok\n" );

    /*
     * 2. Setup the listening TCP socket
     */
    jhd_tls_printf( "  . Bind on https://localhost:4433/ ..." );
    fflush( stdout );

    if( ( ret = jhd_tls_net_bind( &listen_fd, NULL, "4433", JHD_TLS_NET_PROTO_TCP ) ) != 0 )
    {
        jhd_tls_printf( " failed\n  ! jhd_tls_net_bind returned %d\n\n", ret );
        goto exit;
    }

    jhd_tls_printf( " ok\n" );

    /*
     * 3. Seed the RNG
     */
    jhd_tls_printf( "  . Seeding the random number generator..." );
    fflush( stdout );

    if( ( ret = jhd_tls_ctr_drbg_seed( &ctr_drbg, jhd_tls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        jhd_tls_printf( " failed\n  ! jhd_tls_ctr_drbg_seed returned %d\n", ret );
        goto exit;
    }

    jhd_tls_printf( " ok\n" );

    /*
     * 4. Setup stuff
     */
    jhd_tls_printf( "  . Setting up the SSL data...." );
    fflush( stdout );

    if( ( ret = jhd_tls_ssl_config_defaults( &conf,
                    JHD_TLS_SSL_IS_SERVER,
                    JHD_TLS_SSL_TRANSPORT_STREAM,
                    JHD_TLS_SSL_PRESET_DEFAULT ) ) != 0 )
    {
        jhd_tls_printf( " failed\n  ! jhd_tls_ssl_config_defaults returned %d\n\n", ret );
        goto exit;
    }

    jhd_tls_ssl_conf_rng( &conf, jhd_tls_ctr_drbg_random, &ctr_drbg );
    jhd_tls_ssl_conf_dbg( &conf, my_debug, stdout );

#if defined(JHD_TLS_SSL_CACHE_C)
    jhd_tls_ssl_conf_session_cache( &conf, &cache,
                                   jhd_tls_ssl_cache_get,
                                   jhd_tls_ssl_cache_set );
#endif

    jhd_tls_ssl_conf_ca_chain( &conf, srvcert.next, NULL );
    if( ( ret = jhd_tls_ssl_conf_own_cert( &conf, &srvcert, &pkey ) ) != 0 )
    {
        jhd_tls_printf( " failed\n  ! jhd_tls_ssl_conf_own_cert returned %d\n\n", ret );
        goto exit;
    }

    if( ( ret = jhd_tls_ssl_setup( &ssl, &conf ) ) != 0 )
    {
        jhd_tls_printf( " failed\n  ! jhd_tls_ssl_setup returned %d\n\n", ret );
        goto exit;
    }

    jhd_tls_printf( " ok\n" );

reset:
#ifdef JHD_TLS_ERROR_C
    if( ret != 0 )
    {
        char error_buf[100];
        jhd_tls_strerror( ret, error_buf, 100 );
        jhd_tls_printf("Last error was: %d - %s\n\n", ret, error_buf );
    }
#endif

    jhd_tls_net_free( &client_fd );

    jhd_tls_ssl_session_reset( &ssl );

    /*
     * 3. Wait until a client connects
     */
    jhd_tls_printf( "  . Waiting for a remote connection ..." );
    fflush( stdout );

    if( ( ret = jhd_tls_net_accept( &listen_fd, &client_fd,
                                    NULL, 0, NULL ) ) != 0 )
    {
        jhd_tls_printf( " failed\n  ! jhd_tls_net_accept returned %d\n\n", ret );
        goto exit;
    }

    jhd_tls_ssl_set_bio( &ssl, &client_fd, jhd_tls_net_send, jhd_tls_net_recv, NULL );

    jhd_tls_printf( " ok\n" );

    /*
     * 5. Handshake
     */
    jhd_tls_printf( "  . Performing the SSL/TLS handshake..." );
    fflush( stdout );

    while( ( ret = jhd_tls_ssl_handshake( &ssl ) ) != 0 )
    {
        if( ret != JHD_TLS_ERR_SSL_WANT_READ && ret != JHD_TLS_ERR_SSL_WANT_WRITE )
        {
            jhd_tls_printf( " failed\n  ! jhd_tls_ssl_handshake returned %d\n\n", ret );
            goto reset;
        }
    }

    jhd_tls_printf( " ok\n" );

    /*
     * 6. Read the HTTP Request
     */
    jhd_tls_printf( "  < Read from client:" );
    fflush( stdout );

    do
    {
        len = sizeof( buf ) - 1;
        memset( buf, 0, sizeof( buf ) );
        ret = jhd_tls_ssl_read( &ssl, buf, len );

        if( ret == JHD_TLS_ERR_SSL_WANT_READ || ret == JHD_TLS_ERR_SSL_WANT_WRITE )
            continue;

        if( ret <= 0 )
        {
            switch( ret )
            {
                case JHD_TLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                    jhd_tls_printf( " connection was closed gracefully\n" );
                    break;

                case JHD_TLS_ERR_NET_CONN_RESET:
                    jhd_tls_printf( " connection was reset by peer\n" );
                    break;

                default:
                    jhd_tls_printf( " jhd_tls_ssl_read returned -0x%x\n", -ret );
                    break;
            }

            break;
        }

        len = ret;
        jhd_tls_printf( " %d bytes read\n\n%s", len, (char *) buf );

        if( ret > 0 )
            break;
    }
    while( 1 );

    /*
     * 7. Write the 200 Response
     */
    jhd_tls_printf( "  > Write to client:" );
    fflush( stdout );

    len = sprintf( (char *) buf, HTTP_RESPONSE,
                   jhd_tls_ssl_get_ciphersuite( &ssl ) );

    while( ( ret = jhd_tls_ssl_write( &ssl, buf, len ) ) <= 0 )
    {
        if( ret == JHD_TLS_ERR_NET_CONN_RESET )
        {
            jhd_tls_printf( " failed\n  ! peer closed the connection\n\n" );
            goto reset;
        }

        if( ret != JHD_TLS_ERR_SSL_WANT_READ && ret != JHD_TLS_ERR_SSL_WANT_WRITE )
        {
            jhd_tls_printf( " failed\n  ! jhd_tls_ssl_write returned %d\n\n", ret );
            goto exit;
        }
    }

    len = ret;
    jhd_tls_printf( " %d bytes written\n\n%s\n", len, (char *) buf );

    jhd_tls_printf( "  . Closing the connection..." );

    while( ( ret = jhd_tls_ssl_close_notify( &ssl ) ) < 0 )
    {
        if( ret != JHD_TLS_ERR_SSL_WANT_READ &&
            ret != JHD_TLS_ERR_SSL_WANT_WRITE )
        {
            jhd_tls_printf( " failed\n  ! jhd_tls_ssl_close_notify returned %d\n\n", ret );
            goto reset;
        }
    }

    jhd_tls_printf( " ok\n" );

    ret = 0;
    goto reset;

exit:

#ifdef JHD_TLS_ERROR_C
    if( ret != 0 )
    {
        char error_buf[100];
        jhd_tls_strerror( ret, error_buf, 100 );
        jhd_tls_printf("Last error was: %d - %s\n\n", ret, error_buf );
    }
#endif

    jhd_tls_net_free( &client_fd );
    jhd_tls_net_free( &listen_fd );

    jhd_tls_x509_crt_free( &srvcert );
    jhd_tls_pk_free( &pkey );
    jhd_tls_ssl_free( &ssl );
    jhd_tls_ssl_config_free( &conf );
#if defined(JHD_TLS_SSL_CACHE_C)
    jhd_tls_ssl_cache_free( &cache );
#endif
    jhd_tls_ctr_drbg_free( &ctr_drbg );
    jhd_tls_entropy_free( &entropy );

#if defined(_WIN32)
    jhd_tls_printf( "  Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret );
}
#endif /* JHD_TLS_BIGNUM_C && JHD_TLS_CERTS_C && JHD_TLS_ENTROPY_C &&
          JHD_TLS_SSL_TLS_C && JHD_TLS_SSL_SRV_C && JHD_TLS_NET_C &&
          JHD_TLS_RSA_C && JHD_TLS_CTR_DRBG_C && JHD_TLS_X509_CRT_PARSE_C
          && JHD_TLS_FS_IO && JHD_TLS_PEM_PARSE_C */

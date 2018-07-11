/*
 *  SSL session cache implementation
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
 * These session callbacks use a simple chained list
 * to store and retrieve the session information.
 */

#if !defined(JHD_TLS_CONFIG_FILE)
#include <tls/jhd_tls_config.h>
#else
#include JHD_TLS_CONFIG_FILE
#endif

#if defined(JHD_TLS_SSL_CACHE_C)

#if defined(JHD_TLS_PLATFORM_C)
#include <tls/jhd_tls_platform.h>
#else
#include <stdlib.h>
#define jhd_tls_calloc    calloc
#define jhd_tls_free      free
#endif

#include <tls/jhd_tls_ssl_cache.h>

#include <string.h>

void jhd_tls_ssl_cache_init( jhd_tls_ssl_cache_context *cache )
{
    memset( cache, 0, sizeof( jhd_tls_ssl_cache_context ) );

    cache->timeout = JHD_TLS_SSL_CACHE_DEFAULT_TIMEOUT;
    cache->max_entries = JHD_TLS_SSL_CACHE_DEFAULT_MAX_ENTRIES;

#if defined(JHD_TLS_THREADING_C)
    jhd_tls_mutex_init( &cache->mutex );
#endif
}

int jhd_tls_ssl_cache_get( void *data, jhd_tls_ssl_session *session )
{
    int ret = 1;
#if defined(JHD_TLS_HAVE_TIME)
    jhd_tls_time_t t = jhd_tls_time( NULL );
#endif
    jhd_tls_ssl_cache_context *cache = (jhd_tls_ssl_cache_context *) data;
    jhd_tls_ssl_cache_entry *cur, *entry;

#if defined(JHD_TLS_THREADING_C)
    if( jhd_tls_mutex_lock( &cache->mutex ) != 0 )
        return( 1 );
#endif

    cur = cache->chain;
    entry = NULL;

    while( cur != NULL )
    {
        entry = cur;
        cur = cur->next;

#if defined(JHD_TLS_HAVE_TIME)
        if( cache->timeout != 0 &&
            (int) ( t - entry->timestamp ) > cache->timeout )
            continue;
#endif

        if( session->ciphersuite != entry->session.ciphersuite ||
            session->compression != entry->session.compression ||
            session->id_len != entry->session.id_len )
            continue;

        if( memcmp( session->id, entry->session.id,
                    entry->session.id_len ) != 0 )
            continue;

        memcpy( session->master, entry->session.master, 48 );

        session->verify_result = entry->session.verify_result;

#if defined(JHD_TLS_X509_CRT_PARSE_C)
        /*
         * Restore peer certificate (without rest of the original chain)
         */
        if( entry->peer_cert.p != NULL )
        {
            if( ( session->peer_cert = jhd_tls_calloc( 1,
                                 sizeof(jhd_tls_x509_crt) ) ) == NULL )
            {
                ret = 1;
                goto exit;
            }

            jhd_tls_x509_crt_init( session->peer_cert );
            if( jhd_tls_x509_crt_parse( session->peer_cert, entry->peer_cert.p,
                                entry->peer_cert.len ) != 0 )
            {
                jhd_tls_free( session->peer_cert );
                session->peer_cert = NULL;
                ret = 1;
                goto exit;
            }
        }
#endif /* JHD_TLS_X509_CRT_PARSE_C */

        ret = 0;
        goto exit;
    }

exit:
#if defined(JHD_TLS_THREADING_C)
    if( jhd_tls_mutex_unlock( &cache->mutex ) != 0 )
        ret = 1;
#endif

    return( ret );
}

int jhd_tls_ssl_cache_set( void *data, const jhd_tls_ssl_session *session )
{
    int ret = 1;
#if defined(JHD_TLS_HAVE_TIME)
    jhd_tls_time_t t = jhd_tls_time( NULL ), oldest = 0;
    jhd_tls_ssl_cache_entry *old = NULL;
#endif
    jhd_tls_ssl_cache_context *cache = (jhd_tls_ssl_cache_context *) data;
    jhd_tls_ssl_cache_entry *cur, *prv;
    int count = 0;

#if defined(JHD_TLS_THREADING_C)
    if( ( ret = jhd_tls_mutex_lock( &cache->mutex ) ) != 0 )
        return( ret );
#endif

    cur = cache->chain;
    prv = NULL;

    while( cur != NULL )
    {
        count++;

#if defined(JHD_TLS_HAVE_TIME)
        if( cache->timeout != 0 &&
            (int) ( t - cur->timestamp ) > cache->timeout )
        {
            cur->timestamp = t;
            break; /* expired, reuse this slot, update timestamp */
        }
#endif

        if( memcmp( session->id, cur->session.id, cur->session.id_len ) == 0 )
            break; /* client reconnected, keep timestamp for session id */

#if defined(JHD_TLS_HAVE_TIME)
        if( oldest == 0 || cur->timestamp < oldest )
        {
            oldest = cur->timestamp;
            old = cur;
        }
#endif

        prv = cur;
        cur = cur->next;
    }

    if( cur == NULL )
    {
#if defined(JHD_TLS_HAVE_TIME)
        /*
         * Reuse oldest entry if max_entries reached
         */
        if( count >= cache->max_entries )
        {
            if( old == NULL )
            {
                ret = 1;
                goto exit;
            }

            cur = old;
        }
#else /* JHD_TLS_HAVE_TIME */
        /*
         * Reuse first entry in chain if max_entries reached,
         * but move to last place
         */
        if( count >= cache->max_entries )
        {
            if( cache->chain == NULL )
            {
                ret = 1;
                goto exit;
            }

            cur = cache->chain;
            cache->chain = cur->next;
            cur->next = NULL;
            prv->next = cur;
        }
#endif /* JHD_TLS_HAVE_TIME */
        else
        {
            /*
             * max_entries not reached, create new entry
             */
            cur = jhd_tls_calloc( 1, sizeof(jhd_tls_ssl_cache_entry) );
            if( cur == NULL )
            {
                ret = 1;
                goto exit;
            }

            if( prv == NULL )
                cache->chain = cur;
            else
                prv->next = cur;
        }

#if defined(JHD_TLS_HAVE_TIME)
        cur->timestamp = t;
#endif
    }

    memcpy( &cur->session, session, sizeof( jhd_tls_ssl_session ) );

#if defined(JHD_TLS_X509_CRT_PARSE_C)
    /*
     * If we're reusing an entry, free its certificate first
     */
    if( cur->peer_cert.p != NULL )
    {
        jhd_tls_free( cur->peer_cert.p );
        memset( &cur->peer_cert, 0, sizeof(jhd_tls_x509_buf) );
    }

    /*
     * Store peer certificate
     */
    if( session->peer_cert != NULL )
    {
        cur->peer_cert.p = jhd_tls_calloc( 1, session->peer_cert->raw.len );
        if( cur->peer_cert.p == NULL )
        {
            ret = 1;
            goto exit;
        }

        memcpy( cur->peer_cert.p, session->peer_cert->raw.p,
                session->peer_cert->raw.len );
        cur->peer_cert.len = session->peer_cert->raw.len;

        cur->session.peer_cert = NULL;
    }
#endif /* JHD_TLS_X509_CRT_PARSE_C */

    ret = 0;

exit:
#if defined(JHD_TLS_THREADING_C)
    if( jhd_tls_mutex_unlock( &cache->mutex ) != 0 )
        ret = 1;
#endif

    return( ret );
}

#if defined(JHD_TLS_HAVE_TIME)
void jhd_tls_ssl_cache_set_timeout( jhd_tls_ssl_cache_context *cache, int timeout )
{
    if( timeout < 0 ) timeout = 0;

    cache->timeout = timeout;
}
#endif /* JHD_TLS_HAVE_TIME */

void jhd_tls_ssl_cache_set_max_entries( jhd_tls_ssl_cache_context *cache, int max )
{
    if( max < 0 ) max = 0;

    cache->max_entries = max;
}

void jhd_tls_ssl_cache_free( jhd_tls_ssl_cache_context *cache )
{
    jhd_tls_ssl_cache_entry *cur, *prv;

    cur = cache->chain;

    while( cur != NULL )
    {
        prv = cur;
        cur = cur->next;

        jhd_tls_ssl_session_free( &prv->session );

#if defined(JHD_TLS_X509_CRT_PARSE_C)
        jhd_tls_free( prv->peer_cert.p );
#endif /* JHD_TLS_X509_CRT_PARSE_C */

        jhd_tls_free( prv );
    }

#if defined(JHD_TLS_THREADING_C)
    jhd_tls_mutex_free( &cache->mutex );
#endif
    cache->chain = NULL;
}

#endif /* JHD_TLS_SSL_CACHE_C */

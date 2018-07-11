/*
 *  Threading abstraction layer
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
#include <tls/jhd_tls_config.h"
#else
#include JHD_TLS_CONFIG_FILE
#endif

#if defined(JHD_TLS_THREADING_C)

#include <tls/jhd_tls_threading.h"

#if defined(JHD_TLS_THREADING_PTHREAD)
static void threading_mutex_init_pthread( jhd_tls_threading_mutex_t *mutex )
{
    if( mutex == NULL )
        return;

    mutex->is_valid = pthread_mutex_init( &mutex->mutex, NULL ) == 0;
}

static void threading_mutex_free_pthread( jhd_tls_threading_mutex_t *mutex )
{
    if( mutex == NULL || !mutex->is_valid )
        return;

    (void) pthread_mutex_destroy( &mutex->mutex );
    mutex->is_valid = 0;
}

static int threading_mutex_lock_pthread( jhd_tls_threading_mutex_t *mutex )
{
    if( mutex == NULL || ! mutex->is_valid )
        return( JHD_TLS_ERR_THREADING_BAD_INPUT_DATA );

    if( pthread_mutex_lock( &mutex->mutex ) != 0 )
        return( JHD_TLS_ERR_THREADING_MUTEX_ERROR );

    return( 0 );
}

static int threading_mutex_unlock_pthread( jhd_tls_threading_mutex_t *mutex )
{
    if( mutex == NULL || ! mutex->is_valid )
        return( JHD_TLS_ERR_THREADING_BAD_INPUT_DATA );

    if( pthread_mutex_unlock( &mutex->mutex ) != 0 )
        return( JHD_TLS_ERR_THREADING_MUTEX_ERROR );

    return( 0 );
}

void (*jhd_tls_mutex_init)( jhd_tls_threading_mutex_t * ) = threading_mutex_init_pthread;
void (*jhd_tls_mutex_free)( jhd_tls_threading_mutex_t * ) = threading_mutex_free_pthread;
int (*jhd_tls_mutex_lock)( jhd_tls_threading_mutex_t * ) = threading_mutex_lock_pthread;
int (*jhd_tls_mutex_unlock)( jhd_tls_threading_mutex_t * ) = threading_mutex_unlock_pthread;

/*
 * With phtreads we can statically initialize mutexes
 */
#define MUTEX_INIT  = { PTHREAD_MUTEX_INITIALIZER, 1 }

#endif /* JHD_TLS_THREADING_PTHREAD */

#if defined(JHD_TLS_THREADING_ALT)
static int threading_mutex_fail( jhd_tls_threading_mutex_t *mutex )
{
    ((void) mutex );
    return( JHD_TLS_ERR_THREADING_BAD_INPUT_DATA );
}
static void threading_mutex_dummy( jhd_tls_threading_mutex_t *mutex )
{
    ((void) mutex );
    return;
}

void (*jhd_tls_mutex_init)( jhd_tls_threading_mutex_t * ) = threading_mutex_dummy;
void (*jhd_tls_mutex_free)( jhd_tls_threading_mutex_t * ) = threading_mutex_dummy;
int (*jhd_tls_mutex_lock)( jhd_tls_threading_mutex_t * ) = threading_mutex_fail;
int (*jhd_tls_mutex_unlock)( jhd_tls_threading_mutex_t * ) = threading_mutex_fail;

/*
 * Set functions pointers and initialize global mutexes
 */
void jhd_tls_threading_set_alt( void (*mutex_init)( jhd_tls_threading_mutex_t * ),
                       void (*mutex_free)( jhd_tls_threading_mutex_t * ),
                       int (*mutex_lock)( jhd_tls_threading_mutex_t * ),
                       int (*mutex_unlock)( jhd_tls_threading_mutex_t * ) )
{
    jhd_tls_mutex_init = mutex_init;
    jhd_tls_mutex_free = mutex_free;
    jhd_tls_mutex_lock = mutex_lock;
    jhd_tls_mutex_unlock = mutex_unlock;

#if defined(JHD_TLS_FS_IO)
    jhd_tls_mutex_init( &jhd_tls_threading_readdir_mutex );
#endif
#if defined(JHD_TLS_HAVE_TIME_DATE)
    jhd_tls_mutex_init( &jhd_tls_threading_gmtime_mutex );
#endif
}

/*
 * Free global mutexes
 */
void jhd_tls_threading_free_alt( void )
{
#if defined(JHD_TLS_FS_IO)
    jhd_tls_mutex_free( &jhd_tls_threading_readdir_mutex );
#endif
#if defined(JHD_TLS_HAVE_TIME_DATE)
    jhd_tls_mutex_free( &jhd_tls_threading_gmtime_mutex );
#endif
}
#endif /* JHD_TLS_THREADING_ALT */

/*
 * Define global mutexes
 */
#ifndef MUTEX_INIT
#define MUTEX_INIT
#endif
#if defined(JHD_TLS_FS_IO)
jhd_tls_threading_mutex_t jhd_tls_threading_readdir_mutex MUTEX_INIT;
#endif
#if defined(JHD_TLS_HAVE_TIME_DATE)
jhd_tls_threading_mutex_t jhd_tls_threading_gmtime_mutex MUTEX_INIT;
#endif

#endif /* JHD_TLS_THREADING_C */

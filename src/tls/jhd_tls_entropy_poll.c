/*
 *  Platform-specific and custom entropy polling functions
 *
 *  Copyright (C) 2006-2016, ARM Limited, All Rights Reserved
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

#include <string.h>

#if defined(JHD_TLS_ENTROPY_C)

#include <tls/jhd_tls_entropy.h>
#include <tls/jhd_tls_entropy_poll.h>

#if defined(JHD_TLS_TIMING_C)
#include <tls/jhd_tls_timing.h>
#endif
#if defined(JHD_TLS_HAVEGE_C)
#include <tls/jhd_tls_havege.h>
#endif
#if defined(JHD_TLS_ENTROPY_NV_SEED)
#include <tls/jhd_tls_platform.h>
#endif

#if !defined(JHD_TLS_NO_PLATFORM_ENTROPY)

#if !defined(unix) && !defined(__unix__) && !defined(__unix) && \
    !defined(__APPLE__) && !defined(_WIN32) && !defined(__QNXNTO__)
#error "Platform entropy sources only work on Unix and Windows, see JHD_TLS_NO_PLATFORM_ENTROPY in config.h"
#endif

#if defined(_WIN32) && !defined(EFIX64) && !defined(EFI32)

#if !defined(_WIN32_WINNT)
#define _WIN32_WINNT 0x0400
#endif
#include <windows.h>
#include <wincrypt.h>

int jhd_tls_platform_entropy_poll( void *data, unsigned char *output, size_t len,
                           size_t *olen )
{
    HCRYPTPROV provider;
    ((void) data);
    *olen = 0;

    if( CryptAcquireContext( &provider, NULL, NULL,
                              PROV_RSA_FULL, CRYPT_VERIFYCONTEXT ) == FALSE )
    {
        return( JHD_TLS_ERR_ENTROPY_SOURCE_FAILED );
    }

    if( CryptGenRandom( provider, (DWORD) len, output ) == FALSE )
    {
        CryptReleaseContext( provider, 0 );
        return( JHD_TLS_ERR_ENTROPY_SOURCE_FAILED );
    }

    CryptReleaseContext( provider, 0 );
    *olen = len;

    return( 0 );
}
#else /* _WIN32 && !EFIX64 && !EFI32 */

/*
 * Test for Linux getrandom() support.
 * Since there is no wrapper in the libc yet, use the generic syscall wrapper
 * available in GNU libc and compatible libc's (eg uClibc).
 */
#if defined(__linux__) && defined(__GLIBC__)
#include <unistd.h>
#include <sys/syscall.h>
#if defined(SYS_getrandom)
#define HAVE_GETRANDOM

static int getrandom_wrapper( void *buf, size_t buflen, unsigned int flags )
{
    /* MemSan cannot understand that the syscall writes to the buffer */
#if defined(__has_feature)
#if __has_feature(memory_sanitizer)
    memset( buf, 0, buflen );
#endif
#endif

    return( syscall( SYS_getrandom, buf, buflen, flags ) );
}

#include <sys/utsname.h>
/* Check if version is at least 3.17.0 */
static int check_version_3_17_plus( void )
{
    int minor;
    struct utsname un;
    const char *ver;

    /* Get version information */
    uname(&un);
    ver = un.release;

    /* Check major version; assume a single digit */
    if( ver[0] < '3' || ver[0] > '9' || ver [1] != '.' )
        return( -1 );

    if( ver[0] - '0' > 3 )
        return( 0 );

    /* Ok, so now we know major == 3, check minor.
     * Assume 1 or 2 digits. */
    if( ver[2] < '0' || ver[2] > '9' )
        return( -1 );

    minor = ver[2] - '0';

    if( ver[3] >= '0' && ver[3] <= '9' )
        minor = 10 * minor + ver[3] - '0';
    else if( ver [3] != '.' )
        return( -1 );

    if( minor < 17 )
        return( -1 );

    return( 0 );
}
static int has_getrandom = -1;
#endif /* SYS_getrandom */
#endif /* __linux__ */

#include <stdio.h>

int jhd_tls_platform_entropy_poll( void *data,
                           unsigned char *output, size_t len, size_t *olen )
{
    FILE *file;
    size_t read_len;
    ((void) data);

#if defined(HAVE_GETRANDOM)
    if( has_getrandom == -1 )
        has_getrandom = ( check_version_3_17_plus() == 0 );

    if( has_getrandom )
    {
        int ret;

        if( ( ret = getrandom_wrapper( output, len, 0 ) ) < 0 )
            return( JHD_TLS_ERR_ENTROPY_SOURCE_FAILED );

        *olen = ret;
        return( 0 );
    }
#endif /* HAVE_GETRANDOM */

    *olen = 0;

    file = fopen( "/dev/urandom", "rb" );
    if( file == NULL )
        return( JHD_TLS_ERR_ENTROPY_SOURCE_FAILED );

    read_len = fread( output, 1, len, file );
    if( read_len != len )
    {
        fclose( file );
        return( JHD_TLS_ERR_ENTROPY_SOURCE_FAILED );
    }

    fclose( file );
    *olen = len;

    return( 0 );
}
#endif /* _WIN32 && !EFIX64 && !EFI32 */
#endif /* !JHD_TLS_NO_PLATFORM_ENTROPY */

#if defined(JHD_TLS_TEST_NULL_ENTROPY)
int jhd_tls_null_entropy_poll( void *data,
                    unsigned char *output, size_t len, size_t *olen )
{
    ((void) data);
    ((void) output);
    *olen = 0;

    if( len < sizeof(unsigned char) )
        return( 0 );

    *olen = sizeof(unsigned char);

    return( 0 );
}
#endif

#if defined(JHD_TLS_TIMING_C)
int jhd_tls_hardclock_poll( void *data,
                    unsigned char *output, size_t len, size_t *olen )
{
    unsigned long timer = jhd_tls_timing_hardclock();
    ((void) data);
    *olen = 0;

    if( len < sizeof(unsigned long) )
        return( 0 );

    memcpy( output, &timer, sizeof(unsigned long) );
    *olen = sizeof(unsigned long);

    return( 0 );
}
#endif /* JHD_TLS_TIMING_C */

#if defined(JHD_TLS_HAVEGE_C)
int jhd_tls_havege_poll( void *data,
                 unsigned char *output, size_t len, size_t *olen )
{
    jhd_tls_havege_state *hs = (jhd_tls_havege_state *) data;
    *olen = 0;

    if( jhd_tls_havege_random( hs, output, len ) != 0 )
        return( JHD_TLS_ERR_ENTROPY_SOURCE_FAILED );

    *olen = len;

    return( 0 );
}
#endif /* JHD_TLS_HAVEGE_C */

#if defined(JHD_TLS_ENTROPY_NV_SEED)
int jhd_tls_nv_seed_poll( void *data,
                          unsigned char *output, size_t len, size_t *olen )
{
    unsigned char buf[JHD_TLS_ENTROPY_BLOCK_SIZE];
    size_t use_len = JHD_TLS_ENTROPY_BLOCK_SIZE;
    ((void) data);

    memset( buf, 0, JHD_TLS_ENTROPY_BLOCK_SIZE );

    if( jhd_tls_nv_seed_read( buf, JHD_TLS_ENTROPY_BLOCK_SIZE ) < 0 )
      return( JHD_TLS_ERR_ENTROPY_SOURCE_FAILED );

    if( len < use_len )
      use_len = len;

    memcpy( output, buf, use_len );
    *olen = use_len;

    return( 0 );
}
#endif /* JHD_TLS_ENTROPY_NV_SEED */

#endif /* JHD_TLS_ENTROPY_C */

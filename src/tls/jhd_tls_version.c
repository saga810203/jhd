/*
 *  Version information
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

#if defined(JHD_TLS_VERSION_C)

#include <tls/jhd_tls_version.h"
#include <string.h>

unsigned int jhd_tls_version_get_number( void )
{
    return( JHD_TLS_VERSION_NUMBER );
}

void jhd_tls_version_get_string( char *string )
{
    memcpy( string, JHD_TLS_VERSION_STRING,
            sizeof( JHD_TLS_VERSION_STRING ) );
}

void jhd_tls_version_get_string_full( char *string )
{
    memcpy( string, JHD_TLS_VERSION_STRING_FULL,
            sizeof( JHD_TLS_VERSION_STRING_FULL ) );
}

#endif /* JHD_TLS_VERSION_C */

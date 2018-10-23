/**
 * \file config.h
 *
 * \brief Configuration options (set of defines)
 *
 *  This set of compile-time options may be used to enable
 *  or disable features selectively, and reduce the global
 *  memory footprint.
 */
/*
 *  Copyright (C) 2006-2018, ARM Limited, All Rights Reserved
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

#ifndef JHD_TLS_CONFIG_H
#define JHD_TLS_CONFIG_H
#include <limits.h>

#if defined(_MSC_VER)
#error "only supported linux"
#endif

#if CHAR_BIT != 8
#error "jhd_tls requires a platform with 8-bit chars"
#endif

#define JHD_TLS_HAVE_ASM

#include <tls/jhd_tls_check_config.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <sys/types.h>
#include <jhd_log.h>


#define JHD_TLS_COMMON_CHECK_RETURN_ERROR(X) if(X){return JHD_ERROR;}
#define JHD_TLS_COMMON_CHECK_GOTO_FUNC_ERROR(X) if(X){goto func_error;}
#define JHD_TLS_COMMON_CHECK_GOTO_CLEANUP(X) if(X){goto cleanup;}


#ifndef GET_UINT32_LE
#define GET_UINT32_LE(DST,SRC,x)  (DST) = *((uint32_t*)((SRC)+(x)))
#endif

#ifndef PUT_UINT32_LE
#define PUT_UINT32_LE(SRC,DST,x)  *((uint32_t*)((DST)+(x))) = (uint32_t)(SRC)
#endif

#define jhd_tls_platform_zeroize( buf, buf_len ) memset(buf,0,buf_len)


#define memcpy_64(DST,SRC)  *((uint64_t*)(DST)) = *((uint64_t*)(SRC));\
	*((uint64_t*)(8+(DST))) = *((uint64_t*)(8+(SRC)));\
	*((uint64_t*)(16+(DST))) = *((uint64_t*)(16+(SRC)));\
	*((uint64_t*)(24+DST)) = *((uint64_t*)(24+(SRC)));\
	*((uint64_t*)(32+(DST))) = *((uint64_t*)(32+(SRC)));\
	*((uint64_t*)(40+DST)) = *((uint64_t*)(40+(SRC)));\
	*((uint64_t*)(48+(DST))) = *((uint64_t*)(48+(SRC)));\
	*((uint64_t*)(56+DST)) = *((uint64_t*)(56+(SRC)))

#define memcpy_32(DST,SRC)  *((uint64_t*)(DST)) = *((uint64_t*)(SRC));\
	*((uint64_t*)(8+(DST))) = *((uint64_t*)(8+(SRC)));\
	*((uint64_t*)(16+(DST))) = *((uint64_t*)(16+(SRC)));\
	*((uint64_t*)(24+DST)) = *((uint64_t*)(24+(SRC)))

#define memcpy_16(DST,SRC)  *((uint64_t*)(DST)) = *((uint64_t*)(SRC));*((uint64_t*)(8+DST)) = *((uint64_t*)(8+(SRC)))
#define memcpy_8(DST,SRC)  *((uint64_t*)(DST)) = *((uint64_t*)(SRC))
#define memcpy_4(DST,SRC)  *((uint32_t*)(DST)) = *((uint32_t*)(SRC))

#define p128_eq_xor(DST,SRC)  *((uint64_t*)(DST)) ^= *((uint64_t*)(SRC)); *((uint64_t*)(DST+8)) ^= *((uint64_t*)(8+SRC))

#define p128_xor(DST,A,B)  *((uint64_t*)(DST)) = *((uint64_t*)(A)) ^ *((uint64_t*)(B));*((uint64_t*)(8+DST)) = *((uint64_t*)(8+A)) ^ *((uint64_t*)(8+B))

#define p64_eq_xor(DST,SRC)  *((uint64_t*)(DST)) ^= *((uint64_t*)(SRC))

#define p64_xor(DST,A,B)  *((uint64_t*)(DST)) = *((uint64_t*)(A)) ^ *((uint64_t*)(B))

#define mem_zero_4(DST)  *((uint32_t*)(DST)) = 0
#define mem_zero_8(DST)  *((uint64_t*)(DST)) = 0
#define mem_zero_16(DST)  *((uint64_t*)(DST)) = 0; *((uint64_t*)(8+(DST))) = 0
#define mem_zero_32(DST)  *((uint64_t*)(DST)) = 0; *((uint64_t*)(8+(DST))) = 0;*((uint64_t*)(16+(DST))) = 0; *((uint64_t*)(24+(DST))) = 0
#define mem_zero_64(DST)  *((uint64_t*)(DST)) = 0; *((uint64_t*)(8+(DST))) = 0;*((uint64_t*)(16+(DST))) = 0; *((uint64_t*)(24+(DST))) = 0;\
                          *((uint64_t*)(32+(DST))) = 0; *((uint64_t*)(40+(DST))) = 0;*((uint64_t*)(48+(DST))) = 0; *((uint64_t*)(56+(DST))) = 0

typedef  u_char jhd_tls_bool;
#define  jhd_tls_true    ((u_char)1)
#define  jhd_tls_false   ((u_char)0)

#define JHD_TLS_INLINE


void jhd_tls_noop_free(void* ptr);


int jhd_tls_config_init();






 extern pid_t jhd_pid;


#endif /* JHD_TLS_CONFIG_H */

/*
 * jhd_string.h
 *
 *  Created on: May 14, 2018
 *      Author: root
 */

#ifndef JHD_STRING_H_
#define JHD_STRING_H_

#include <jhd_config.h>
typedef u_char jhd_string;

#define JHD_MAX_INT64_T_VALUE  9223372036854775807

#define JHD_STRING_LEN(str)  ((*((uint16_t*)str)) & ( 1 << 15 ))

#define JHD_STRING_DATA(str) ((u_char*) (((u_char*)str)+2))


#define jhd_string_free(str) if(!((1<<15) & (*((uint16_t*)str)))){ jhd_free_original(str,(*((uint16_t*)str)));}

extern  u_char JHD_STRING_HEX[];


jhd_string* jhd_build_static_string(u_char* str);
jhd_string* jhd_build_static_string_with_len(u_char* str,size_t len);

jhd_string* jhd_build_string(u_char* str);
jhd_string* jhd_build_string_with_len(u_char* str,size_t len);

jhd_string* jhd_string_dup(jhd_string* str);

jhd_bool  jhd_string_equals(jhd_string* str1,jhd_string* str2);

int jhd_chars_to_u64(u_char *chars, size_t n,uint64_t *result);
int jhd_hex_to_u64(u_char *chars,size_t n,uint64_t *result);
int jhd_chars_to_u16(u_char *chars, size_t n,uint16_t *result);
int jhd_hex_to_u16(u_char *chars,size_t n,uint16_t *result);


u_char* jhd_u64_to_hex(u_char* last,uint64_t val);


jhd_bool jhd_static_string_equals(u_char* str1,size_t str1_len,u_char* str2,size_t str2_len);

#endif /* JHD_STRING_H_ */

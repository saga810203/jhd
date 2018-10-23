/*
 * jhd_string.c
 *
 *  Created on: 2018年5月18日
 *      Author: root
 */
#include<jhd_string.h>
#include<jhd_pool.h>
#include <jhd_log.h>

u_char JHD_STRING_HEX[] = "0123456789ABCDEF";

jhd_string* jhd_build_static_string(u_char* str) {
	u_char* ret;
	size_t len = strlen(str);
	ret = malloc(len + 3);
	if (ret) {
		*((uint16_t*) ret) = (uint16_t) (len | (1 << 15));
		ret += 2;
		strcpy(ret, str);
		return (jhd_string*) (ret - 2);
	}
	return NULL;
}

jhd_string* jhd_build_static_string_with_len(u_char* str, size_t len) {
	u_char* ret;
	ret = malloc(len + 3);
	if (ret) {
		*((uint16_t*) ret) = (uint16_t) (len | (1 << 15));
		ret += 2;
		memcpy(ret, str, len);
		ret[len] = '\0';
		return (jhd_string*) (ret - 2);
	}
	return NULL;
}

jhd_string* jhd_build_string(u_char* str) {
	u_char* ret;
	size_t len = strlen(str);
	ret = jhd_malloc(len + 1);
	if (ret) {
		*((uint16_t*) (ret - 2)) = (uint16_t) len;
		strcpy(ret, str);
		return (jhd_string*) (ret - 2);
	}
	return NULL;

}
jhd_string* jhd_build_string_with_len(u_char* str, size_t len) {
	u_char* ret;
	ret = jhd_malloc(len + 1);
	if (ret) {
		*((uint16_t*) (ret - 2)) = (uint16_t) (len);
		memcpy(ret, str, len);
		ret[len] = '\0';
		return (jhd_string*) (ret - 2);
	}
	return NULL;
}

jhd_string* jhd_string_dup(jhd_string* str) {
	u_char* ret;
	uint16_t len = *((uint16_t*) str);
	if (len & (1 << 15)) {
		return str;
	} else {
		ret = jhd_malloc(len + 1);
		if (ret) {
			*((uint16_t*) (ret - 2)) = len;
			memcpy(ret, ((u_char*) str) + 2, len);
			return (jhd_string*) (ret - 2);
		}
		return NULL;
	}
}
jhd_bool jhd_string_equals(jhd_string* str1, jhd_string* str2) {
	uint16_t len1, len2;
	u_char *p1, *p2;
	int i;
	if (str1 != str2) {
		len1 = JHD_STRING_LEN(str1);
		len2 = JHD_STRING_LEN(str2);
		if (len1 == len2) {
			p1 = JHD_STRING_DATA(str1);
			p2 = JHD_STRING_DATA(str2);
			for (i = 0; i < len1; ++i, ++p1, ++p2) {
				if ((*p1) != (*p2)) {
					return jhd_false;
				}
			}
			return jhd_true;
		} else {
			return jhd_false;
		}
	} else {
		return jhd_true;
	}
}


int jhd_chars_to_u64(u_char *chars, size_t n,uint64_t *result){
	uint64_t value, cutoff, cutlim;
	log_assert(n>0);
	log_assert(chars  != NULL);
	log_assert(result != NULL);

	cutoff = 0xFFFFFFFFFFFFFFFFULL / 10;
	cutlim = 0xFFFFFFFFFFFFFFFFULL % 10;

	for (value = 0; n--; ++chars) {
		if (*chars < '0' || *chars > '9') {
			return JHD_ERROR;
		}

		if (value > cutoff || ((value == cutoff) && (*chars - '0' > cutlim))) {
			return JHD_ERROR;
		}
		value = value * 10 + (*chars - '0');
	}
	*result = value;
	return JHD_OK;
}
int jhd_hex_to_u64(u_char *chars,size_t n,uint64_t *result){
	u_char ch;
	int i;
	uint64_t value, cutoff;
	log_assert(n>0);
	log_assert(chars  != NULL);
	log_assert(result != NULL);
	if(n>16){
		return JHD_ERROR;
	}
	value = 0;
	i = n;
	while(i >0){
		ch = *chars;
		--i;
		if (ch >= '0' && ch <= '9') {
			value <<=4;
			value += (ch - '0');
			continue;
		}
		ch |= 0x20;
		if (ch >= 'a' && ch <= 'f') {
			value <<=4;
			value += (ch - 'a' + 10);
			continue;
		}
		return JHD_ERROR;
	}
	*result = value;
	return JHD_OK;
}

int jhd_chars_to_u16(u_char *chars, size_t n,uint16_t *result){
	uint16_t value, cutoff, cutlim;
	log_assert(n>0);
	log_assert(chars  != NULL);
	log_assert(result != NULL);

	cutoff = 0xFFFF / 10;
	cutlim = 0xFFFF % 10;

	for (value = 0; n--; ++chars) {
		if (*chars < '0' || *chars > '9') {
			return JHD_ERROR;
		}

		if (value > cutoff || ((value == cutoff) && (*chars - '0' > cutlim))) {
			return JHD_ERROR;
		}
		value = value * 10 + (*chars - '0');
	}
	*result = value;
	return JHD_OK;
}
int jhd_hex_to_u16(u_char *chars,size_t n,uint16_t *result){
	u_char ch;
	int i;
	uint16_t value;
	log_assert(n>0);
	log_assert(chars  != NULL);
	log_assert(result != NULL);
	if(n>4){
		return JHD_ERROR;
	}
	value = 0;
	i = n;
	while(i >0){
		ch = *chars;
		--i;
		if (ch >= '0' && ch <= '9') {
			value <<=4;
			value += (ch - '0');
			continue;
		}
		ch |= 0x20;
		if (ch >= 'a' && ch <= 'f') {
			value <<=4;
			value += (ch - 'a' + 10);
			continue;
		}
		return JHD_ERROR;
	}
	*result = value;
	return JHD_OK;
}


u_char* jhd_u64_to_hex(u_char* last,uint64_t val){
	do {
		--last;
		*last = JHD_STRING_HEX[(uint32_t)(val & 0xf)];
	} while (val >>= 4);
	return last;
}

jhd_bool jhd_static_string_equals(u_char* str1,size_t str1_len,u_char* str2,size_t str2_len){
	if(str1_len== str1_len){
		int i ;
		for(i=0; i < str1_len;++i){
			if(str1[i] != str2[i]){
				return jhd_false;
			}
		}
		return jhd_true;
	}
	return jhd_false;

}

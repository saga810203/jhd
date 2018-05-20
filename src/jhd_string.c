/*
 * jhd_string.c
 *
 *  Created on: 2018年5月18日
 *      Author: root
 */
#include<jhd_core.h>

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
int64_t jhd_chars_to_uint64(u_char *chars, size_t n) {
	int64_t value, cutoff, cutlim;

	if (n == 0) {
		return JHD_ERROR;
	}

	cutoff = JHD_MAX_INT64_T_VALUE / 10;
	cutlim = JHD_MAX_INT64_T_VALUE % 10;

	for (value = 0; n--; ++chars) {
		if (*chars < '0' || *chars > '9') {
			return JHD_ERROR;
		}

		if (value >= cutoff && (value > cutoff || *chars - '0' > cutlim)) {
			return JHD_ERROR;
		}

		value = value * 10 + (*chars - '0');
	}
	return value;
}
int64_t jhd_hex_to_uint64(u_char *chars,size_t n){
	u_char c, ch;
	int64_t value, cutoff;

	if (n == 0) {
		return JHD_ERROR;
	}

	cutoff = JHD_MAX_INT64_T_VALUE / 16;

	for (value = 0; n--; ++chars) {
		if (value > cutoff) {
			return JHD_ERROR;
		}

		ch = *chars;

		if (ch >= '0' && ch <= '9') {
			value = value * 16 + (ch - '0');
			continue;
		}

		c = (u_char) (ch | 0x20);

		if (c >= 'a' && c <= 'f') {
			value = value * 16 + (c - 'a' + 10);
			continue;
		}
		return JHD_ERROR;
	}
	return value;
}
u_char* jhd_uint16_to_hex(u_char* last,uint32_t val){
	do {
		--last;
		*last = JHD_STRING_HEX[(uint32_t)(val & 0xf)];
	} while (val >>= 4);
	return last;
}


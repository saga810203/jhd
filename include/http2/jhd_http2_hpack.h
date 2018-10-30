/*
 * jhd_http2_hpack.h
 *
 *  Created on: Oct 30, 2018
 *      Author: root
 */

#ifndef HTTP2_JHD_HTTP2_HPACK_H_
#define HTTP2_JHD_HTTP2_HPACK_H_
#include <jhd_config.h>
#include <jhd_log.h>
#include <jhd_event.h>


typedef struct {
    u_char     *data;
    uint16_t  len;
} jhd_http2_hpack_string;


typedef struct{
		jhd_http2_hpack_string name;
		jhd_http2_hpack_string val;
} jhd_http2_hpack_header_item;



typedef struct {
		uint16_t  size;
		uint16_t  capacity;
		u_char*   data;
		u_char*   next;
		u_char**   index;
		uint16_t  rds_headers;
		uint16_t  bytes_headers;
}jhd_http2_hpack;


#define jhd_http2_hpack_string(str)     {  (u_char *) str,(uint16_t)(sizeof(str) - 1)}



int jhd_http2_hpack_init(jhd_http2_hpack *hpack,uint16_t size);
int jhd_http2_hpack_add(jhd_http2_hpack  *hpack,u_char* name,uint16_t name_len,u_char* val,uint16_t val_len);



int jhd_http2_hpack_resize(jhd_http2_hpack *hpack,uint16_t new_size,uint16_t *out_capacity);
void jhd_http2_hpack_get_index_header_item(jhd_http2_hpack *hpack,int32_t idx,u_char **name,uint16_t *name_len,u_char **val,uint16_t *val_len);
void jhd_http2_hpack_get_index_header_name(jhd_http2_hpack *hpack,int32_t idx,u_char **name,uint16_t *name_len);

int jhd_http2_hpack_find_item(jhd_http2_hpack *hpack,int32_t idx,u_char *name,uint16_t name_len,u_char *val,uint16_t val_len);
int jhd_http2_hpack_find_name(jhd_http2_hpack *hpack,int32_t idx,u_char *name,uint16_t *name_len);



jhd_inline uint16_t jhd_http2_hpack_calc_real_capacity(uint16_t size){
	uint16_t capacity = 4096;
	u_char* data;
	while(capacity < size){
		log_assert(capacity <=(0xFFFF - 4096));
		capacity+=4096;
	}
	return capacity;
}


#ifdef JHD_INLINE
#define jhd_http2_hpack_is_static(idx) ((idx) < 62)
#define jhd_http2_hpack_free(H)  jhd_free_with_size((H)->data,(H)->capacity)
#else



jhd_inline jhd_bool jhd_http2_hpack_is_static(uint32_t idx){
	return idx < 62;
}
jhd_inline void jhd_http2_hpack_free(jhd_http2_hpack *hpack){
     jhd_free_with_size(hpack->data,hpack->capacity);
}
#endif


#endif /* HTTP2_JHD_HTTP2_HPACK_H_ */

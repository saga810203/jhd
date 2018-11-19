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
#include <jhd_pool.h>
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
	uint32_t name_idx;
	uint32_t val_idx;
}jhd_http2_hpack_search_result;

typedef struct {
		uint16_t  size;
		uint16_t  capacity;
		u_char*   data;
		u_char*   next;
		u_char**   index;
		uint16_t  rds_headers;
		uint16_t  bytes_headers;
}jhd_http2_hpack;


extern jhd_http2_hpack_header_item jhd_http2_headers_static[];


#define jhd_http2_hpack_string(str)     {  (u_char *) str,(uint16_t)(sizeof(str) - 1)}


jhd_inline u_char* jhd_http2_hpack_static_name(u_char idx){
	return jhd_http2_headers_static[idx-1].name.data;
}

jhd_inline uint16_t* jhd_http2_hpack_static_name_len(u_char idx){
	return jhd_http2_headers_static[idx-1].name.len;
}


int jhd_http2_hpack_init(jhd_http2_hpack *hpack,uint16_t size);
int jhd_http2_hpack_add(jhd_http2_hpack  *hpack,u_char* name,uint16_t name_len,u_char* val,uint16_t val_len);



int jhd_http2_hpack_resize(jhd_http2_hpack *hpack,uint16_t new_size,u_char **old_hpack_data,uint16_t *out_capacity);
void jhd_http2_hpack_get_index_header_item(jhd_http2_hpack *hpack,uint32_t idx,u_char **name,uint16_t *name_len,u_char **val,uint16_t *val_len);
void jhd_http2_hpack_get_index_header_name(jhd_http2_hpack *hpack,uint32_t idx,u_char **name,uint16_t *name_len);

uint32_t jhd_http2_hpack_find_item(jhd_http2_hpack *hpack,u_char *name,uint16_t name_len,u_char *val,uint16_t val_len);
uint32_t jhd_http2_hpack_find_name(jhd_http2_hpack *hpack,u_char *name,uint16_t name_len);
uint32_t jhd_http2_hpack_find_static_name(u_char *name,uint16_t name_len);


void jhd_http2_hpack_search_item(jhd_http2_hpack *hpack,u_char *name,uint16_t name_len,u_char *val,uint16_t val_len,jhd_http2_hpack_search_result *result);

void jhd_http2_hpack_search_dynamic_item(jhd_http2_hpack *hpack,u_char *name,uint16_t name_len,u_char *val,uint16_t val_len,jhd_http2_hpack_search_result *result);




#ifdef JHD_INLINE
#define jhd_http2_hpack_is_static(idx) ((idx) < 62)
#define jhd_http2_hpack_is_dyncmic(idx)((idx) > 61)



#define jhd_http2_hpack_free(H)  jhd_free_with_size((H)->data,(H)->capacity)
#else



static jhd_inline jhd_bool jhd_http2_hpack_is_static(uint32_t idx){
	return idx < 62;
}

static jhd_inline jhd_bool jhd_http2_hpack_is_dyncmic(uint32_t idx){
	return idx > 61;
}
static jhd_inline void jhd_http2_hpack_free(jhd_http2_hpack *hpack){
     jhd_free_with_size(hpack->data,hpack->capacity);
}
#endif




int jhd_http2_hpack_parse_value(u_char *start,u_char *end,u_char **val,uint16_t *val_len,uint16_t *val_alloced,uint16_t *wait_mem_num);










#endif /* HTTP2_JHD_HTTP2_HPACK_H_ */

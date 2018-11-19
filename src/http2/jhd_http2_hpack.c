#include <http2/jhd_http2_hpack.h>








jhd_http2_hpack_header_item jhd_http2_headers_static[]={
	{ jhd_http2_hpack_string(":authority"), {jhd_empty_string,0} },
	{ jhd_http2_hpack_string(":method"), jhd_http2_hpack_string("GET") },
	{ jhd_http2_hpack_string(":method"), jhd_http2_hpack_string("POST") },
	{ jhd_http2_hpack_string(":path"), jhd_http2_hpack_string("/") },
	{ jhd_http2_hpack_string(":path"), jhd_http2_hpack_string("/index.html") },
	{ jhd_http2_hpack_string(":scheme"), jhd_http2_hpack_string("http") },
	{ jhd_http2_hpack_string(":scheme"), jhd_http2_hpack_string("https") },
	{ jhd_http2_hpack_string(":status"), jhd_http2_hpack_string("200") },
	{ jhd_http2_hpack_string(":status"), jhd_http2_hpack_string("204") },
	{ jhd_http2_hpack_string(":status"), jhd_http2_hpack_string("206") },
	{ jhd_http2_hpack_string(":status"), jhd_http2_hpack_string("304") },
	{ jhd_http2_hpack_string(":status"), jhd_http2_hpack_string("400") },
	{ jhd_http2_hpack_string(":status"), jhd_http2_hpack_string("404") },
	{ jhd_http2_hpack_string(":status"), jhd_http2_hpack_string("500") },
	{ jhd_http2_hpack_string("accept-charset"), {jhd_empty_string,0} },
	{ jhd_http2_hpack_string("accept-encoding"), jhd_http2_hpack_string("gzip, deflate") },
	{ jhd_http2_hpack_string("accept-language"), {jhd_empty_string,0} },
	{ jhd_http2_hpack_string("accept-ranges"), {jhd_empty_string,0} },
	{ jhd_http2_hpack_string("accept"), {jhd_empty_string,0} },
	{ jhd_http2_hpack_string("access-control-allow-origin"), {jhd_empty_string,0} },
	{ jhd_http2_hpack_string("age"), {jhd_empty_string,0} },
	{ jhd_http2_hpack_string("allow"), {jhd_empty_string,0} },
	{ jhd_http2_hpack_string("authorization"), {jhd_empty_string,0} },
	{ jhd_http2_hpack_string("cache-control"), {jhd_empty_string,0} },
	{ jhd_http2_hpack_string("content-disposition"), {jhd_empty_string,0} },
	{ jhd_http2_hpack_string("content-encoding"), {jhd_empty_string,0} },
	{ jhd_http2_hpack_string("content-language"), {jhd_empty_string,0} },
	{ jhd_http2_hpack_string("content-length"), {jhd_empty_string,0} },
	{ jhd_http2_hpack_string("content-location"), {jhd_empty_string,0} },
	{ jhd_http2_hpack_string("content-range"), {jhd_empty_string,0} },
	{ jhd_http2_hpack_string("content-type"), {jhd_empty_string,0} },
	{ jhd_http2_hpack_string("cookie"), {jhd_empty_string,0} },
	{ jhd_http2_hpack_string("date"), {jhd_empty_string,0} },
	{ jhd_http2_hpack_string("etag"), {jhd_empty_string,0} },
	{ jhd_http2_hpack_string("expect"), {jhd_empty_string,0} },
	{ jhd_http2_hpack_string("expires"), {jhd_empty_string,0} },
	{ jhd_http2_hpack_string("from"), {jhd_empty_string,0} },
	{ jhd_http2_hpack_string("host"), {jhd_empty_string,0} },
	{ jhd_http2_hpack_string("if-match"), {jhd_empty_string,0} },
	{ jhd_http2_hpack_string("if-modified-since"), {jhd_empty_string,0} },
	{ jhd_http2_hpack_string("if-none-match"), {jhd_empty_string,0} },
	{ jhd_http2_hpack_string("if-range"), {jhd_empty_string,0} },
	{ jhd_http2_hpack_string("if-unmodified-since"), {jhd_empty_string,0} },
	{ jhd_http2_hpack_string("last-modified"), {jhd_empty_string,0} },
	{ jhd_http2_hpack_string("link"), {jhd_empty_string,0} },
	{ jhd_http2_hpack_string("location"), {jhd_empty_string,0} },
	{ jhd_http2_hpack_string("max-forwards"), {jhd_empty_string,0} },
	{ jhd_http2_hpack_string("proxy-authenticate"), {jhd_empty_string,0} },
	{ jhd_http2_hpack_string("proxy-authorization"), {jhd_empty_string,0} },
	{ jhd_http2_hpack_string("range"), {jhd_empty_string,0} },
	{ jhd_http2_hpack_string("referer"), {jhd_empty_string,0} },
	{ jhd_http2_hpack_string("refresh"), {jhd_empty_string,0} },
	{ jhd_http2_hpack_string("retry-after"), {jhd_empty_string,0} },
	{ jhd_http2_hpack_string("server"), {jhd_empty_string,0} },
	{ jhd_http2_hpack_string("set-cookie"), {jhd_empty_string,0} },
	{ jhd_http2_hpack_string("strict-transport-security"), {jhd_empty_string,0} },
	{ jhd_http2_hpack_string("transfer-encoding"), {jhd_empty_string,0} },
	{ jhd_http2_hpack_string("user-agent"), {jhd_empty_string,0} },
	{ jhd_http2_hpack_string("vary"), {jhd_empty_string,0} },
	{ jhd_http2_hpack_string("via"), {jhd_empty_string,0} },
	{ jhd_http2_hpack_string("www-authenticate"), {jhd_empty_string,0} },
};



int jhd_http2_hpack_init(jhd_http2_hpack *hpack,uint16_t size){
	log_assert(size % 4096  == 0);
	if(size > 0){
		hpack->data = jhd_alloc(size);
		if(hpack->data){
			hpack->next = hpack->data;
			hpack->index= (u_char**)(((uint64_t)hpack->data)  + ((uint64_t)hpack->capacity));
			hpack->capacity = size;
			hpack->size = size;
		}else{

			return JHD_AGAIN;
		}
	}
	return  JHD_OK;
}

void jhd_http2_hpack_remove(jhd_http2_hpack *hpack,uint16_t size){
	u_char* b_index;
	u_char** index;
	uint16_t real_size;
	uint16_t f_len;
	uint16_t num;
	int i;

	num=0;
	real_size = 0;
	b_index = hpack->data;
	while(real_size < size){
		f_len = *((uint16_t*)b_index);
		real_size+=f_len;
		b_index+=(sizeof(uint16_t)+f_len+1);
		f_len = *((uint16_t*)b_index);
		real_size+=f_len;
		b_index+=(sizeof(uint16_t)+f_len+1);
		real_size+=32;
		++num;
	}
	hpack->bytes_headers-=real_size;
	hpack->rds_headers -=num;
	if(hpack->rds_headers){
		memcpy(hpack->data,b_index, hpack->bytes_headers - (32 - (sizeof(uint16_t) * 2)-1)) ;
		hpack->next = hpack->data + hpack->bytes_headers - (32 - (sizeof(uint16_t) * 2)-1);
		i = 0 ;
		b_index = hpack->data;
		hpack->index = (u_char**)(((uint64_t)hpack->data)  + ((uint64_t)hpack->capacity) - (sizeof(void*) * hpack->rds_headers));
		index =(u_char**) hpack->index;
		if(hpack->rds_headers){
			i=0;
			index[i++] = b_index;
			do{
				f_len = *((uint16_t*)b_index);
				b_index+=(sizeof(uint16_t)+f_len+1);
				f_len = *((uint16_t*)b_index);
				b_index+=(sizeof(uint16_t)+f_len+1);
				index[i++] = b_index;
			}while(i< hpack->rds_headers);
		}
	}else{
		hpack->next = hpack->data;
	}
}

int jhd_http2_hpack_add(jhd_http2_hpack  *hpack,u_char* name,uint16_t name_len,u_char* val,uint16_t val_len){
	u_char* p,*n;
	uint16_t size ;

	log_assert(name_len <= 128);
	log_assert(val_len <= 8192);

	size = name_len + val_len+32;
	if(size > hpack->size){
		return JHD_ERROR;
	}
	if((hpack->size - hpack->bytes_headers) < size){
		jhd_http2_hpack_remove(hpack,size);
	}
	p = n = hpack->next;
	*((uint16_t*)p) =name_len;
	p+=sizeof(uint16_t);
	memcpy(p,name,name_len);
	p+=name_len;
	*p = 0;
	++p;
	*((uint16_t*)p) = val_len;
	p+=sizeof(uint16_t);
	if(val_len){
		memcpy(p,val,val_len);
		p+=val_len;
	}
	*p=0;
	++p;
	hpack->next = p;

	hpack->bytes_headers+=size;

	p = (u_char*)hpack->index;
	p -=sizeof(void*);
	if(hpack->rds_headers){
		memmove(p,hpack->index,sizeof(void*)* hpack->rds_headers);
	}
	hpack->index = (u_char**)p;
	hpack->index[hpack->rds_headers++] = n;
	return JHD_OK;
}



int jhd_http2_hpack_resize(jhd_http2_hpack *hpack,uint16_t new_size,u_char **old_data,uint16_t *capacity_size){
	uint16_t new_capacity;
	int64_t delta;
	u_char* new_data;
	u_char** new_index;
	int i ;
	if(new_size == 0){
		if(hpack->capacity != 0){
			*old_data = hpack->data;
			*capacity_size = hpack->capacity;
			memset(hpack,0,sizeof(jhd_http2_hpack));
			return JHD_OK;

		}
        return JHD_OK;
	}else{
		new_capacity = 4096;
		while(new_capacity< new_size){
			if(new_capacity > (65535 - 4096)){
				return JHD_ERROR;
			}
			new_capacity+=4096;
		}
	}

	log_assert(new_size <= new_capacity);
	log_assert(new_capacity % 4096 ==0);

	if(hpack->capacity == 0){
		return jhd_http2_hpack_init(hpack,new_size);
	}
	if(new_size > hpack->size){
		if(new_size <= hpack->capacity){
			hpack->size = new_size;
		}else{
			new_data = jhd_alloc(new_capacity);
			if(new_data){
				memcpy(new_data,hpack->data,hpack->size);
				delta = ((int64_t)new_data) -((int64_t)hpack->data);
				new_index = (u_char **)(new_data  + new_capacity - (sizeof(void*) * hpack->rds_headers));

				for(i=0;i< hpack->rds_headers;++i){
					new_index[i] = hpack->index[i]+delta;
				}
				*old_data = hpack->data;
				*capacity_size = hpack->capacity;
				hpack->data = new_data;
				hpack->capacity = new_capacity;
				hpack->index = new_index;
				hpack->next +=delta;
				hpack->size = new_size;
				return JHD_OK;
			}else{
				*capacity_size = new_capacity;
				return JHD_AGAIN;
			}
		}
	}else if(new_size<hpack->size){
		if(hpack->bytes_headers>new_size){
			jhd_http2_hpack_remove(hpack,hpack->bytes_headers- new_size);
		}
		hpack->size = new_size;
		return JHD_OK;
	}
	return JHD_OK;
}
void jhd_http2_hpack_get_index_header_item(jhd_http2_hpack *hpack,uint32_t idx,u_char **name,uint16_t *name_len,u_char **val,uint16_t *val_len){
	u_char *p;
	log_assert(idx >0);
	--idx;
	if(idx< 61){
		*name = jhd_http2_headers_static[idx].name.data;
		*name_len = jhd_http2_headers_static[idx].name.len;
		*val = jhd_http2_headers_static[idx].val.data;
		*val_len = jhd_http2_headers_static[idx].val.len;
	}else{
		idx -= 61;
		if(idx<hpack->rds_headers){
			p =hpack->index[idx];
			*name_len = *((uint16_t*)p);
			p+=sizeof(uint16_t);
			*name = p;
			p+= *name_len;
			++p;
			*val_len =  *((uint16_t*)p);
			*val = p + sizeof(uint16_t);
		}
	}
}
void jhd_http2_hpack_get_index_header_name(jhd_http2_hpack *hpack,uint32_t idx,u_char **name,uint16_t *name_len){
	u_char *p;
	log_assert(idx >0);
	--idx;
	if(idx< 61){
		*name = jhd_http2_headers_static[idx].name.data;
		*name_len = jhd_http2_headers_static[idx].name.len;
	}else{
		idx -= 61;
		if(idx<hpack->rds_headers){
			p =hpack->index[idx];
			*name_len = *((uint16_t*)p);
			p+=sizeof(uint16_t);
			*name = p;
		}
	}
}

uint32_t jhd_http2_hpack_find_item(jhd_http2_hpack *hpack,u_char *name,uint16_t name_len,u_char *val,uint16_t val_len){
	uint32_t i;
	u_char *p;
	jhd_http2_hpack_header_item *static_item = jhd_http2_headers_static;
	for(static_item = jhd_http2_headers_static,i = 0 ; i < 61; ++i,++static_item){
		if(static_item->name.len == name_len){
			if(static_item->val.len == val_len){
				if(memcmp(static_item->name.data,name,name_len)==0){
					if(memcmp(static_item->val.data,val,val_len)==0){
						return i+1;
					}
				}
			}
		}
	}

	for(i = 0 ; i < hpack->rds_headers ; ++i){
		p =hpack->index[i];
		if(name_len ==(*((uint16_t*)p))){
			p+=sizeof(uint16_t);
			if(val_len ==(*((uint16_t*)(p+name_len +1)))){
				if(memcmp(p,name,name_len)==0){
					p+=(name_len + 1 + sizeof(uint16_t));
					if(memcmp(p,val,val_len)==0){
						return i + 62;
					}
				}
			}

		}
	}
	return 0;
}


void jhd_http2_hpack_search_item(jhd_http2_hpack *hpack,u_char *name,uint16_t name_len,u_char *val,uint16_t val_len,jhd_http2_hpack_search_result *result){
	uint32_t i;
	u_char *p;
	jhd_http2_hpack_header_item *static_item = jhd_http2_headers_static;

	log_assert(result->name_idx == 0  &&  result->val_idx == 0);

	for(static_item = jhd_http2_headers_static,i = 0 ; i < 61; ++i,++static_item){
		if(static_item->name.len == name_len){
			if(memcmp(static_item->name.data,name,name_len)==0){
				if(result->name_idx == 0){
					result->name_idx = i+1;
				}
				if(static_item->val.len == val_len){
					if(memcmp(static_item->val.data,val,val_len)==0){
						result->val_idx = i+i;
						return;
					}
				}
			}
		}
	}
	for(i = 0 ; i < hpack->rds_headers ; ++i){
		p =hpack->index[i];
		if(name_len ==(*((uint16_t*)p))){
			p+=sizeof(uint16_t);
			if(memcmp(p,name,name_len)==0){
				if(result->name_idx == 0){
					result->name_idx = i+62;
				}
				++p;
				p+=name_len;
				if(val_len ==(*((uint16_t*)p))){

					p+= sizeof(uint16_t);
					if(memcmp(p,val,val_len)==0){
						result->val_idx = i+62;
						return;
					}
				}
			}
		}
	}
}

void jhd_http2_hpack_search_dynamic_item(jhd_http2_hpack *hpack,u_char *name,uint16_t name_len,u_char *val,uint16_t val_len,jhd_http2_hpack_search_result *result){
	uint32_t i;
	u_char *p;
	jhd_http2_hpack_header_item *static_item = jhd_http2_headers_static;

	log_assert(result->name_idx == 0  &&  result->val_idx == 0);

	for(i = 0 ; i < hpack->rds_headers ; ++i){
		p =hpack->index[i];
		if(name_len ==(*((uint16_t*)p))){
			p+=sizeof(uint16_t);
			if(memcmp(p,name,name_len)==0){
				if(result->name_idx == 0){
					result->name_idx = i+62;
				}
				++p;
				p+=name_len;
				if(val_len ==(*((uint16_t*)p))){

					p+= sizeof(uint16_t);
					if(memcmp(p,val,val_len)==0){
						result->val_idx = i+62;
						return;
					}
				}
			}
		}
	}
}


uint32_t jhd_http2_hpack_find_static_name(u_char *name,uint16_t name_len){
	uint32_t i;
	u_char *p;
	jhd_http2_hpack_header_item *static_item = jhd_http2_headers_static;
	for(static_item = jhd_http2_headers_static,i = 0 ; i < 61; ++i,++static_item){
		if(static_item->name.len == name_len){
			if(memcmp(static_item->name.data,name,name_len)==0){
					return i+1;
			}
		}
	}
	return 0;
}


uint32_t jhd_http2_hpack_find_name(jhd_http2_hpack *hpack,u_char *name,uint16_t name_len){
	uint32_t i;
	u_char *p;
	jhd_http2_hpack_header_item *static_item = jhd_http2_headers_static;
	for(static_item = jhd_http2_headers_static,i = 0 ; i < 61; ++i,++static_item){
		if(static_item->name.len == name_len){
			if(memcmp(static_item->name.data,name,name_len)==0){
					return i+1;
			}
		}
	}
	for(i = 0 ; i < hpack->rds_headers ; ++i){
		p =hpack->index[i];
		if(name_len ==(*((uint16_t*)p))){
			p+=sizeof(uint16_t);
			if(memcmp(p,name,name_len)==0){
					return i + 62;
			}
		}
	}
	return 0;
}

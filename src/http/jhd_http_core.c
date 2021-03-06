#include <jhd_config.h>
#include <jhd_log.h>
#include <jhd_queue.h>
#include <http/jhd_http_core.h>
#include <http2/jhd_http2_response_send.h>

jhd_queue_t  jhd_http_serveres={&jhd_http_serveres,&jhd_http_serveres};

jhd_queue_t  jhd_http_content_type_queue = {&jhd_http_content_type_queue,&jhd_http_content_type_queue};


const u_char *default_http_content_type =(u_char*)"application/octet-stream";
const u_char  default_http_content_type_len = sizeof("application/octet-stream") -1;

const char *default_jhd_http_bad_request_context= "<html>\n"
		"<head><title>400 Bad Request</title></head>\n"
		"<body bgcolor=\"white\">\n"
		"<center><h1>400 Bad Request</h1></center>\n"
		"<hr><center>jhttpd</center>\n"
		"</body>\n"
		"</html>";

u_char *jhd_http_bad_request_context ;

uint16_t jhd_http_bad_request_context_len = sizeof("<html>\n"
		"<head><title>400 Bad Request</title></head>\n"
		"<body bgcolor=\"white\">\n"
		"<center><h1>400 Bad Request</h1></center>\n"
		"<hr><center>jhttpd</center>\n"
		"</body>\n"
		"</html>") - 1;



const u_char *default_jhd_http_412_request_context=(u_char*) "<html>\n"
		"<head><title>412 Precondition Failed</title></head>\n"
		"<body bgcolor=\"white\">\n"
		"<center><h1>412 Precondition Failed</h1></center>\n"
		"<hr><center>jhttpd</center>\n"
		"</body>\n"
		"</html>";

const char *jhd_http_412_request_context ;

uint16_t jhd_http_412_request_context_len = sizeof("<html>\n"
		"<head><title>412 Precondition Failed</title></head>\n"
		"<body bgcolor=\"white\">\n"
		"<center><h1>412 Precondition Failed</h1></center>\n"
		"<hr><center>jhttpd</center>\n"
		"</body>\n"
		"</html>") - 1;



const u_char *default_jhd_http_nofound_request_context= (u_char*)"<html>\n"
		"<head><title>404 NOT FOUND</title></head>\n"
		"<body bgcolor=\"white\">\n"
		"<center><h1>404 NOT FOUND</h1></center>\n"
		"<hr><center>jhttpd</center>\n"
		"</body>\n"
		"</html>";

u_char *jhd_http_nofound_request_context ;

uint16_t jhd_http_nofound_request_context_len = sizeof("<html>\n"
		"<head><title>404 NOT FOUND</title></head>\n"
		"<body bgcolor=\"white\">\n"
		"<center><h1>404 NOT FOUND</h1></center>\n"
		"<hr><center>jhttpd</center>\n"
		"</body>\n"
		"</html>") - 1;


const u_char *default_jhd_http_internal_error_request_context= (u_char*)"<html>\n"
		"<head><title>500 Internal Error</title></head>\n"
		"<body bgcolor=\"white\">\n"
		"<center><h1>500 Internal Error</h1></center>\n"
		"<hr><center>jhttpd</center>\n"
		"</body>\n"
		"</html>";

u_char *jhd_http_internal_error_request_context ;

uint16_t jhd_http_internal_error_request_context_len = sizeof("<html>\n"
		"<head><title>500 Internal Error</title></head>\n"
		"<body bgcolor=\"white\">\n"
		"<center><h1>500 Internal Error</h1></center>\n"
		"<hr><center>jhttpd</center>\n"
		"</body>\n"
		"</html>") - 1;

void jhd_http_content_type_queue_free(){
	jhd_queue_t *q;
	jhd_http_header *header;
	while(jhd_queue_has_item(&jhd_http_content_type_queue)){
		q = jhd_http_content_type_queue.next;
		jhd_queue_only_remove(q);
		header = jhd_queue_data(q,jhd_http_header,queue);
		free(header->name);
		free(header->value);
		free(header);
	}
}

int jhd_http_content_type_add(u_char *ext,u_char ext_len,u_char *content_type,uint16_t content_type_len){
	jhd_http_header *header,*ih;
	jhd_queue_t *head,*q;
	log_assert_master();

	header = malloc(sizeof(jhd_http_header));
	if(header){
		header ->value = NULL;
		header ->name = malloc(ext_len+1);
		if(header->name){
			memcpy(header->name,ext,ext_len);
			header->name[ext_len] = 0;
			header->name_len = ext_len;
			header ->value =malloc(content_type_len+1);
			if(header->value){
				memcpy(header->value,content_type,content_type_len);
				header->value[content_type_len] = 0;
				header->value_len = content_type_len;
				head = &jhd_http_content_type_queue;
				for(q = jhd_queue_next(head); q!=head;){
					ih = jhd_queue_data(q,jhd_http_header,queue);
					if(ih->name_len > ext_len){
						q = jhd_queue_prev(q);
						jhd_queue_insert_after(q,&header->queue);
						return JHD_OK;
					}else if(ih->name_len == ext_len &&(0 < memcmp(ih->name,ext,ext_len))){
						q = jhd_queue_prev(q);
						jhd_queue_insert_after(q,&header->queue);
						return JHD_OK;
					}
				}
				jhd_queue_insert_tail(head,&header->queue);
				return JHD_OK;
			}
		}
		goto func_error;
		return JHD_OK;
	}
func_error:
	if(header){
		if(header->value){
			free(header->value);
		}
		free(header);
	}
	jhd_http_content_type_queue_free();
	return JHD_ERROR;
}

void jhd_http_content_type_get(u_char *ext,u_char ext_len,u_char **content_type,uint16_t *content_type_len){
	int rc;
	jhd_queue_t *head,*q;
	jhd_http_header *header;

	head = &jhd_http_content_type_queue;

	for(q = jhd_queue_next(head);q != head;q= jhd_queue_next(q)){
		header = jhd_queue_data(q,jhd_http_header,queue);

		if(header->name_len > ext_len){
			break;
		}else if(header->name_len == ext_len ){
			rc = memcmp(ext,header->name,ext_len);
			if(rc == 0){
				*content_type = header->value;
				*content_type_len = header->value_len;
				return;
			}else if(rc > 0){
				break;
			}
		}
	}
	*content_type =(u_char*) default_http_content_type;
	*content_type_len = default_http_content_type_len;
}

void jhd_http_listening_context_free_with_single_server(void *ctx){
	log_assert(((jhd_http_listening_context*)ctx) != NULL);
	log_assert(((jhd_http_listening_context*)ctx)->data != NULL);
	log_assert(((jhd_http_listening_context*)ctx)->capcity == 0);
	log_assert(((jhd_http_listening_context*)ctx)->size == 0);
	log_assert_master();
	free(ctx);
}

void jhd_http_listening_context_free_with_mulitple_server(void *ctx){
	log_assert(((jhd_http_listening_context*)ctx) != NULL);
	log_assert(((jhd_http_listening_context*)ctx)->data != NULL);
	log_assert(((jhd_http_listening_context*)ctx)->capcity != 0);
	log_assert(((jhd_http_listening_context*)ctx)->size != 0);
	log_assert(((jhd_http_listening_context*)ctx)->capcity >((jhd_http_listening_context*)ctx)->size);
	log_assert_master();
	free(((jhd_http_listening_context*)ctx)->data);
	free(ctx);
}


void jhd_http_free_all_http_server(){
	jhd_queue_t *head,*q;
	jhd_http_server  *svr;
	jhd_http_service *svs;
	while(jhd_queue_has_item(&jhd_http_serveres)){
		q = jhd_http_serveres.next;
		jhd_queue_only_remove(q);
		svr = jhd_queue_data(q,jhd_http_server,queue);

		head  = &((jhd_http_server*)svr)->services;
		for(q = jhd_queue_next(head); q!= head;){
			svs = jhd_queue_data(q,jhd_http_service,queue);
			q = jhd_queue_next(q);
			svs->server_ctx_free_func(svs->service_ctx);
			free(svs);
		}
		free(svr);
	}
}



int jhd_http_single_server_handler(void *lis_ctx_data,jhd_http_request *r){
	jhd_queue_t *head,*q;
	jhd_http_service *svs;
	head  = &((jhd_http_server*)lis_ctx_data)->services;
	for(q = jhd_queue_next(head); q!= head; q = jhd_queue_next(q)){
		svs = jhd_queue_data(q,jhd_http_service,queue);
		if(svs->match(svs->service_ctx,r)){
			r->http_service = svs;
			return svs->service_func(r);
		}
	}
	q = head->prev;
	svs =jhd_queue_data(q,jhd_http_service,queue);
	r->http_service = svs;
	return svs->service_func(r);
}


int jhd_http_mulitple_server_handler(void *lis_ctx_data,jhd_http_request *r){
	jhd_queue_t *head,*q;
	jhd_http_service *svs;
	jhd_http_server  **svr;

	svr = lis_ctx_data;
	if(r->host.len){
		do{
			if(r->host.len >= (*svr)->host_len && memcmp(r->host.data,(*svr)->host,(*svr)->host_len)==0){
					head  = &((*svr)->services);
					for(q = jhd_queue_next(head); q!= head; q = jhd_queue_next(q)){
						svs = jhd_queue_data(q,jhd_http_service,queue);
						if(svs->match(svs->service_ctx,r)){
							r->http_service = svs;
							return svs->service_func(r);
						}
					}
					q = head->prev;
					svs =jhd_queue_data(q,jhd_http_service,queue);
					r->http_service = svs;
					return svs->service_func(r);
			}
			++svr;
		}while(*svr != NULL);
	}
	svr = lis_ctx_data;

	head  = &((*svr)->services);
	for(q = jhd_queue_next(head); q!= head; q = jhd_queue_next(q)){
		svs = jhd_queue_data(q,jhd_http_service,queue);
		if(svs->match(svs->service_ctx,r)){
			r->http_service = svs;
			return svs->service_func(r);
		}
	}
	q = head->prev;
	svs =jhd_queue_data(q,jhd_http_service,queue);
	r->http_service = svs;
	return svs->service_func(r);
}



void jhd_http_request_init_by_http11(jhd_http_request *r,jhd_event_t *ev){}






void jhd_http_request_handle_with_bad_by_http11(jhd_http_request *r){}
void jhd_http_request_handle_with_nofound_by_http11(jhd_http_request *r){}
void jhd_http_request_handle_with_internal_error_by_http11(jhd_http_request *r){}

void jhd_http_request_handle_with_bad(jhd_http_request *r){
	log_assert(jhd_queue_empty(&r->headers));
	if(r->is_http2){
		jhd_http2_send_cached_response(r,400,jhd_http_bad_request_context,jhd_http_bad_request_context_len);
	}else{
		jhd_http2_send_cached_response(r,400,jhd_http_bad_request_context,jhd_http_bad_request_context_len);
	}
}
void jhd_http_request_handle_with_nofound(jhd_http_request *r){
	log_assert(jhd_queue_emtpy(&r->headers));
	if(r->is_http2){
		jhd_http2_send_cached_response(r,404,jhd_http_nofound_request_context,jhd_http_nofound_request_context_len);
	}else{
		jhd_http11_send_cached_response(r,404,jhd_http_nofound_request_context,jhd_http_nofound_request_context_len);
	}
}
void jhd_http_request_handle_with_internal_error(jhd_http_request *r){
	log_assert(jhd_queue_emtpy(&r->headers));
	if(r->is_http2){
		jhd_http2_send_cached_response(r,500,jhd_http_internal_error_request_context,jhd_http_internal_error_request_context_len);
	}else{
		jhd_http2_send_cached_response(r,500,jhd_http_internal_error_request_context,jhd_http_internal_error_request_context_len);
	}
}

void jhd_http_request_handle_with_not_modified(jhd_http_request *r){
	log_assert(jhd_queue_emtpy(&r->headers));
	if(r->is_http2){
		jhd_http2_send_not_modified_response(r);
	}else{
		jhd_http_request_handle_with_not_modified_by_http11(r);
	}
}









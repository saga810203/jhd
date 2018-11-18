#include <jhd_config.h>
#include <jhd_log.h>
#include <http/jhd_http_core.h>

jhd_queue_t  jhd_http_serveres={&jhd_http_serveres,&jhd_http_serveres};


void jhd_http_listening_context_free(void *ctx){
	log_assert(ctx != NULL);
	log_assert_master();
	if(((jhd_http_listening_context*)ctx)->data){
		free(((jhd_http_listening_context*)ctx)->data);
		((jhd_http_listening_context*)ctx)->data = NULL;
	}
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



int jhd_http_single_server_handler(void *svr,jhd_http_request *r){
	jhd_queue_t *head,*q;
	jhd_http_service *svs;
	head  = &((jhd_http_server*)svr)->services;
	for(q = jhd_queue_next(head); q!= head; q = jhd_queue_next(q)){
		svs = jhd_queue_data(q,jhd_http_service,queue);
		if(svs->match(svs->service_ctx,r->uri,r->uri_len)){
			return svs->service_func(svs->service_ctx,r);
		}
	}
	q = head->prev;
	svs =jhd_queue_data(q,jhd_http_service,queue);
	return svs->service_func(svs->service_ctx,r);
}


int jhd_http_mulitple_server_handler(void *lis_ctx,jhd_http_request *r){
	jhd_queue_t *head,*q;
	jhd_http_service *svs;
	jhd_http_server  **svr;

	svr = lis_ctx;
	do{
		if(r->host_len == (*svr)->host_len && memcmp(r->host,(*svr)->host,r->host_len)==0){
				head  = &((*svr)->services);
				for(q = jhd_queue_next(head); q!= head; q = jhd_queue_next(q)){
					svs = jhd_queue_data(q,jhd_http_service,queue);
					if(svs->match(svs->service_ctx,r->uri,r->uri_len)){
						return svs->service_func(svs->service_ctx,r);
					}
				}
				q = head->prev;
				svs =jhd_queue_data(q,jhd_http_service,queue);
				return svs->service_func(svs->service_ctx,r);
		}
		++svr;
	}while(*svr != NULL);
	svr = lis_ctx;

	head  = &((*svr)->services);
	for(q = jhd_queue_next(head); q!= head; q = jhd_queue_next(q)){
		svs = jhd_queue_data(q,jhd_http_service,queue);
		if(svs->match(svs->service_ctx,r->uri,r->uri_len)){
			return svs->service_func(svs->service_ctx,r);
		}
	}
	q = head->prev;
	svs =jhd_queue_data(q,jhd_http_service,queue);
	return svs->service_func(svs->service_ctx,r);
}



void jhd_http_request_init_by_http11(jhd_http_request *r,jhd_event_t *ev){}

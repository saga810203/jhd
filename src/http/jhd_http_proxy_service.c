#include <http/jhd_http_proxy_service.h>


void jhd_http_proxy_request_handler(jhd_http_request *r) {
   jhd_queue_t h,*head,*q;
   jhd_http_proxy_service_context *ctx;
   jhd_http_header *header;

   u_char *content_type,*user_agent;
   uint16_t  content_type_len,user_agent_len;

   ctx = r->http_service->service_ctx;
   jhd_queue_init(&h);
   jhd_http_proxy_filter_request_headers_with_control_header_queue(&ctx->enabled_proxy_headers,r,&h);

   if(ctx->send_user_agent){
	   content_type_len = 0;
   }else{
	   content_type = r->content_type.data;
	   content_type_len = r->content_type.alloced;
	   r->content_type.alloced = 0;
   }
   if(ctx->send_user_agent){
   	   user_agent_len = 0;
      }else{
   	   user_agent = r->user_agent.data;
   	   user_agent_len = r->user_agent.alloced;
   	   r->user_agent.alloced = 0;
    }



func_free:
	if(user_agent_len){
		jhd_free_with_size(user_agent,user_agent_len);
	}
	if(content_type_len){
		jhd_free_with_size(content_type,content_type_len);
	}
	head = &h;
	for(q = jhd_queue_next(head); q!= head;){
		header = jhd_queue_data(q,jhd_http_header,queue);
		q = jhd_queue_next(q);
		jhd_http_free_header(header);
	}
}














jhd_inline static int add_control_header_by_sort(jhd_queue_t *head,u_char *header_name,uint16_t header_name_len){
	jhd_http_proxy_control_header *header,*cmp_header;
	jhd_queue_t *q;

	header = malloc(sizeof(jhd_http_proxy_control_header));
	if(header){
		header->data = malloc(header_name_len +1);
		if(header->data){
			memcpy(header->data,header_name,header_name_len);
			header->data[header_name_len] = 0;
			for(q = jhd_queue_next(head); q!= head;q = jhd_queue_next(q)){
				cmp_header = jhd_queue_data(q,jhd_http_proxy_control_header,queue);
				if(header_name_len < cmp_header->len){
					q = q->prev;
					jhd_queue_insert_after(q,&header->queue);
					return JHD_OK;
				}else if(header_name_len == cmp_header->len && ((memcmp(cmp_header->data,header_name,header_name_len)>0))){
					q = q->prev;
					jhd_queue_insert_after(q,&header->queue);
					return JHD_OK;
				}
			}
			jhd_queue_insert_tail(head,&header->queue);
			return JHD_OK;
		}
		free(header);
	}
	return JHD_AGAIN;
}

int jhd_http_proxy_service_context_enabled_proxy_headers(jhd_http_proxy_service_context *ctx,u_char *header_name,uint16_t header_name_len){
	return add_control_header_by_sort(&ctx->enabled_proxy_headers,header_name,header_name_len);
}
int jhd_http_proxy_service_context_enabled_response_headers(jhd_http_proxy_service_context *ctx,u_char *header_name,uint16_t header_name_len){
	return add_control_header_by_sort(&ctx->enabled_response_headers,header_name,header_name_len);
}
jhd_bool jhd_http_proxy_control_header_queue_included(jhd_queue_t *head,u_char *header_name,uint16_t header_name_len){
	jhd_http_proxy_control_header *header;
	jhd_queue_t *q;
	for(q = jhd_queue_next(head); q!= head;q = jhd_queue_next(q)){
		header = jhd_queue_data(q,jhd_http_proxy_control_header,queue);
		if(header_name_len < header->len){
				return jhd_false;
		}else if(header_name_len == header->len){
			if(memcmp(header->data,header_name,header_name_len)==0){
				return jhd_true;
			}else if(memcmp(header->data,header_name,header_name_len)>0){
				return jhd_false;
			}
		}
	}
	return jhd_false;
}
void jhd_http_proxy_filter_request_headers_with_control_header_queue(jhd_queue_t *contorl_head,jhd_http_request *r,jhd_queue_t *dst_head){
	jhd_http_header *header;
	jhd_http_proxy_control_header *control_header;
	jhd_queue_t *head,*q,*tq;
	head = &r->headers;
	for(q = jhd_queue_next(head); q!= head;){
		header = jhd_queue_data(q,jhd_http_header,queue);
		if(jhd_http_proxy_control_header_queue_included(contorl_head,header->name,header->name_len)){
			q = jhd_queue_next(q);
		}else{
			tq = q;
			q = jhd_queue_next(q);
			jhd_queue_only_remove(tq);
			jhd_queue_insert_tail(dst_head,tq);
		}
	}
}


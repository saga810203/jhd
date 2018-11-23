#include <http2/jhd_http2_stream_listener.h>



void jhd_http2_stream_invlid_listener(jhd_http2_stream *stream){
	log_assert(1==2);
}

void jhd_http2_stream_ignore_listener(jhd_http2_stream *stream){
	log_notice("exec stream listener  %s",__FUNCTION__);
}

void jhd_http2_stream_ignore_data_listener(jhd_http2_stream *stream,jhd_http2_frame *frame){
	log_notice("exec stream listener  %s",__FUNCTION__);
	frame->free_func(frame);
}
void jhd_http2_stream_invalid_data_listener(jhd_http2_stream *stream,jhd_http2_frame *frame){
	log_assert(1==2);
}


void jhd_http2_stream_listener_by_rest_with_direct_free_request(jhd_http2_stream *stream){
	jhd_http_request *r;
	r = stream->lis_ctx;
	jhd_queue_only_remove(&r->event.queue);
	jhd_free_with_size(r,sizeof(jhd_http_request));
}
void jhd_http2_stream_listener_by_rest_with_direct_free_request_and_cache_frame_data(jhd_http2_stream *stream){

	jhd_http_request *r;
	r = stream->lis_ctx;
//	jhd_queue_only_remove(&r->event.queue);
	jhd_free_with_size(r->cache_frame.data,r->cache_frame.data_len);
	jhd_free_with_size(r,sizeof(jhd_http_request));
}

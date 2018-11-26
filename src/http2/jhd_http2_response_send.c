#include <jhd_config.h>
#include <jhd_log.h>
#include <http2/jhd_http2_response_send.h>


static void stream_listener_by_remote_recv_send_cache_raw_data(jhd_http2_stream *stream){
	jhd_http_request *r;
	r = stream->lis_ctx;
	jhd_queue_remove(&stream->flow_control);
	jhd_http2_stream_send_last_raw_data(r);
}

static void stream_listener_by_send_window_change_send_cache_raw_data(jhd_http2_stream *stream){
	jhd_http_request *r;
	r = stream->lis_ctx;
	jhd_queue_remove(&stream->flow_control);
	jhd_http2_stream_send_last_raw_data(r);
}


static jhd_http2_stream_listener server_send_response_with_flow_control_and_not_in_send_queue ={
		jhd_http2_stream_ignore_listener,	//	jhd_event_handler_pt remote_close;
		jhd_http2_stream_ignore_data_listener,//		jhd_event_handler_pt remote_data;
		jhd_http2_stream_ignore_listener,      //	    remote_empty_data;
		jhd_http2_stream_listener_by_rest_with_direct_free_request_and_cache_frame_data,//		    jhd_event_handler_pt reset;
		stream_listener_by_remote_recv_send_cache_raw_data,//		jhd_event_handler_pt remote_recv;
		jhd_http2_stream_ignore_listener,	//	jhd_event_handler_pt recv_window_change;//keep stream recv_window_size == ?(return in ev->data->data->recv.state)
		stream_listener_by_send_window_change_send_cache_raw_data,
};





static void cache_frame_free_with_over(void *frame){
	jhd_http_request * r;
	jhd_http2_stream *stream;
	r =  (jhd_http_request *) (((u_char *) frame) - offsetof(jhd_http_request, cache_frame));
	stream = r->stream;
	stream->listener = &server_send_response_with_flow_control_and_not_in_send_queue;
}

static void cache_frame_free_with_free_request(void *frame){
	jhd_http_request * r;
	r =  (jhd_http_request *) (((u_char *) frame) - offsetof(jhd_http_request, cache_frame));

	log_assert(r->event.queue.next == NULL  ||(jhd_queue_not_queued(&r->event.queue)));
	log_assert(r->stream == NULL);

	jhd_free_with_size(r->cache_frame.data,r->cache_frame.data_len);
	jhd_free_with_size(r,sizeof(jhd_http_request));
}




static void stream_listener_by_rest_with_change_cache_frame_free_func(jhd_http2_stream *stream){
	log_assert_code(((jhd_http_request *)(stream->lis_ctx))->stream = NULL;)

	((jhd_http_request *)(stream->lis_ctx))->cache_frame.free_func = cache_frame_free_with_free_request;



}

static void cache_frame_free_with_send_next_fragmentation(void *frame){
	jhd_http2_stream_send_last_raw_data( (jhd_http_request *) (((u_char *) frame) - offsetof(jhd_http_request, cache_frame)));
}



static void stream_listener_by_remote_recv_with_change_cache_frame_free_func(jhd_http2_stream *stream){
	log_assert(jhd_queue_queued(&stream->flow_control));
	jhd_queue_remove(&stream->flow_control);
	((jhd_http_request *)(stream->lis_ctx))->cache_frame.free_func = cache_frame_free_with_send_next_fragmentation;
}



static void stream_listener_by_send_window_change_with_change_cache_frame_free_func(jhd_http2_stream *stream){
	((jhd_http_request *)(stream->lis_ctx))->cache_frame.free_func = cache_frame_free_with_send_next_fragmentation;
}


static jhd_http2_stream_listener server_stream_listener_with_flow_control_and_in_send_queue ={
		jhd_http2_stream_ignore_listener,	//	jhd_event_handler_pt remote_close;
		jhd_http2_stream_ignore_data_listener,//		jhd_event_handler_pt remote_data;
		jhd_http2_stream_ignore_listener,      //	    remote_empty_data;
		stream_listener_by_rest_with_change_cache_frame_free_func,//		    jhd_event_handler_pt reset;
		stream_listener_by_remote_recv_with_change_cache_frame_free_func,//		jhd_event_handler_pt remote_recv;
		jhd_http2_stream_ignore_listener,	//	jhd_event_handler_pt recv_window_change;//keep stream recv_window_size == ?(return in ev->data->data->recv.state)
		stream_listener_by_send_window_change_with_change_cache_frame_free_func,
};

/**
 * raw   data mem point = r->cache_frame.data;
 * raw   data mem len   = r->cache_frame.data_len;
 *
 * raw   next pos = r->payload;
 *
 * raw   len = r->payload_len;
 *
 */
void jhd_http2_stream_send_last_raw_data(jhd_http_request *r){
	jhd_http2_frame *frame;
	jhd_http2_stream *stream;
	jhd_connection_t *c;
	jhd_http2_connection *h2c;
	int size;
	u_char *p;

	stream = r->stream;
	c = stream->connection;
	h2c = c->data;
	frame = &r->cache_frame;


	log_assert(frame->data != NULL);
	log_assert(r->payload != NULL);
	log_assert(frame->data >  (r->payload +9));
	log_assert((frame->data  - r->payload) <= (16384+9) );


	log_assert(r->payload_len >0);
	log_assert(r->payload_len < 16384);
	log_assert(frame->data_len >= (r->payload_len +9));



	size = stream->send_window_size;
	if(size > h2c->send.window_size){
		size = h2c->send.window_size;
	}


	if(size<1){
		jhd_queue_insert_tail(&h2c->flow_control,&stream->flow_control);
		stream->listener = &server_send_response_with_flow_control_and_not_in_send_queue;
	}else if(size < ((int)r->payload_len)){
		jhd_queue_insert_tail(&h2c->flow_control,&stream->flow_control);
		h2c->send.window_size -= size;
		stream->send_window_size -= size;

		frame->pos = r->payload;
		frame->len = size + 9;
		p =  r->payload - 9;

		p[0] = 0;
		p[1] = ((u_char)(size>> 8));
		p[2] = ((u_char)(size));
//		p[3] = JHD_HTTP2_FRAME_TYPE_DATA_FRAME;
		p[4] = 0;
		p+=5;
		jhd_http2_set_stream_id(p,stream->id);
		frame->next = NULL;
		frame->free_func = cache_frame_free_with_over;
		jhd_http2_send_queue_frame(c,h2c,frame);
		stream->listener =&server_stream_listener_with_flow_control_and_in_send_queue;
	}else{
		h2c->send.window_size -= ((int)r->payload_len);

		log_assert_code(r->stream = NULL;)

		frame->free_func = cache_frame_free_with_free_request;
		frame->pos = r->payload;
		frame->len = (((int)r->payload_len+9));
		p =  r->payload - 9;
		p[0] = 0;
		p[1] = ((u_char)(size>> 8));
		p[2] = ((u_char)(size));
//		p[3] = JHD_HTTP2_FRAME_TYPE_DATA_FRAME;
		p[4] = JHD_HTTP2_END_STREAM_FLAG;
		p+=5;
		jhd_http2_set_stream_id(p,stream->id);
		frame->next = NULL;
		jhd_http2_send_queue_frame(c,h2c,frame);

		jhd_queue_remove(&stream->queue);
		h2c->recv.stream = &jhd_http2_invalid_stream;
		--h2c->processing;
		jhd_free_with_size(stream,sizeof(jhd_http2_stream));
	}
}

#include <http/jhd_http_core.h>
#include <http2/jhd_http2.h>
#include <tls/jhd_tls_ssl_internal.h>
#include <jhd_pool.h>
#include <jhd_time.h>


jhd_http2_stream_listener server_stream_first_listener ={

						//notify
				NULL,	//	jhd_event_handler_pt remote_close;
						//notify
				NULL,//		jhd_event_handler_pt remote_data;
						//notify
				NULL,//		jhd_event_handler_pt remote_empty_data;
						//notify
				NULL,//		jhd_event_handler_pt reset;
						//notify  //handler do send frame but disable block  not set ev->handler
				NULL,//		jhd_event_handler_pt remote_recv;
						//notify   change stream->recv_window_size   ==  return value(event_h2c->recv.state);
				NULL,	//	jhd_event_handler_pt recv_window_change;//keep stream recv_window_size == ?(return in ev->data->data->recv.state)

						//notify  don't change connection state  can send data
				NULL,	//	jhd_event_handler_pt send_window_change;//keep stream recv_window_size == ?(return in ev->data->data->recv.state)
};


void jhd_http_request_init_by_http2(jhd_http_request *r,jhd_event_t *ev){
	jhd_http2_connection  *h2c;
	r->data = h2c->recv.stream;
	jhd_queue_move(&r->headers,&h2c->recv.headers);
	h2c->recv.stream->lis_ctx = r ;
	h2c->recv.stream->listener = &server_stream_first_listener;

}

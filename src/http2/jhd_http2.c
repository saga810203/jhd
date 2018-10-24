#include <http/jhd_http_core.h>
#include <http2/jhd_http2.h>

void jhd_http2_only_by_clean_start(jhd_connection_t *c){

}
void jhd_http2_only_by_tls_start(jhd_connection_t *c){

}
void jhd_http2_with_alpn_start(jhd_connection_t *c){


	log_assert_worker();
	log_assert(((jhd_tls_ssl_config*) c->listening->ssl)->alpn_list!= NULL);

}























jhd_http_core_request_info  jhd_http2_info={};

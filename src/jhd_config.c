#include <jhd_config.h>
#include <jhd_log.h>
#include <http2/jhd_http2.h>





void jhd_config_check(){

	log_assert(sizeof(jhd_http2_stream)>= (sizeof(jhd_http2_frame)+17));

}

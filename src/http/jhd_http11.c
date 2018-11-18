#include <jhd_config.h>
#include <jhd_log.h>
#include <jhd_connection.h>
#include <http/jhd_http_core.h>




void jhd_http11_init(jhd_event_t *ev){
	jhd_connection_t *c;
	//int ret;
	log_assert_worker();
	c = ev->data;



	//TODO impl

	log_err("no impl");
	c->close(c);

}

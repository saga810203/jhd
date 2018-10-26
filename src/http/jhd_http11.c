#include <jhd_http_core.h>
#include <jhd_event.h>



void jhd_http11_init(jhd_event_t *ev){
	jhd_connection_t *c;
	int ret;
	log_assert_worker();
	c = ev->data;

	jhd_event_with_timeout(ev){
		c->close(c);
		return;
	}

	//TODO impl

	log_err("no impl");
	c->close(c);

}

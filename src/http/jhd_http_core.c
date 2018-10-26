#include <jhd_http_core.h>


void jhd_http_listening_context_free(void *ctx){
	log_assert(ctx != NULL);
	log_assert_master();
	if(((jhd_http_listening_context*)ctx)->data){
		free(((jhd_http_listening_context*)ctx)->data);
		((jhd_http_listening_context*)ctx)->data = NULL;
	}
	free(ctx);
}

#include <jhd_aio.h>

static int jhd_aio_max_nr = 128;
static struct iocb *jhd_iocb_ptr = NULL;


static io_context_t jhd_aio;


struct iocb *jhd_free_iocbs = NULL;
jhd_queue_t waitting_iocb_queue;


int jhd_aio_setup() {
	int ret, i;
	struct iocb ** ppiocb;


	jhd_queue_init(&waitting_iocb_queue);

	memset(&jhd_aio, 0, sizeof(io_context_t));
	ret = io_setup(jhd_aio_max_nr, &jhd_aio);
	if (0 != ret) {
		jhd_aio_max_nr = 0;
		log_stderr("execute io_setup(%d,&jhd_aio)== %d", ret);
	}
	if (ret == 0) {

		jhd_iocb_ptr = malloc(sizeof(struct iocb) * jhd_aio_max_nr);
		if (jhd_iocb_ptr) {
			for (i = 0; i < jhd_aio_max_nr; ++i) {
				ppiocb = (struct iocb **) (&jhd_iocb_ptr[i]);
				*ppiocb = jhd_free_iocbs;
				jhd_free_iocbs = (struct iocb*) (ppiocb);
			}
		} else {
			io_destroy(jhd_aio);
		}
	}
	return ret;
}



void jhd_aio_destroy() {
	if(jhd_aio_max_nr){
		io_destroy(jhd_aio);
	}
	if(jhd_iocb_ptr){
		free(jhd_iocb_ptr);
	}
}

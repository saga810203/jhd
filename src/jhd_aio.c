
#include <jhd_aio.h>
#include <jhd_connection.h>

static int jhd_aio_max_nr = 128;
static jhd_aio_cb *jhd_iocb_ptr = NULL;


static aio_context_t jhd_aio;


jhd_aio_cb *jhd_free_iocbs = NULL;
jhd_queue_t waitting_iocb_queue;
uint32_t    jhd_aio_block_size = 512;


static jhd_connection_t *aio_con = NULL;
static int aio_eventfd = -1;


static void jhd_epoll_eventfd_handler(jhd_event_t *ev)
{
    int               n, events;
    long              i;
    uint64_t          ready;
    int         err;
    struct io_event   event[64];
    jhd_aio_cb * cb;
    struct timespec   ts;
    jhd_event_t *e;
    n = read(aio_eventfd, &ready, 8);
    err = errno;
    if (n == 8) {
    	 ts.tv_sec = 0;
    	 ts.tv_nsec = 0;
    	    while (ready) {
    	        events = io_getevents(jhd_aio, 1, 64, event, &ts);
    	        if (events > 0) {
    	            ready -= events;
    	            for (i = 0; i < events; i++) {
    	                e = (jhd_event_t *) (uintptr_t) event[i].data;
    	                cb = (jhd_aio_cb*) (((u_char *) (event[i].obj)) - offsetof(jhd_aio_cb, aio));
    	                cb->result = event[i].res;
    	                jhd_post_event(e, &jhd_posted_events);
    	            }
    	            continue;
    	        }
    	        if (events == 0) {
    	            return;
    	        }
    	        /* events == -1 */
    	        log_stderr("io_getevents() failed");
    	        return;
    	    }
    }else{
    	log_stderr("read aio eventfd return:%d",n);
    }


}

jhd_inline static int io_setup(u_int nr_reqs, aio_context_t *ctx){
    return syscall(SYS_io_setup, nr_reqs, ctx);
}


jhd_inline static int io_destroy(aio_context_t ctx){
    return syscall(SYS_io_destroy, ctx);
}


jhd_inline static int io_getevents(aio_context_t ctx, long min_nr, long nr, struct io_event *events,struct timespec *tmo){
    return syscall(SYS_io_getevents, ctx, min_nr, nr, events, tmo);
}

jhd_inline static int io_cancel(aio_context_t ctx, struct iocb *iocb,struct io_event *result){
	return syscall(SYS_io_cancel,ctx,iocb,result);
}
void jhd_aio_read(jhd_event_t *ev,void*ic,int fd,u_char *buf, size_t size, off_t offset){
	 struct iocb      *piocb[1];
	 piocb[0] = &((jhd_aio_cb *)(ic))->aio;
	 ((jhd_aio_cb *)(ic))->aio.aio_data = (uint64_t) (uintptr_t) ev;
	 ((jhd_aio_cb *)(ic))->aio.aio_lio_opcode = IOCB_CMD_PREAD;
	 ((jhd_aio_cb *)(ic))->aio.aio_fildes = fd;
	 ((jhd_aio_cb *)(ic))->aio.aio_buf = (uint64_t) (uintptr_t) buf;
	 ((jhd_aio_cb *)(ic))->aio.aio_nbytes = size;
	 ((jhd_aio_cb *)(ic))->aio.aio_offset = offset;
#ifdef JHD_LOG_ASSERT_ENABLE
if(
#endif
	io_submit(jhd_aio, 1, piocb)
#ifdef JHD_LOG_ASSERT_ENABLE
!=1){
	log_assert(1==2);
}
#else
;
#endif
}
void jhd_aio_write(jhd_event_t *ev,void*ic,int fd,u_char *buf, size_t size, off_t offset){
	struct iocb      *piocb[1];
	piocb[0] = &((jhd_aio_cb *)(ic))->aio;
	((jhd_aio_cb *)(ic))->aio.aio_data = (uint64_t) (uintptr_t) ev;
	((jhd_aio_cb *)(ic))->aio.aio_lio_opcode = IOCB_CMD_PWRITE;
	((jhd_aio_cb *)(ic))->aio.aio_fildes = fd;
	((jhd_aio_cb *)(ic))->aio.aio_buf = (uint64_t) (uintptr_t) buf;
	((jhd_aio_cb *)(ic))->aio.aio_nbytes = size;
	((jhd_aio_cb *)(ic))->aio.aio_offset = offset;
	#ifdef JHD_LOG_ASSERT_ENABLE
	if(
	#endif
	io_submit(jhd_aio, 1, piocb)
	#ifdef JHD_LOG_ASSERT_ENABLE
	!=1){
	log_assert(1==2);
	}
	#else
	;
	#endif
}

void jhd_aio_submit(jhd_aio_cb *aio){
	struct iocb      *piocb[1];
	piocb[0] = &aio->aio;

#ifdef JHD_LOG_ASSERT_ENABLE
if(
#endif
io_submit(jhd_aio, 1, piocb)
#ifdef JHD_LOG_ASSERT_ENABLE
!=1){
log_assert(1==2);
}
#else
;
#endif

}

int jhd_aio_setup() {
	int ret, i;
    struct epoll_event  ee;
    jhd_aio_cb *paio;


	memset(&jhd_aio, 0, sizeof(aio_context_t));

    aio_eventfd = eventfd(0, 0);

    //TODO check connection init  epoll init; return JHD_AGAIN;

    if (aio_eventfd == -1) {
    	log_stderr("eventfd() failed");
    	return JHD_ERROR;
	}
    ret = 1;

	if (ioctl(aio_eventfd, FIONBIO, &ret) == -1) {
		log_stderr("ioctl(aio_eventfd, FIONBIO) failed");
		jhd_close(aio_eventfd);
		aio_eventfd = -1;
		return JHD_ERROR;
	}

	if (io_setup(jhd_aio_max_nr, &jhd_aio) == -1) {
		log_stderr("io_setup() failed");
		jhd_close(aio_eventfd);
		return JHD_ERROR;
	}
	log_assert(free_connection_count>0);

	aio_con = jhd_connection_get();

	aio_con->fd = aio_eventfd;

	aio_con->read.handler = jhd_epoll_eventfd_handler;

	jhd_queue_init(&waitting_iocb_queue);
	paio = jhd_iocb_ptr = malloc(sizeof(jhd_aio_cb) * jhd_aio_max_nr);
	if (paio) {
		jhd_free_iocbs = NULL;
		memset(paio,0,sizeof(jhd_aio_cb) * jhd_aio_max_nr);
		for (i = 0; i < jhd_aio_max_nr; ++i,++paio) {
		    paio->aio.aio_flags = IOCB_FLAG_RESFD;
		    paio->aio.aio_resfd = aio_eventfd;
		    paio->aio.aio_data = NULL;
		    paio->next = jhd_free_iocbs;
		    jhd_free_iocbs = paio;
		}
	} else {
		io_destroy(jhd_aio);
		jhd_connection_destroy(aio_con);
		jhd_close(aio_eventfd);
		aio_eventfd = -1;
		log_stderr("malloc(iocb *  jhd_aio_max_nrfailed");
		return JHD_ERROR;
	}
	ee.events = EPOLLIN|EPOLLET;
	ee.data.u32 = aio_con->idx;

	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, aio_eventfd, &ee) == -1) {
		io_destroy(jhd_aio);
		jhd_connection_destroy(aio_con);
		jhd_close(aio_eventfd);
		aio_eventfd = -1;
		free(jhd_iocb_ptr);
		 log_stderr("epoll_ctl(EPOLL_CTL_ADD, aio_eventfd) failed");
		 return JHD_ERROR;
	}
}



void jhd_aio_destroy() {
	int i ;
	jhd_aio_cb *aiocb;
	jhd_event_t *ev;
	if(	aio_eventfd != -1){
		for(i = 0 ; i < jhd_aio_max_nr ; ++i){
			aiocb = &jhd_iocb_ptr[i];

			if(aiocb->aio.aio_data){
				aiocb->result = -1;
				ev = (jhd_event_t*)aiocb->aio.aio_data;
				jhd_post_event(ev,&jhd_posted_events);
			}

		}
		io_destroy(jhd_aio);
		jhd_connection_destroy(aio_con);
		jhd_close(aio_eventfd);
		aio_eventfd = -1;
		free(jhd_iocb_ptr);
	}
}

/*
 * jhd_log.c
 *
 *  Created on: May 11, 2018
 *      Author: root
 */

#include <jhd_core.h>



void _log_out(u_char* file_name,u_char *func_name,int line,jhd_log_t *log,u_int16_t log_mask,u_int16_t level,const u_char* fmt,...){
	va_list      args;

    u_char      *p, *last, *msg;
    ssize_t      n;

    u_char       errstr[JHD_MAX_ERROR_STR];

    last = errstr + JHD_MAX_ERROR_STR;

    p = memcpy(errstr, ngx_cached_err_log_time.data,
                   ngx_cached_err_log_time.len);

    p = ngx_slprintf(p, last, " [%V] ", &err_levels[level]);

    /* pid#tid */
    p = ngx_slprintf(p, last, "%P#" NGX_TID_T_FMT ": ",
                    ngx_log_pid, ngx_log_tid);

    if (log->connection) {
        p = ngx_slprintf(p, last, "*%uA ", log->connection);
    }

    msg = p;


    va_start(args, fmt);
    p = ngx_vslprintf(p, last, fmt, args);
    va_end(args);

    if (err) {
           p = ngx_log_errno(p, last, err);
       }

       if (level != NGX_LOG_DEBUG && log->handler) {
           p = log->handler(log, p, last - p);
       }

       if (p > last - NGX_LINEFEED_SIZE) {
           p = last - NGX_LINEFEED_SIZE;
       }

       ngx_linefeed(p);

       wrote_stderr = 0;
       debug_connection = (log->log_level & NGX_LOG_DEBUG_CONNECTION) != 0;

       while (log) {

           if (log->log_level < level && !debug_connection) {
               break;
           }

           if (log->writer) {
               log->writer(log, level, errstr, p - errstr);
               goto next;
           }

           if (ngx_time() == log->disk_full_time) {

               /*
                * on FreeBSD writing to a full filesystem with enabled softupdates
                * may block process for much longer time than writing to non-full
                * filesystem, so we skip writing to a log for one second
                */

               goto next;
           }

           n = ngx_write_fd(log->file->fd, errstr, p - errstr);

           if (n == -1 && ngx_errno == NGX_ENOSPC) {
               log->disk_full_time = ngx_time();
           }

           if (log->file->fd == ngx_stderr) {
               wrote_stderr = 1;
           }

       next:

           log = log->next;
       }

       if (!ngx_use_stderr
           || level > NGX_LOG_WARN
           || wrote_stderr)
       {
           return;
       }

       msg -= (7 + err_levels[level].len + 3);

       (void) ngx_sprintf(msg, "nginx: [%V] ", &err_levels[level]);

       (void) ngx_write_console(ngx_stderr, msg, p - msg);


}




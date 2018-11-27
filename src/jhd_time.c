/*
 * jhd_time.c
 *
 *  Created on: May 11, 2018
 *      Author: root
 */

#include <jhd_time.h>
#include <jhd_config.h>
#include <jhd_log.h>


static u_char log_time_value[JHD_CACHE_LOG_TIME_LEN+1];
static u_char http_time_value[JHD_CACHE_HTTP_DATE_LEN+1];

u_char* jhd_cache_log_time = &log_time_value[0];
u_char* jhd_cache_http_date = &http_time_value[0];

time_t        jhd_cache_time;
uint64_t      jhd_current_msec;

static char  *week[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
static char  *months[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

void
jhd_gmtime(time_t t, struct tm *tp)
{
    int   yday;
    int  sec, min, hour, mday, mon, year, wday, days, leap;

    /* the calculation is valid for positive time_t only */

    if (t < 0) {
        t = 0;
    }

    days = t / 86400;
    sec = t % 86400;

    /*
     * no more than 4 year digits supported,
     * truncate to December 31, 9999, 23:59:59
     */

    if (days > 2932896) {
        days = 2932896;
        sec = 86399;
    }

    /* January 1, 1970 was Thursday */

    wday = (4 + days) % 7;

    hour = sec / 3600;
    sec %= 3600;
    min = sec / 60;
    sec %= 60;

    /*
     * the algorithm based on Gauss' formula,
     * see src/core/ngx_parse_time.c
     */

    /* days since March 1, 1 BC */
    days = days - (31 + 28) + 719527;

    /*
     * The "days" should be adjusted to 1 only, however, some March 1st's go
     * to previous year, so we adjust them to 2.  This causes also shift of the
     * last February days to next year, but we catch the case when "yday"
     * becomes negative.
     */

    year = (days + 2) * 400 / (365 * 400 + 100 - 4 + 1);

    yday = days - (365 * year + year / 4 - year / 100 + year / 400);

    if (yday < 0) {
        leap = (year % 4 == 0) && (year % 100 || (year % 400 == 0));
        yday = 365 + leap + yday;
        year--;
    }

    /*
     * The empirical formula that maps "yday" to month.
     * There are at least 10 variants, some of them are:
     *     mon = (yday + 31) * 15 / 459
     *     mon = (yday + 31) * 17 / 520
     *     mon = (yday + 31) * 20 / 612
     */

    mon = (yday + 31) * 10 / 306;

    /* the Gauss' formula that evaluates days before the month */

    mday = yday - (367 * mon / 12 - 30) + 1;

    if (yday >= 306) {

        year++;
        mon -= 10;

        /*
         * there is no "yday" in Win32 SYSTEMTIME
         *
         * yday -= 306;
         */

    } else {

        mon += 2;

        /*
         * there is no "yday" in Win32 SYSTEMTIME
         *
         * yday += 31 + 28 + leap;
         */
    }

    tp->tm_sec=  sec;
    tp->tm_min =  min;
    tp->tm_hour = hour;
    tp->tm_mday =mday;
    tp->tm_mon = mon;
    tp->tm_year = year;
    tp->tm_wday = wday;
}

void jhd_update_time() {
	struct tm tm, gmt;
	struct timeval tv;
	struct timespec ts;

	gettimeofday(&tv, NULL);

	clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);

	jhd_current_msec = ts.tv_sec * 1000 + (ts.tv_nsec / 1000000);

	log_debug("cpu time:%lu",jhd_current_msec);

	if (jhd_cache_time == tv.tv_sec) {
		return;
	}
	jhd_cache_time = tv.tv_sec;
	jhd_gmtime(jhd_cache_time, &gmt);
	sprintf((char*)jhd_cache_http_date, "%s, %02d %s %4d %02d:%02d:%02d GMT", week[gmt.tm_wday], gmt.tm_mday, months[gmt.tm_mon - 1], gmt.tm_year, gmt.tm_hour, gmt.tm_min,
	        gmt.tm_sec);
	//TODO:  impl    cache_time + timezone_value :   +  8*60*60     beijing
	localtime_r(&tv.tv_sec, &tm);
	tm.tm_mon++;
	tm.tm_year += 1900;
	sprintf((char*)jhd_cache_log_time, "%4d/%02d/%02d %02d:%02d:%02d", tm.tm_year, tm.tm_mon, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
	log_debug("log time:%s",jhd_cache_log_time);
}

void jhd_write_http_time(u_char *dst,time_t tm){
	struct tm gmt;
	jhd_gmtime(tm, &gmt);
	sprintf((char*)dst, "%s, %02d %s %4d %02d:%02d:%02d GMT", week[gmt.tm_wday], gmt.tm_mday, months[gmt.tm_mon - 1], gmt.tm_year, gmt.tm_hour, gmt.tm_min,gmt.tm_sec);
}



static int  mday[] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

time_t jhd_parse_http_time(u_char *value, size_t len)
{
    u_char      *p, *end;
    int    month;
    int   day, year, hour, min, sec;
    uint64_t     time;
    enum {
        no = 0,
        rfc822,   /* Tue, 10 Nov 2002 23:50:13   */
        rfc850,   /* Tuesday, 10-Dec-02 23:50:13 */
        isoc      /* Tue Dec 10 23:50:13 2002    */
    } fmt;

    fmt = 0;
    end = value + len;

    for (p = value; p < end; p++) {
        if (*p == ',') {
            break;
        }

        if (*p == ' ') {
            fmt = isoc;
            break;
        }
    }

    for (p++; p < end; p++) {
        if (*p != ' ') {
            break;
        }
    }

    if (end - p < 18) {
        return 0XFFFFFFFFFFFFFFFFULL;
    }

    if (fmt != isoc) {
        if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9') {
        	  return 0XFFFFFFFFFFFFFFFFULL;
        }

        day = (*p - '0') * 10 + (*(p + 1) - '0');
        p += 2;

        if (*p == ' ') {
            if (end - p < 18) {
            	  return 0XFFFFFFFFFFFFFFFFULL;
            }
            fmt = rfc822;

        } else if (*p == '-') {
            fmt = rfc850;

        } else {
        	  return 0XFFFFFFFFFFFFFFFFULL;
        }

        p++;
    }

    switch (*p) {

    case 'J':
        month = *(p + 1) == 'a' ? 0 : *(p + 2) == 'n' ? 5 : 6;
        break;

    case 'F':
        month = 1;
        break;

    case 'M':
        month = *(p + 2) == 'r' ? 2 : 4;
        break;

    case 'A':
        month = *(p + 1) == 'p' ? 3 : 7;
        break;

    case 'S':
        month = 8;
        break;

    case 'O':
        month = 9;
        break;

    case 'N':
        month = 10;
        break;

    case 'D':
        month = 11;
        break;

    default:
    	  return 0XFFFFFFFFFFFFFFFFULL;
    }

    p += 3;

    if ((fmt == rfc822 && *p != ' ') || (fmt == rfc850 && *p != '-')) {
    	  return 0XFFFFFFFFFFFFFFFFULL;
    }

    p++;

    if (fmt == rfc822) {
        if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9'
            || *(p + 2) < '0' || *(p + 2) > '9'
            || *(p + 3) < '0' || *(p + 3) > '9')
        {
        	  return 0XFFFFFFFFFFFFFFFFULL;
        }

        year = (*p - '0') * 1000 + (*(p + 1) - '0') * 100
               + (*(p + 2) - '0') * 10 + (*(p + 3) - '0');
        p += 4;

    } else if (fmt == rfc850) {
        if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9') {
        	  return 0XFFFFFFFFFFFFFFFFULL;
        }

        year = (*p - '0') * 10 + (*(p + 1) - '0');
        year += (year < 70) ? 2000 : 1900;
        p += 2;
    }

    if (fmt == isoc) {
        if (*p == ' ') {
            p++;
        }

        if (*p < '0' || *p > '9') {
        	  return 0XFFFFFFFFFFFFFFFFULL;
        }

        day = *p++ - '0';

        if (*p != ' ') {
            if (*p < '0' || *p > '9') {
            	  return 0XFFFFFFFFFFFFFFFFULL;
            }

            day = day * 10 + (*p++ - '0');
        }

        if (end - p < 14) {
        	  return 0XFFFFFFFFFFFFFFFFULL;
        }
    }

    if (*p++ != ' ') {
    	  return 0XFFFFFFFFFFFFFFFFULL;
    }

    if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9') {
    	  return 0XFFFFFFFFFFFFFFFFULL;
    }

    hour = (*p - '0') * 10 + (*(p + 1) - '0');
    p += 2;

    if (*p++ != ':') {
    	  return 0XFFFFFFFFFFFFFFFFULL;
    }

    if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9') {
    	  return 0XFFFFFFFFFFFFFFFFULL;
    }

    min = (*p - '0') * 10 + (*(p + 1) - '0');
    p += 2;

    if (*p++ != ':') {
    	  return 0XFFFFFFFFFFFFFFFFULL;
    }

    if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9') {
    	  return 0XFFFFFFFFFFFFFFFFULL;
    }

    sec = (*p - '0') * 10 + (*(p + 1) - '0');

    if (fmt == isoc) {
        p += 2;

        if (*p++ != ' ') {
        	  return 0XFFFFFFFFFFFFFFFFULL;
        }

        if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9'
            || *(p + 2) < '0' || *(p + 2) > '9'
            || *(p + 3) < '0' || *(p + 3) > '9')
        {
        	  return 0XFFFFFFFFFFFFFFFFULL;
        }

        year = (*p - '0') * 1000 + (*(p + 1) - '0') * 100
               + (*(p + 2) - '0') * 10 + (*(p + 3) - '0');
    }

    if (hour > 23 || min > 59 || sec > 59) {
    	  return 0XFFFFFFFFFFFFFFFFULL;
    }

    if (day == 29 && month == 1) {
        if ((year & 3) || ((year % 100 == 0) && (year % 400) != 0)) {
        	  return 0XFFFFFFFFFFFFFFFFULL;
        }

    } else if (day > mday[month]) {
    	  return 0XFFFFFFFFFFFFFFFFULL;
    }

    /*
     * shift new year to March 1 and start months from 1 (not 0),
     * it is needed for Gauss' formula
     */

    if (--month <= 0) {
        month += 12;
        year -= 1;
    }

    /* Gauss' formula for Gregorian days since March 1, 1 BC */

    time = (uint64_t) (
            /* days in years including leap years since March 1, 1 BC */

            365 * year + year / 4 - year / 100 + year / 400

            /* days before the month */

            + 367 * month / 12 - 30

            /* days before the day */

            + day - 1

            /*
             * 719527 days were between March 1, 1 BC and March 1, 1970,
             * 31 and 28 days were in January and February 1970
             */

            - 719527 + 31 + 28) * 86400 + hour * 3600 + min * 60 + sec;


    return (time_t) time;
}

/*
 * jhd_time.c
 *
 *  Created on: May 11, 2018
 *      Author: root
 */

#include <jhd_core.h>


static u_char log_time_value[JHD_CACHE_LOG_TIME_LEN+1];
static u_char http_time_value[JHD_CACHE_HTTP_DATE_LEN+1];

u_char* jhd_cache_log_time = &log_time_value[0];
u_char* jhd_cache_http_date = &http_time_value[0];

volatile time_t        jhd_cache_time;
volatile uint64_t      jhd_current_msec;

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

	if (jhd_cache_time == tv.tv_sec) {
		return;
	}
	jhd_cache_time = tv.tv_sec;
	jhd_gmtime(jhd_cache_time, &gmt);
	sprintf(jhd_cache_http_date, "%s, %02d %s %4d %02d:%02d:%02d GMT", week[gmt.tm_wday], gmt.tm_mday, months[gmt.tm_mon - 1], gmt.tm_year, gmt.tm_hour, gmt.tm_min,
	        gmt.tm_sec);

	//TODO:  impl    cache_time + timezone_value :   +  8*60*60     beijing
	localtime_r(&tv.tv_sec, &tm);

	tm->tm_mon++;
	tm->tm_year += 1900;

	sprintf(jhd_cache_log_time, "%4d/%02d/%02d %02d:%02d:%02d", tm.tm_year, tm.tm_mon, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
}

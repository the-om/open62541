/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information. */

/* Enable POSIX features */
#if !defined(_XOPEN_SOURCE) && !defined(_WRS_KERNEL)
# define _XOPEN_SOURCE 600
#endif
#ifndef _DEFAULT_SOURCE
# define _DEFAULT_SOURCE
#endif
/* On older systems we need to define _BSD_SOURCE.
 * _DEFAULT_SOURCE is an alias for that. */
#ifndef _BSD_SOURCE
# define _BSD_SOURCE
#endif

#include <time.h>
#ifdef _WIN32
/* Backup definition of SLIST_ENTRY on mingw winnt.h */
# ifdef SLIST_ENTRY
#  pragma push_macro("SLIST_ENTRY")
#  undef SLIST_ENTRY
#  define POP_SLIST_ENTRY
# endif
# include <windows.h>
/* restore definition */
# ifdef POP_SLIST_ENTRY
#  undef SLIST_ENTRY
#  undef POP_SLIST_ENTRY
#  pragma pop_macro("SLIST_ENTRY")
# endif
#else
# include <sys/time.h>
#endif

#if defined(__APPLE__) || defined(__MACH__)
# include <mach/clock.h>
# include <mach/mach.h>
#endif

#include "ua_types.h"

UA_DateTime UA_DateTime_now(void) {
#if defined(_WIN32)
    /* Windows filetime has the same definition as UA_DateTime */
    FILETIME ft;
    SYSTEMTIME st;
    GetSystemTime(&st);
    SystemTimeToFileTime(&st, &ft);
    ULARGE_INTEGER ul;
    ul.LowPart = ft.dwLowDateTime;
    ul.HighPart = ft.dwHighDateTime;
    return (UA_DateTime)ul.QuadPart;
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec * UA_SEC_TO_DATETIME) + (tv.tv_usec * UA_USEC_TO_DATETIME) + UA_DATETIME_UNIX_EPOCH;
#endif
}

/* credit to https://stackoverflow.com/questions/13804095/get-the-time-zone-gmt-offset-in-c */
static
UA_DateTime UA_DateTime_diffLocalTimeUTC(void) {
    time_t gmt, rawtime = time(NULL);
    struct tm *ptm;

#if !defined(_WIN32)
    struct tm gbuf;
    ptm = gmtime_r(&rawtime, &gbuf);
#else
    ptm = gmtime(&rawtime);
#endif
    // Request that mktime() looksup dst in timezone database
    ptm->tm_isdst = -1;
    gmt = mktime(ptm);

    return (UA_DateTime) ((int)difftime(rawtime, gmt) * UA_SEC_TO_DATETIME);
}

UA_DateTime UA_DateTime_nowLocalTime(void) {
    return UA_DateTime_now() + UA_DateTime_diffLocalTimeUTC();
}

UA_DateTime UA_DateTime_nowMonotonic(void) {
#if defined(_WIN32)
    LARGE_INTEGER freq, ticks;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&ticks);
    UA_Double ticks2dt = UA_SEC_TO_DATETIME / (UA_Double)freq.QuadPart;
    return (UA_DateTime)(ticks.QuadPart * ticks2dt);
#elif defined(__APPLE__) || defined(__MACH__)
    /* OS X does not have clock_gettime, use clock_get_time */
    clock_serv_t cclock;
    mach_timespec_t mts;
    host_get_clock_service(mach_host_self(), SYSTEM_CLOCK, &cclock);
    clock_get_time(cclock, &mts);
    mach_port_deallocate(mach_task_self(), cclock);
    return (mts.tv_sec * UA_SEC_TO_DATETIME) + (mts.tv_nsec / 100);
#elif !defined(CLOCK_MONOTONIC_RAW)
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ts.tv_sec * UA_SEC_TO_DATETIME) + (ts.tv_nsec / 100);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (ts.tv_sec * UA_SEC_TO_DATETIME) + (ts.tv_nsec / 100);
#endif
}

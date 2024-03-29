/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2012, Eduardo Silva P. <edsiper@gmail.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Library General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <ctype.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/prctl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sendfile.h>

#include "monkey.h"
#include "mk_memory.h"
#include "mk_utils.h"
#include "mk_file.h"
#include "mk_string.h"
#include "mk_config.h"
#include "mk_socket.h"
#include "mk_clock.h"
#include "mk_user.h"
#include "mk_cache.h"
#include "mk_macros.h"

/* Date helpers */
static const char *mk_date_wd[7]  = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
static const char *mk_date_ym[12] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul",
                                     "Aug", "Sep", "Oct", "Nov", "Dec"};

/*
 *This function given a unix time, set in a mk_pointer
 * the date in the RFC1123 format like:
 *
 *    Wed, 23 Jun 2010 22:32:01 GMT
 *
 * it also adds a 'CRLF' at the end
 */
int mk_utils_utime2gmt(char **data, time_t date)
{
    int size = 31;
    unsigned int year;
    char *buf=0;
    struct tm *gtm;

    if (date == 0) {
        if ((date = time(NULL)) == -1) {
            return -1;
        }
    }

    /* Convert unix time to struct tm */
    gtm = mk_cache_get(mk_cache_utils_gmtime);

    /* If this function was invoked from a non-thread context it should exit */
    mk_bug(!gtm);
    gtm = gmtime_r(&date, gtm);
    if (!gtm) {
        return -1;
    }

    /* struct tm -> tm_year counts number of years after 1900 */
    year = gtm->tm_year + 1900;

    /* Compose template */
    buf = *data;

    /* Week day */
    *buf++ = mk_date_wd[gtm->tm_wday][0];
    *buf++ = mk_date_wd[gtm->tm_wday][1];
    *buf++ = mk_date_wd[gtm->tm_wday][2];
    *buf++ = ',';
    *buf++ = ' ';

    /* Day of the month */
    *buf++ = ('0' + (gtm->tm_mday / 10));
    *buf++ = ('0' + (gtm->tm_mday % 10));
    *buf++ = ' ';

    /* Year month */
    *buf++ = mk_date_ym[gtm->tm_mon][0];
    *buf++ = mk_date_ym[gtm->tm_mon][1];
    *buf++ = mk_date_ym[gtm->tm_mon][2];
    *buf++ = ' ';

    /* Year */
    *buf++ = ('0' + (year / 1000) % 10);
    *buf++ = ('0' + (year / 100) % 10);
    *buf++ = ('0' + (year / 10) % 10);
    *buf++ = ('0' + (year % 10));
    *buf++ = ' ';

    /* Hour */
    *buf++ = ('0' + (gtm->tm_hour / 10));
    *buf++ = ('0' + (gtm->tm_hour % 10));
    *buf++ = ':';

    /* Minutes */
    *buf++ = ('0' + (gtm->tm_min / 10));
    *buf++ = ('0' + (gtm->tm_min % 10));
    *buf++ = ':';

    /* Seconds */
    *buf++ = ('0' + (gtm->tm_sec / 10));
    *buf++ = ('0' + (gtm->tm_sec % 10));
    *buf++ = ' ';

    /* GMT Time zone + CRLF */
    *buf++ = 'G';
    *buf++ = 'M';
    *buf++ = 'T';
    *buf++ = '\r';
    *buf++ = '\n';
    *buf++ = '\0';

    /* Set mk_pointer data len */
    return size;
}

time_t mk_utils_gmt2utime(char *date)
{
    time_t new_unix_time;
    struct tm t_data;

    if (!strptime(date, GMT_DATEFORMAT, (struct tm *) &t_data)) {
        return -1;
    }

    new_unix_time = mktime((struct tm *) &t_data);

    return (new_unix_time);
}

int mk_buffer_cat(mk_pointer *p, char *buf1, int len1, char *buf2, int len2)
{
    /* Validate lengths */
    if (len1 < 0 || len2 < 0) {
         return -1;
    }

    /* alloc space */
    p->data = (char *) mk_mem_malloc(len1 + len2 + 1);

    /* copy data */
    memcpy(p->data, buf1, len1);
    memcpy(p->data + len1, buf2, len2);
    p->data[len1 + len2] = '\0';

    /* assign len */
    p->len = len1 + len2;

    return 0;
}

/* Run current process in background mode (daemon, evil Monkey >:) */
int mk_utils_set_daemon()
{
    pid_t pid;

    if ((pid = fork()) < 0){
		mk_err("Error: Failed creating to switch to daemon mode(fork failed)");
        exit(EXIT_FAILURE);
	}

    if (pid > 0) /* parent */
        exit(EXIT_SUCCESS);

    /* set files mask */
    umask(0);

    /* Create new session */
    setsid();

    if (chdir("/") < 0) { /* make sure we can unmount the inherited filesystem */
        mk_err("Error: Unable to unmount the inherited filesystem in the daemon process");
        exit(EXIT_FAILURE);
	}

    /* Our last STDOUT message */
    mk_info("Background mode ON");

    fclose(stderr);
    fclose(stdout);

    return 0;
}

/* Convert hexadecimal to int */
int mk_utils_hex2int(char *hex, int len)
{
    int i = 0;
    int res = 0;
    char c;

    while ((c = *hex++) && i < len) {
        res *= 0x10;

        if (c >= 'a' && c <= 'f') {
            res += (c - 0x57);
        }
        else if (c >= 'A' && c <= 'F') {
            res += (c - 0x37);
        }
        else if (c >= '0' && c <= '9') {
            res += (c - 0x30);
        }
        else {
            return -1;
        }
        i++;
    }

    if (res < 0) {
        return -1;
    }

    return res;
}

/* If the URI contains hexa format characters it will return
 * convert the Hexa values to ASCII character
 */
char *mk_utils_url_decode(mk_pointer uri)
{
    int i, hex_result;
    int buf_idx = 0;
    char *buf;
    char hex[3];

    if ((i = mk_string_char_search(uri.data, '%', uri.len)) < 0) {
        return NULL;
    }

    buf = mk_mem_malloc_z(uri.len);

    if (i > 0) {
        strncpy(buf, uri.data, i);
        buf_idx = i;
    }

    while (i < uri.len) {
        if (uri.data[i] == '%' && i + 2 < uri.len) {
            memset(hex, '\0', sizeof(hex));
            strncpy(hex, uri.data + i + 1, 2);
            hex[2] = '\0';

            hex_result = mk_utils_hex2int(hex, 2);

            if (hex_result != -1) {
                buf[buf_idx] = hex_result;
            }
            else {
                mk_mem_free(buf);
                return NULL;
            }
            i += 2;
        }
        else {
            buf[buf_idx] = uri.data[i];
        }
        i++;
        buf_idx++;
    }
    buf[buf_idx] = '\0';

    return buf;
}

#ifdef TRACE
#include <sys/time.h>
void mk_utils_trace(const char *component, int color, const char *function,
                    char *file, int line, const char* format, ...)
{
    va_list args;
    char *color_function = NULL;
    char *color_fileline = NULL;

    char *reset_color = ANSI_RESET;
    char *bold_color = ANSI_BOLD;
    char *magenta_color = ANSI_MAGENTA;
    char *red_color = ANSI_RED;
    char *green_color = ANSI_GREEN;
    char *cyan_color = ANSI_CYAN;

    struct timeval tv;
    struct timezone tz;

    if (envtrace) {
        if (!strstr(envtrace, file)) {
            return;
        }
    }

    /* Mutex lock */
    pthread_mutex_lock(&mutex_trace);

    gettimeofday(&tv, &tz);

    /* Switch message color */
    switch(color) {
    case MK_TRACE_CORE:
        color_function = ANSI_YELLOW;
        color_fileline = ANSI_WHITE;
        break;
    case MK_TRACE_PLUGIN:
        color_function = ANSI_BLUE;
        color_fileline = ANSI_WHITE;
        break;
    }

    /* Only print colors to a terminal */
    if (!isatty(STDOUT_FILENO)) {
        color_function = "";
        color_fileline = "";
        reset_color = "";
        bold_color = "";
        magenta_color = "";
        red_color = "";
        green_color = "";
        cyan_color = "";
    }

    va_start( args, format );

    printf("~ %s%2i.%i%s %s%s[%s%s%s%s%s|%s:%i%s] %s%s():%s ",
           cyan_color, (int) (tv.tv_sec - monkey_init_time), (int) tv.tv_usec, reset_color,
           magenta_color, bold_color,
           reset_color, bold_color, green_color, component, color_fileline, file,
           line, magenta_color,
           color_function, function, red_color);
    vprintf(format, args );
    va_end(args);
    printf("%s\n", reset_color);
    fflush(stdout);

    /* Mutex unlock */
    pthread_mutex_unlock(&mutex_trace);

}

int mk_utils_print_errno(int n)
{
        switch(n) {
        case EAGAIN:
            MK_TRACE("EAGAIN");
            return -1;
        case EBADF:
            MK_TRACE("EBADF");
            return -1;
        case EFAULT:
            MK_TRACE("EFAULT");
            return -1;
        case EFBIG:
            MK_TRACE("EFBIG");
            return -1;
        case EINTR:
            MK_TRACE("EINTR");
            return -1;
        case EINVAL:
            MK_TRACE("EINVAL");
            return -1;
        case EPIPE:
            MK_TRACE("EPIPE");
            return -1;
        default:
            MK_TRACE("DONT KNOW");
            return 0;
        }

        return 0;
}

#endif

/* Write Monkey's PID */
int mk_utils_register_pid()
{
    int fd;
    char pidstr[MK_MAX_PID_LEN];
    unsigned long len = 0;
    char *filepath = NULL;
    struct flock lock;
    struct stat sb;

    if (config->pid_status == MK_TRUE)
        return -1;

    mk_string_build(&filepath, &len, "%s.%d", config->pid_file_path, config->serverport);
    if (!stat(filepath, &sb)) {
        /* file exists, perhaps previously kepts by SIGKILL */
        unlink(filepath);
    }

    if ((fd = open(filepath, O_RDWR | O_CREAT, 0444)) < 0) {
        mk_err("Error: I can't log pid of monkey");
        exit(EXIT_FAILURE);
    }

    /* create a write exclusive lock for the entire file */
    lock.l_type = F_WRLCK;
    lock.l_start = 0;
    lock.l_whence = SEEK_SET;
    lock.l_len = 0;

    if (fcntl(fd, F_SETLK, &lock) < 0) {
        close(fd);
        mk_err("Error: I cannot set the lock for the pid of monkey");
        exit(EXIT_FAILURE);
    }

    sprintf(pidstr, "%i", getpid());
    len = strlen(pidstr);
    if (write(fd, pidstr, len) != len) {
        close(fd);
        mk_err("Error: I cannot write the lock for the pid of monkey");
        exit(EXIT_FAILURE);
    }

    mk_mem_free(filepath);
    config->pid_status = MK_TRUE;

    return 0;
}

/* Remove PID file */
int mk_utils_remove_pid()
{
    unsigned long len = 0;
    char *filepath = NULL;

    mk_string_build(&filepath, &len, "%s.%d", config->pid_file_path, config->serverport);
    mk_user_undo_uidgid();
    if (unlink(filepath)) {
        mk_warn("cannot delete pidfile\n");
    }
    mk_mem_free(filepath);
    config->pid_status = MK_FALSE;
    return 0;
}

void mk_print(int type, const char *format, ...)
{
    time_t now;
    struct tm *current;

    char *header_color = NULL;
    char *header_title = NULL;
    char *bold_color = ANSI_BOLD;
    char *reset_color = ANSI_RESET;
    char *white_color = ANSI_WHITE;
    va_list args;

    va_start(args, format);

    switch (type) {
    case MK_INFO:
        header_title = "Info";
        header_color = ANSI_GREEN;
        break;
    case MK_ERR:
        header_title = "Error";
        header_color = ANSI_RED;
        break;
    case MK_WARN:
        header_title = "Warning";
        header_color = ANSI_YELLOW;
        break;
    case MK_BUG:
#ifdef DEBUG
        mk_utils_stacktrace();
#endif
        header_title = " BUG !";
        header_color = ANSI_BOLD ANSI_RED;
        break;
    }

    /* Only print colors to a terminal */
    if (!isatty(STDOUT_FILENO)) {
        header_color = "";
        bold_color = "";
        reset_color = "";
        white_color = "";
    }

    now = time(NULL);
    struct tm result;
    current = localtime_r(&now, &result);
    printf("%s[%s%i/%02i/%02i %02i:%02i:%02i%s]%s ",
           bold_color, reset_color,
           current->tm_year + 1900,
           current->tm_mon + 1,
           current->tm_mday,
           current->tm_hour,
           current->tm_min,
           current->tm_sec,
           bold_color, reset_color);

    printf("%s[%s%7s%s]%s ",
           bold_color, header_color, header_title, white_color, reset_color);

    vprintf(format, args);
    va_end(args);
    printf("%s\n", reset_color);
    fflush(stdout);
}

pthread_t mk_utils_worker_spawn(void (*func) (void *))
{
    pthread_t tid;
    pthread_attr_t thread_attr;

    pthread_attr_init(&thread_attr);
    pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&tid, &thread_attr, (void *) func, NULL) < 0) {
        perror("pthread_create");
        exit(EXIT_FAILURE);
    }

    return tid;
}

int mk_utils_worker_rename(const char *title)
{
    return prctl(PR_SET_NAME, title, 0, 0, 0);
}

#ifdef DEBUG
#include <execinfo.h>

void mk_utils_stacktrace(void)
{
    int i;
    size_t size;
    char **str;
    void *arr[10];

    printf("\n%s[stack trace]%s\n", ANSI_BOLD, ANSI_RESET);
    size = backtrace(arr, 10);
    str = backtrace_symbols(arr, size);
    for (i = 0; i < size; i++) {
        printf(" + %s\n", str[i]);
    }

    fflush(stdout);

}
#endif

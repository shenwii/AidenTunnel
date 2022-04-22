#ifndef _LOG_H
#define _LOG_H

#include <stdio.h>
#include <time.h>

#define LOG_INFO(fmt, ...)                           \
    {                                                \
        time_t now = time(NULL);                     \
        struct tm *__tm;                             \
        __tm = localtime(&now);                      \
        fprintf(stdout, "INFO:    ");                \
        fprintf(stdout,                              \
            "%04d/%02d/%02d %02d:%02d:%02d, " ,      \
            __tm->tm_year + 1900,                    \
            __tm->tm_mon + 1,                        \
            __tm->tm_mday,                           \
            __tm->tm_hour,                           \
            __tm->tm_min,                            \
            __tm->tm_sec                             \
        );                                           \
        fprintf(stdout, fmt, ## __VA_ARGS__);        \
        fflush(stdout);                              \
    }

#define LOG_ERR(fmt, ...)                            \
    {                                                \
        time_t now = time(NULL);                     \
        struct tm *__tm;                             \
        __tm = localtime(&now);                      \
        fprintf(stderr, "ERROR:   ");                \
        fprintf(stderr,                              \
            "%04d/%02d/%02d %02d:%02d:%02d, " ,      \
            __tm->tm_year + 1900,                    \
            __tm->tm_mon + 1,                        \
            __tm->tm_mday,                           \
            __tm->tm_hour,                           \
            __tm->tm_min,                            \
            __tm->tm_sec                             \
        );                                           \
        fprintf(stderr, fmt, ## __VA_ARGS__);        \
        fflush(stderr);                              \
    }

#define LOG_WARN(fmt, ...)                           \
    {                                                \
        time_t now = time(NULL);                     \
        struct tm *__tm;                             \
        __tm = localtime(&now);                      \
        fprintf(stdout, "WARNING: ");                \
        fprintf(stdout,                              \
            "%04d/%02d/%02d %02d:%02d:%02d, " ,      \
            __tm->tm_year + 1900,                    \
            __tm->tm_mon + 1,                        \
            __tm->tm_mday,                           \
            __tm->tm_hour,                           \
            __tm->tm_min,                            \
            __tm->tm_sec                             \
        );                                           \
        fprintf(stdout, fmt, ## __VA_ARGS__);        \
        fflush(stdout);                              \
    }

#ifdef DEBUG
# define LOG_DEBUG(fmt, ...)                         \
    {                                                \
        time_t now = time(NULL);                     \
        struct tm *__tm;                             \
        __tm = localtime(&now);                      \
        fprintf(stderr, "DEBUG:   ");                \
        fprintf(stderr,                              \
            "%04d/%02d/%02d %02d:%02d:%02d, " ,      \
            __tm->tm_year + 1900,                    \
            __tm->tm_mon + 1,                        \
            __tm->tm_mday,                           \
            __tm->tm_hour,                           \
            __tm->tm_min,                            \
            __tm->tm_sec                             \
        );                                           \
        fprintf(stderr, fmt, ## __VA_ARGS__);        \
        fflush(stderr);                              \
    }
#else
# define LOG_DEBUG(fmt, ...)
#endif

#endif

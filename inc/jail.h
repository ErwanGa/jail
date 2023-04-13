/*
 * Copyright 2021
 */

/**
 * @file jail.h
 * @brief
 * @author Erwan Gautron
 * @version 0.1
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/time.h>          /**< setrlimit - rlim_t typedef */
#include <sys/resource.h>      /**< setrlimit - rlim_t typedef */
#include <semaphore.h>
#include <pwd.h>               /**< getpwnam */
#include <grp.h>
#include <fcntl.h>
#ifndef DEBUG
#include <syslog.h>
#endif

#define VAR_RUN "/var/run/jail"


#if defined __x86_64__
#define UINT32_FMT "%d"
#define UINT64X_FMT "%07lx"
#define UINT32X_FMT "%07x"
#else
#define SINT64_FMT "%lld"
#define UINT32_FMT "%d"
#define UINT64X_FMT "%07llx"
#define UINT32X_FMT "%07x"
#define UINT64_FMT "%lld"

#endif






#ifdef DEBUG
#define CG_LOG_NAME "[NxJail]"
#define CG_LOG_DIE  "[NxJail]"
#define LOG_FATAL 1
#define LOG_ERR 2
#define LOG_WARNING  3
#define LOG_DEBUG  4

#define LOG_LEVEL 4

#define S(l) (1==l) ? "FATAL" : (2==l) ? "ERROR" :(3==l) ? "WARN" :(4==l) ? "INFO" : "DBG"
#define LOG(level, trc, ...) do{ if (level<=LOG_LEVEL) {fprintf(stderr, CG_LOG_NAME "[%s]: " trc, S(level), ## __VA_ARGS__);  } }while(0)
#define DIE(trc, ...) do{ if (LOG_FATAL<=LOG_LEVEL) { fprintf(stderr, CG_LOG_DIE " " trc "\n", ## __VA_ARGS__);};  exit(1); }while(0)

#define ENTER() LOG(LOG_DEBUG, "Enter %s\n", __func__)
#define EXIT()  LOG(LOG_DEBUG, "Exit %s\n", __func__)
#else

#define LOG_LEVEL LOG_WARNING

#define LOG(level, trc, ...) do { if (level<=LOG_LEVEL) syslog(level, trc,  ## __VA_ARGS__); } while(0);
#define DIE(trc, ...) do { syslog(LOG_CRIT, trc "\n", ## __VA_ARGS__); exit(1); }while(0);

#define ENTER() LOG(LOG_DEBUG, "Enter %s\n", __func__)
#define EXIT()  LOG(LOG_DEBUG, "Exit %s\n", __func__)
#endif

#define MAX_NAME_LEN   256
#define MAX_ID_LEN     32
#define MAX_BIND_LEN   256
#define MAX_CAPS_LEN   1024
#define MAX_HOME_LEN   256
#define MAX_LIBS_LEN   1024
#define MAX_ARGS_LEN   1024
#define MAX_PATH_LEN   1024
/**
 * @brief
 */
typedef struct limits_s
{
  rlim_t as;        /**< The maximum size of the process's virtual memory */
  rlim_t fsize;     /**< The  maximum size of files that the process may create. */
  rlim_t stack;     /**< The maximum size of the process stack, in bytes.*/
  rlim_t mq;        /**< Specifies  the  limit  on the number of bytes that can be allocated for
                      POSIX message queues for the real user ID of the calling process */
  rlim_t data;      /**< The  maximum  size  of  the process's data segment (initialized data, uninitialized data, and heap).*/
  int nice;         /**< process nicing */
  int arena;        /**< MALLOC_ARENA_MAX */
}limits_t;


/**
 * @brief
 */
typedef struct data_s
{
    char     name[MAX_NAME_LEN];    /**< Full Name of the process  */
    struct   passwd *user ;         /**< User  */
    struct   group  *grp;           /**< User group */
    char     caps[MAX_CAPS_LEN];    /**< capabilities */
    char     args[MAX_ARGS_LEN];     /**< program arguments */
    limits_t  limits;               /**< Limits - if values is set to 0 then unlimited*/
    mode_t    umask;                /**< Umask to set*/
    char     chpath[MAX_LIBS_LEN];  /** path for chroot */
    char     home[MAX_HOME_LEN];    /**< home */
    char     copy_f[MAX_LIBS_LEN];  /**< copied (not binded) /etc/<file> */
    char     copy_d[MAX_LIBS_LEN];  /**< copied (not binded) /etc/bmq */
    char     bind_ro[MAX_BIND_LEN]; /**< binded dir /lib /usr/lib */
    char     bind_rw[MAX_BIND_LEN]; /**< binded in rw mode */
    bool     never_die;             /**< if true the process shall be restarted when dying */
    bool     reboot_on_die;         /**< if true the board shall reboot on process crash */
}data_t;

typedef struct {
    sem_t sem;  /**< semaphore */
    int i;     /* counter */
} semint_t;

extern semint_t *synchronizer;
/**
 * @brief
 *     Parse file in to get needed datas for launching the required process
 * @param in
 *     Parameters file name
 * @param out
 *     Structure containing the required datas
 * @return
 *     0 if success
 *     DIE (process exit) in an error occurs
 */
int parse(const char *const in, data_t *const out);

/**
 * @brief
 *    Launch the process in its jail
 * @param in
 *    Data fillup by perse function
 * @see
 *   parse
 */
void launch(data_t * const in);


/**
 * @brief
 *      Create the jail
 * @param in
 */
void create_jail(data_t * const in);


/**
 * @brief
 *     Destroy the jail
 * @param in
 */
void destroy_jail(data_t * const in);


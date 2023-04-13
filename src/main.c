/**
 * @file main.c
 * @brief
 * @author Erwan Gautron
 * @version 0.1
 */

/***
 * @brief Launch a program in a chroot
 *   * Drop privileges
 *   * Set limits
 *   * Creation sandbox and chroot
 *   * Change uid:gid
 *   * fork and execv
 */
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <pwd.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>    //write
#include <time.h>    //write
#include "../inc/jail.h"
#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
/**
 * @brief
 *
 * @param argc
 * @param []
 *
 * @return
 */
static bool killed=false;
static int jail_main(char* data_path)
{
    data_t * data = (data_t*) calloc(1, sizeof(data_t));
    ENTER();
    if (NULL != data)
    {
        do{
            if (0 == parse(data_path, data) )
            {
                launch(data);
            }
            else
            {
                data->never_die = 0;

            }
            if ( killed )
                data->never_die = 0;
        }while(data->never_die);
        if ((data->reboot_on_die) && (!killed))
        {
            LOG(LOG_DEBUG, "Shall call reboot");
        }
        free(data);
    }
    EXIT();
    return 0;
}

/**
 * @brief
 *
 * @param signum
 */
static void child_handler(int signum)
{
    /*
     * [CWE-479] [-Werror=analyzer-unsafe-call-within-signal-handler]
     * change exit call by _exit
     * ‘_exit’ is a possible signal-safe alternative for ‘exit’
     */
    switch(signum)
    {
        case SIGALRM: _exit(EXIT_FAILURE); break;
        case SIGUSR1: _exit(EXIT_SUCCESS); break;
        case SIGUSR2: _exit(EXIT_SUCCESS); break;
        case SIGCHLD: _exit(EXIT_FAILURE); break;
    }
}
static void term_handler(int signum)
{
    switch(signum)
    {
        case SIGTERM :
            killed = true; break;
        default:
        break;
    }
}

/**
 * @brief
 *
 * @return
 */


static void starts (char * const path, bool delete)
{
    pid_t pid_0, pid_1;

    /* fork ... */
    pid_0 = fork();

    if (0 == pid_0)
    {
        /* I'm the child */
        signal(SIGCHLD,child_handler);
        signal(SIGUSR1,child_handler);
        signal(SIGALRM,child_handler);

        /* But I become a parent */
        pid_1 = fork();

        if (pid_1 > 0)
        {
            /* And I wait that my child kill me
             * It will release my parent continuing it's job*/
            alarm(2);
            pause();
            exit(EXIT_FAILURE);
            //exit(0);
        }
        else
        {
            /* I'm the little child*/
            int sid;

            int parent = getppid();
            signal(SIGCHLD,SIG_DFL); /* A child process dies */
            signal(SIGTSTP,SIG_IGN); /* Various TTY signals */
            signal(SIGTTOU,SIG_IGN);
            signal(SIGTTIN,SIG_IGN);
            signal(SIGHUP, SIG_IGN); /* Ignore hangup signal */

            umask(0);
            /* detach me from my parent */
            sid = setsid();
            if (sid<0)
            {
                exit(EXIT_FAILURE);
            }
#ifdef NO_PRINTF
            /* Redirect standard files to /dev/null */
            freopen( "/dev/null", "r", stdin);
            freopen( "/dev/null", "w", stdout);
            freopen( "/dev/null", "w", stderr);
#endif
            /* Tell the parent process that we are A-okay */
            kill( parent, SIGUSR1 );
            LOG(LOG_DEBUG, "I'm %d \n", getpid());

            signal(SIGTERM, term_handler); /* SIGTERM shall wait the end of child */
            /* calling the jail keeper */
            if (jail_main(path) != 0)
            {
                LOG(LOG_DEBUG, "execve Error %d \n", errno);
            }

            if (delete)
            {
                /*delete the XML if needed */
                unlink(path);
            }
            EXIT();
            exit(0);
        }
    }
    else
    {
        int status;
        /* wait end of the fork */
        waitpid(pid_0, &status, 0);
        LOG(LOG_DEBUG, "End of daemonizing the new process\n");
    }
}

FILE *LCH_log = NULL;


/*
 *
 * Entry point
 * Arg[1] xml
 * arg[2] latest
 * */
#define LOCK_F "/var/lock/subsys/jail"


#define LOG_F "/var/log/jail.log"


/**
 * @brief
 *
 * @param argc
 * @param []
 *
 * @return
 */
int main (int argc, char*argv [])
{
    struct stat st;
    uid_t myuid = getuid();
    struct timeval tv_1;
    struct timeval tv_2;

    if (0 != myuid)
    {
        printf("You shall be root for running this command\n");
        exit(EXIT_FAILURE);
    }


    if ( (1 == argc) || (argc > 3))
    {
        exit(EXIT_FAILURE);
    }
    /* do not start if locked */
    if (0 == stat (LOCK_F, &st))
    {
        exit(EXIT_FAILURE);
    }

   gettimeofday(&tv_1, NULL);

#ifndef DEBUG
    openlog("Nxjail", LOG_CONS|LOG_PID, LOG_USER);
#endif
    /* LOCK ME*/
    if (3 == argc)
    {
        /* if argc == 3 then create the lock */
        int lfp = open(LOCK_F,O_RDWR|O_CREAT|O_EXCL,0640);
        if ( lfp < 0 )
        {
            LOG( LOG_ERR, "unable to create lock file %s, code=" UINT32_FMT "(%s)", LOCK_F, errno, strerror(errno) );
            exit(EXIT_FAILURE);
        }
    }

    if (stat(VAR_RUN, &st) != 0)
    {
        /* Directory does not exist. EEXIST for race condition */
        mkdir(VAR_RUN, 0755);
    }

    LOG(LOG_DEBUG,"Hello %d\n", argc);


    if (0 == stat(argv[1], &st))
    {
        fprintf(stderr,"Starting %s : ", argv[1]);
        LOG(LOG_DEBUG, "-----> Starting %s \n", argv[1]);
        starts(argv[1], false);
    }

    /* let time to execve to start */
    /* get time for stat stat */
    gettimeofday(&tv_2, NULL);

    fprintf(stderr,"OK \n");
    LOG(LOG_WARNING,"-----> Started <%ld %ld>\n",
            tv_2.tv_sec - tv_1.tv_sec,
            tv_2.tv_usec - tv_1.tv_usec);
#ifndef DEBUG
    closelog();
#endif
    return 0;
}


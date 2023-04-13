/**
 * @file run.c
 * @brief
 * @author Erwan Gautron
 * @version 0.1
 */

#include "../inc/jail.h"
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>       /*<< getpwnam */
#include <sys/wait.h>
#include <sys/stat.h>       /*<< umask */
#include <cap-ng.h>          /* libcap-ng */
#define _GNU_SOURCE
#include <sys/prctl.h>
#include <sys/capability.h>  /* libcap */
#include <sys/stat.h>
#include <fcntl.h>


/**
 * @brief
 *
 * @param in
 *
 * @return
 */

static void set_signal_handles()
{
    sigset_t empty;
    ENTER();
    /* Empty the signal mask in case someone is blocking a signal */
    if (sigemptyset(&empty)) {
            DIE("Unable to obtain empty signal set\n");
    }
    LOG(LOG_DEBUG, "Set Signal for %d\n", getpid());
    sigprocmask(SIG_SETMASK, &empty, NULL);
    /* Terminate on SIGHUP. */
    signal(SIGCHLD,SIG_DFL); /* A child process dies */
    signal(SIGTSTP,SIG_IGN); /* Various TTY signals */
    signal(SIGTTOU,SIG_IGN);
    signal(SIGTTIN,SIG_IGN);
    signal(SIGHUP, SIG_DFL); /* Die on SIGHUP */
    signal(SIGTERM, SIG_DFL); /* Die on SIGTERM */
    EXIT();
}
/**
 * @brief
 *   set the limits
 * @param in
 *
 * @return
 */
static void set_limits(data_t *in)
{
    int retVal = 0;
    struct rlimit rlim;
    ENTER();
    /*assume that in != NULL */
    /* setting limits of mem usage */
    if (0 == retVal)
    {
        rlim.rlim_cur = (in->limits.as == 0) ?  RLIM_INFINITY : in->limits.as ;
        rlim.rlim_max = (in->limits.as == 0) ?  RLIM_INFINITY : in->limits.as ;
        retVal = setrlimit (RLIMIT_AS, &rlim);
    }

    if (0 == retVal)
    {
        /* setting rlim file on disk */
        rlim.rlim_cur = (in->limits.fsize == 0) ?  RLIM_INFINITY : in->limits.fsize;
        rlim.rlim_max = (in->limits.fsize == 0) ?  RLIM_INFINITY : in->limits.fsize;
        retVal = setrlimit (RLIMIT_FSIZE, &rlim);
    }

    if (0 == retVal)
    {
        /* setting rlim message queue */
        rlim.rlim_cur = (in->limits.mq == 0) ?  RLIM_INFINITY : in->limits.mq ;
        rlim.rlim_max = (in->limits.mq == 0) ?  RLIM_INFINITY : in->limits.mq ;
        retVal = setrlimit (RLIMIT_MSGQUEUE, &rlim);
    }

    if (0 == retVal)
    {
        /* setting rlim stack size */
        rlim.rlim_cur = (in->limits.stack == 0) ?  RLIM_INFINITY : in->limits.stack;
        rlim.rlim_max = (in->limits.stack == 0) ?  RLIM_INFINITY : in->limits.stack;
        retVal = setrlimit (RLIMIT_STACK, &rlim);
    }

    if (0 == retVal)
    {
        /* Force Core dump limit to 0 */
        rlim.rlim_cur = 0;
        rlim.rlim_max = 0;
        retVal = setrlimit (RLIMIT_CORE, &rlim);
    }



    if (0 != retVal)
    {
        DIE("Cannot set the limits");
    }

    EXIT();
}



/**
 * @brief
 * Returns if capability is authorised
 * @param cap
 *     capablities in capng string format
 * @return
 *      true if capabilities can be used
 *
 * sys_admin, setpcap, setfcap, sys_chroot are forbidden
 */
static bool is_authorised_cap(char * cap)
{
    bool retval = ! (
            (0 == strncmp (cap, "sys_admin", 9) ) ||
            (0 == strncmp (cap, "setpcap", 7) ) ||
            (0 == strncmp (cap, "setfcap", 7) ) ||
            (0 == strncmp (cap, "sys_chroot", 10) )
            );
    return retval;
}

/**
 * @brief
 *    Drop capalibilities;
 *    Set the required caps
 *    change the user
 *
 * @param in
 *
 * @return
 */
/***
 * capabilities string
 * chown, dac_override, dac_read_search
 * fowner, fsetid, kill, setgid, setuid, setpcap
 * linux_immutable, net_bind_service, net_broadcast
 * net_admin, net_raw
 * ipc_lock, ipc_owner, sys_module
 * sys_module, sys_rawio, sys_chroot, sys_ptrace
 * sys_pacct, sys_admin ,sys_boot, sys_nice
 * sys_resource, sys_time, sys_tty_config
 * mknod, lease, audit_write, audit_control
 * setfcap, mac_override, mac_admin, syslog, wake_alarm
 * block_suspend, audit_read
 *

 * syslog shall be setted if the process wants to use syslog :-)
 */
static void set_caps(data_t * const in)
{
    int retVal = 0;
    int caps=0;
    char *cap = NULL;
    int chown = 0 ;
    char fcap [256];
    char *saveptr =NULL;
    /**
     * static function, assume that in is not NULL
     */
    ENTER();
    if (NULL == in->user)
    {
        /* just to remove some warnings as in->user
         * is always set due
         * to the xml parsing and dtd
         */
        DIE("User Not set");
    }

    capng_clear(CAPNG_SELECT_BOTH);
    capng_update(CAPNG_ADD, CAPNG_EFFECTIVE|CAPNG_PERMITTED|CAPNG_INHERITABLE, CAP_CHOWN);
    capng_update(CAPNG_ADD, CAPNG_EFFECTIVE|CAPNG_PERMITTED|CAPNG_INHERITABLE, CAP_SETPCAP);
    capng_update(CAPNG_ADD, CAPNG_EFFECTIVE|CAPNG_PERMITTED|CAPNG_INHERITABLE, CAP_SETFCAP);
    cap = strtok_r(in->caps, " ", &saveptr);
    fcap[0]=0;
    while(cap != NULL)
    {
        if ((caps = capng_name_to_capability(cap)) >= 0)
        {
            int a = strlen(fcap);
            LOG (LOG_DEBUG, "setting CAP %s  \n", cap);
            if (strncmp ( cap, "chown", 6) == 0)
                chown = 1;
            if (is_authorised_cap(cap))
            {
                capng_update( CAPNG_ADD, CAPNG_EFFECTIVE|CAPNG_PERMITTED|CAPNG_INHERITABLE, caps );
                if (a<255)
                    snprintf(&fcap[a], 255-a, "cap_%s+epi  ", cap);
                LOG(LOG_DEBUG, "%d %s\n",a,  fcap);
            }
        }
        cap = (char*) strtok_r(NULL, " ", &saveptr);
    }


    if (fcap[0] != 0)
    {
        int ee = 0;
        cap_t aa = cap_from_text(fcap);
        if (aa != NULL)
        {
            ee = cap_set_file(in->name, aa);
            if (0 != ee )
            {
                LOG(LOG_DEBUG, "cap_set_file %s %s %d\n", in->name, fcap, ee);
            }
        }
        else
        {
            LOG(LOG_DEBUG, "cap_from_text %s\n", fcap);
        }
    }
    LOG(LOG_DEBUG, "Change Id %s (%d / %d) \n", in->user->pw_name, in->user->pw_uid, in->grp->gr_gid);
    if ((retVal = capng_change_id(in->user->pw_uid, in->grp->gr_gid,  CAPNG_DROP_SUPP_GRP|CAPNG_CLEAR_BOUNDING )) != 0)
    {
        DIE("capng_change_id error %i\n", retVal);
    }

    if (!chown)
        capng_update(CAPNG_DROP, CAPNG_EFFECTIVE|CAPNG_PERMITTED|CAPNG_INHERITABLE, CAP_CHOWN);
    capng_update(CAPNG_DROP, CAPNG_EFFECTIVE|CAPNG_PERMITTED|CAPNG_INHERITABLE, CAP_SETPCAP);
    capng_update(CAPNG_DROP, CAPNG_EFFECTIVE|CAPNG_PERMITTED|CAPNG_INHERITABLE, CAP_SETFCAP);

    capng_apply(CAPNG_SELECT_BOTH);

    cap = strtok_r(in->caps, " ", &saveptr);
    fcap[0]=0;
    while(cap != NULL)
    {
        if ((caps = capng_name_to_capability(cap)) >= 0)
        {
            LOG (LOG_DEBUG, "CAP AMBIENT%s  \n", cap);
            if (is_authorised_cap(cap))
            {
                if ( prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, caps, 0, 0) < 0)
                {
                    DIE("PR_CAP_AMBIENT error \n");
                }

            }
        }
        cap = (char*) strtok_r(NULL, " ", &saveptr);
    }


    if ((retVal = prctl(PR_SET_KEEPCAPS, 1)) < 0)
    {
        DIE("prctl(PR_SET_KEEPCAPS) failed");
    }

    EXIT();
}

/**
 * @brief
 *    set umask for the new processus
 *
 * @param in
 *
 * @return
 */
static void set_umask(data_t * const  in)
{
    ENTER();
    /* umask call never fails */
    umask(in->umask);

    EXIT();
}

static int set_nice(data_t * const  in)
{
    int retVal = 0;

    if ( (0 != in->limits.nice) && ( in->limits.nice < 19) && (in->limits.nice > -20))
    {
        retVal = nice (in->limits.nice);
        LOG (LOG_DEBUG, "set nice %d %d  \n", in->limits.nice, retVal);
    }
    return retVal = 0;
}

static void run(data_t * const in, int f)
{
    int retVal = 0;
    int child;
    int status = -1;
    int nbarg = 0;
    char *args[16] ={0}; /* assume that args is not >16 */
    char *envs[16] ={0}; /* assume that args is not >16 */
    char *saveptr =  NULL;
    ENTER();


    LOG(LOG_DEBUG, "Parse args\n");
     /* fill args array */
    args[0] = in->name;
    nbarg = 1;
    args[nbarg] = strtok_r(in->args, " ", &saveptr);
    while( NULL!=args[nbarg] && nbarg<16)
    {
        nbarg++;
        args[nbarg] = (char*) strtok_r(NULL, " ", &saveptr);
    }
    child = fork();

    if ( -1 == child )
    {
        DIE("Cannot fork");
    }
    else if ( 0 == child )
    {
#if 0
        char env_arena[64]={0};
#endif
        char env_home[]="HOME=";
        char env_shell[]="SHELL=";
        char env_path[]="PATH=";
        int env_id=0;

        envs[env_id] = env_home;env_id++;
        envs[env_id] = env_shell;env_id++;
        envs[env_id] = env_path;env_id++;


        retVal |= setenv("HOME", "", 1);
        retVal |= setenv("SHELL", "", 1);
        retVal |= setenv("PATH", "", 1);

        if (in->limits.arena > 0)
        {
#if 0
            char arena[16];
            snprintf(arena, 15, "%d", in->limits.arena);
            LOG(LOG_ERR, "arena %s\n", arena);
            retVal |= setenv("MALLOC_ARENA_MAX", arena, 1);
            snprintf(env_arena, 63, "MALLOC_ARENA_MAX=%d", in->limits.arena);
            envs[env_id] =  env_arena;env_id++;
#endif
        }
        else
        {
            LOG(LOG_ERR, "arena not set\n");
        }

        if ( 0 != retVal )
        {
            DIE("Cannot set environment");
        }

        LOG(LOG_DEBUG, "execve %s\n", args[0]);


        if ( execve(in->name, args, envs) < 0 )
        {
            DIE("execve Error %d %s \n", errno, envs[0]);
        }
    }
    else
    {
        /* 0 != child => i'm the parent end childpid is child */
        int mypid = getpid();
        int myppid = getppid();
        if ( write(f, &child, sizeof(child)) < 0 )
        {
            LOG(LOG_ERR, "Write error\n");
        }
        else if ( write(f, &mypid, sizeof(mypid)) < 0 )
        {
            LOG(LOG_ERR, "Write error\n");
        }
        else if ( write(f, &myppid, sizeof(myppid)) < 0 )
        {
            LOG(LOG_ERR, "Write error\n");
        }
        LOG(LOG_DEBUG,"Store %d %d %d \n",  child, mypid, myppid);
        close(f);

        LOG(LOG_DEBUG, "waitpid\n");
        waitpid(child, &status, 0);
        LOG(LOG_DEBUG, "child died, exiting..\n");
        exit(0);
    }

    EXIT();
}

/**
 * @brief
 *
 * @param in
 *
 * @return
 */

void launch(data_t * const in)
{
    int child;
    int status = -1;

    ENTER();

    if (NULL != in)
    {
        char locker[MAX_LIBS_LEN+32];
        int f;
        snprintf(locker ,MAX_LIBS_LEN+32 , "%s/%s", VAR_RUN, in->chpath );
        f = open (locker, O_CREAT | O_WRONLY | O_EXCL, 0666);
        if (f<0)
        {
            LOG(LOG_ERR, "Process already running");
            in->never_die = 0;
            return;
        }

        child = fork();

        if (-1 == child)
        {
            DIE("Cannot fork\n");
        }
        else if (0 == child)
        {
            set_nice(in);
            set_signal_handles();
            /* Here we chroot/chgid */
            create_jail(in);
            set_limits(in);
            set_caps(in);
            set_umask(in);
            run(in, f);
        }
        else
        {
            close(f);

            waitpid(child, &status, 0);
            /* I'm the parent
             * if my child dies , I shell delete the jail
             */
            destroy_jail(in);
            LOG(LOG_DEBUG, "delete %s\n", locker);
            unlink(locker);
        }
    }

    EXIT();
}

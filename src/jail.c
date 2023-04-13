/**
 * @file jail.c
 * @brief
 * @author Erwan Gautron
 * @version 0.1
 */

#include "../inc/jail.h"
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/mount.h>
#include <libgen.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/sendfile.h>
#include <fts.h>

#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <mntent.h>

#define JAIL_EP "/var/jail"
#define MAX_PATH_LEN_16 (MAX_PATH_LEN+32)

/**
 * @brief
 *     Create diretory
 * @param path
 *     Path a dir to create
 * @param mode
 *     mode
 * @return
 */
static int do_mkdir(const char *path, mode_t mode)
{
    struct stat     st;
    int             status = 0;

    if (stat(path, &st) != 0)
    {
        /* Directory does not exist. EEXIST for race condition */
        if (mkdir(path, mode) != 0 && errno != EEXIST)
            status = -1;
    }
    else if (!S_ISDIR(st.st_mode))
    {
        errno = ENOTDIR;
        status = -1;
    }

    return(status);
}


/**
 * @brief
 *
 * @param path
 * @param mode
 *
 * @return
 */
static int mkpath(const char *path, mode_t mode)
{
    char           *pp;
    char           *sp;
    int             status;
    char           *copypath = strdup(path);

    status = 0;
    pp = copypath;
    while (status == 0 && (sp = strchr(pp, '/')) != 0)
    {
        if (sp != pp)
        {
            /* Neither root nor double slash in path */
            *sp = '\0';
            status = do_mkdir(copypath, mode);
            *sp = '/';
        }
        pp = sp + 1;
    }
    if (status == 0)
        status = do_mkdir(path, mode);
    free(copypath);
    return (status);
}


/**
 * @brief
 *      mount bind src directory in dst
 * @param src
 *      initial path
 * @param dst
 *      binding path
 * @param ro
 *      remount in with readonly
 * @param dev
 *      enable dev creation
 */
static void do_mount(const char * const src, const char * const dst, bool ro, bool dev)
{
    unsigned long flags =  MS_BIND | MS_DIRSYNC ;
    LOG(LOG_DEBUG, "----> Binding  %s in %s\n", src, dst);
/* just kill a process */
    if (mount(src, dst,  NULL , flags, NULL) < 0)
    {
        DIE("cannot mount bind %d", errno);
    }
    if (!dev)
    {
        flags = MS_BIND | MS_DIRSYNC | (ro ?  MS_RDONLY : 0 ) | MS_NODEV |  MS_NOSUID | MS_REMOUNT | MS_SYNCHRONOUS;
        if (mount(src, dst,  NULL , flags, NULL) < 0)
        {
            DIE("cannot remount rd %d", errno);
        }
        if (ro)
        {
            chmod(dst, 0555);
        }
    }
}

/**
 * @brief
 *    recursive directory deletion; Deletes dir even if the directory is empty
 * @param path
 *    path to delete
 */
static void delete_dirs(const char *dir)
{
    FTS *ftsp = NULL;
    FTSENT *curr;
    char *files[] = { (char *) dir, NULL };

    // FTS_NOCHDIR  - Avoid changing cwd, which could cause unexpected behavior
    //                in multithreaded programs
    // FTS_PHYSICAL - Don't follow symlinks. Prevents deletion of files outside
    //                of the specified directory
    // FTS_XDEV     - Don't cross filesystem boundaries
    ftsp = fts_open(files, FTS_NOCHDIR | FTS_PHYSICAL | FTS_XDEV, NULL);
    if (!ftsp) {
        LOG(LOG_ERR, "%s: fts_open failed: %s\n", dir, strerror(errno));
        return;
    }

    while ((curr = fts_read(ftsp))) {
        switch (curr->fts_info) {
        case FTS_NS:
        case FTS_DNR:
        case FTS_ERR:
            LOG(LOG_ERR, "%s: fts_read error: %s\n",
                    curr->fts_accpath, strerror(curr->fts_errno));
            break;

        case FTS_DC:
        case FTS_DOT:
        case FTS_NSOK:
            // Not reached unless FTS_LOGICAL, FTS_SEEDOT, or FTS_NOSTAT were
            // passed to fts_open()
            break;

        case FTS_D:
            // Do nothing. Need depth-first search, so directories are deleted
            // in FTS_DP
            break;

        case FTS_DP:
        case FTS_F:
        case FTS_SL:
        case FTS_SLNONE:
        case FTS_DEFAULT:
            if (remove(curr->fts_accpath) < 0) {
                LOG(LOG_ERR, "%s: Failed to remove: %s\n",
                        curr->fts_path, strerror(errno));
            }
            break;
        }
    }
    fts_close(ftsp);
}

/**
 * @brief
 *     umount a binded dir
 * @param path
 */


static bool is_mounted(const char * const path)
{
    FILE *mtab = NULL;
    struct mntent * part = NULL;
    bool ret = false;

    mtab = setmntent("/etc/mtab","r");
    if (NULL != mtab)
    {
        while ( ((part=getmntent(mtab)) != NULL)&& (!ret) )
        {
            if (NULL != part->mnt_fsname)
            {
              ret = ( 0 == strcmp(part->mnt_dir, path) );
            }
        }
    }
    return ret;
}

static void do_umount(const char * const path)
{
    LOG(LOG_DEBUG, "Umount %s \n", path);
    if (is_mounted(path))
    {
        if ( -1 == umount2(path,  MNT_DETACH) )
        {
            LOG(LOG_DEBUG, "Cannot umount %s (%d)\n",path, errno);
            pause();
        }
    }
    else
    {
        LOG(LOG_DEBUG, "%s seems not yet mounted\n", path);
    }
}


/**
 * @brief
 *     Create a basic skeleton of the jail
 * @param in
 */
static void create_basic_skel(data_t *  const in)
{
    char *shortname = in->chpath;
    char  path[MAX_PATH_LEN_16*2];

    /* base */
    do_mkdir(JAIL_EP, 0755);

    /* jail */
    snprintf(path, MAX_PATH_LEN_16, JAIL_EP "/%s", shortname);
    if(0 != do_mkdir(path, 0755) )
    {
        DIE("Cannot create %s", path);
    }

    snprintf(path, MAX_PATH_LEN_16, JAIL_EP "/%s/dev", shortname);
    if(0 != do_mkdir(path, 0755) )
    {
        DIE("Cannot create %s", path);
    }

    snprintf(path, MAX_PATH_LEN_16, JAIL_EP "/%s/dev/shm", shortname);
    if(0 != do_mkdir(path, 0755) )
    {
        DIE("Cannot create %s", path);
    }

    snprintf(path, MAX_PATH_LEN_16, JAIL_EP "/%s/dev/pts", shortname);
    if(0 != do_mkdir(path, 0755) )
    {
        DIE("Cannot create %s", path);
    }

    snprintf(path, MAX_PATH_LEN_16, JAIL_EP "/%s/proc", shortname);
    if(0 != do_mkdir(path, 0755) )
    {
        DIE("Cannot create %s", path);
    }
    /* libs */
    snprintf(path, MAX_PATH_LEN_16, JAIL_EP "/%s/lib", shortname);
    if (0 != do_mkdir(path, 0755) )
    {
        DIE("Cannot create %s", path);
    }

    /* bin */
    snprintf(path, MAX_PATH_LEN_16, JAIL_EP "/%s/bin", shortname);
    if (0 != do_mkdir(path, 0755) )
    {
        DIE("Cannot create %s", path);
    }

    /* etc */
    snprintf(path, MAX_PATH_LEN_16,  JAIL_EP "/%s/etc", shortname);
    if (0 != do_mkdir(path, 0755) )
    {
        DIE("->Cannot create %s", path);
    }

    /* home */
    snprintf(path, MAX_PATH_LEN_16,  JAIL_EP "/%s/home", shortname);
    if (0 != do_mkdir(path, 0755) )
    {
        DIE("->Cannot create %s", path);
    }

    /* home/user */
    snprintf(path, MAX_PATH_LEN_16*2,  JAIL_EP "/%s/home/%s", shortname, in->home);
    if (0 != do_mkdir(path, 0750) )
    {
        DIE("->Cannot create %s", path);
    }

    if (-1 == chown(path, in->user->pw_uid, in->grp->gr_gid) )
    {
        printf("Error while chowning home\n");
    }


}

static void temp(data_t * const in)
{
   char  path[MAX_PATH_LEN_16];
   struct stat st;
   char *shortname = in->chpath;
   snprintf(path, MAX_PATH_LEN_16,  JAIL_EP "/%s/data/tmp", shortname);
   if ( 0 == stat(path, &st) )
   {
        if (S_ISDIR(st.st_mode))
        {
            char local [MAX_PATH_LEN_16] = {0};
            if (NULL != getcwd(local,  MAX_PATH_LEN_16))
            {

                snprintf(path, MAX_PATH_LEN_16,  JAIL_EP "/%s", shortname);
                if (0 != chdir (path) ){}
                if (0 !=symlink("data/tmp", "tmp"))
                {
                    printf("symlink in %s\n", shortname);
                }
                if (0 != chdir(local) ) {}
            }
        }
   }
}


/**
 * @brief
 *    mount bind directories
 *      dev and proc are automaticly mount
 *      then bind dir given in bind_ro and and bind_rw fields
 * @param in
 */
static void mount_dirs(data_t * const in)
{
    char *shortname =  in->chpath;
    char  path[MAX_PATH_LEN_16];
    char  f_path[MAX_PATH_LEN_16];
    char *f = NULL;
    char *saveptr = NULL;

    /* TODO : remove binding of dev and replace it
     * by the needed mknod -> field to add in the xml
     * description
     * */
    snprintf(path, MAX_PATH_LEN_16,   JAIL_EP "/%s/dev", shortname);
    do_mount("/dev", path, false, true);
    snprintf(path, MAX_PATH_LEN_16,   JAIL_EP "/%s/dev/pts", shortname);
    do_mount("/dev/pts", path, false, true);
    snprintf(path, MAX_PATH_LEN_16,   JAIL_EP "/%s/dev/shm", shortname);
    do_mount("/dev/shm", path, false, true);
    snprintf(path, MAX_PATH_LEN_16,   JAIL_EP "/%s/proc", shortname);
    do_mount("/proc", path, true, false);

    /* read bind_ro, all dir are split by ' ' */
    f = strtok_r(in->bind_ro, " ", &saveptr);
    while(f != NULL)
    {
        int cpt=0;
        while (f[cpt]!='/' && f[cpt]!=0 ) cpt++;
        snprintf(f_path, MAX_PATH_LEN_16, JAIL_EP "/%s%s", shortname, &f[cpt]);
        mkpath(f_path, 0755);
        do_mount(&f[cpt], f_path, true, false);
        f = strtok_r(NULL, " ", &saveptr);
    }

    f = strtok_r(in->bind_rw, " ",  &saveptr);
    while(f != NULL)
    {
        int cpt=0;
        while (f[cpt]!='/' && f[cpt]!=0 ) cpt++;
        snprintf(f_path, MAX_PATH_LEN_16, JAIL_EP "/%s%s", shortname, &f[cpt]);
        mkpath(f_path, 0755);
        do_mount(&f[cpt], f_path, false, false);
        f = strtok_r(NULL, " ", &saveptr);
    }
}


/**
 * @brief
 *    umount the binded dir
 *    !! It shall be done by the parent of the jail !!
 * @param in
 */
static void umount_dirs(data_t * const in)
{
    char *shortname =   in->chpath;
    char  path[MAX_PATH_LEN_16];
    char  f_path[MAX_PATH_LEN_16];
    char *f = NULL;
    char *saveptr = NULL;

    snprintf(path, MAX_PATH_LEN_16,   JAIL_EP "/%s/dev/pts", shortname);
    do_umount(path);

    snprintf(path, MAX_PATH_LEN_16,   JAIL_EP "/%s/dev/shm", shortname);
    do_umount(path);

    snprintf(path, MAX_PATH_LEN_16,   JAIL_EP "/%s/dev", shortname);
    do_umount(path);

    snprintf(path, MAX_PATH_LEN_16,   JAIL_EP "/%s/proc", shortname);
    do_umount(path);

    f = strtok_r(in->bind_ro, " ", &saveptr);
    while(f != NULL)
    {
        int cpt=0;
        while (f[cpt]!='/' && f[cpt]!=0 ) cpt++;
        snprintf(f_path, MAX_PATH_LEN_16, JAIL_EP "/%s%s", shortname, &f[cpt]);
        do_umount(f_path);
        f = strtok_r(NULL, " ", &saveptr);
    }

    f = strtok_r(in->bind_rw, " ", &saveptr);
    while(f != NULL)
    {
        int cpt=0;
        while (f[cpt]!='/' && f[cpt]!=0 ) cpt++;
        snprintf(f_path, MAX_PATH_LEN_16, JAIL_EP "/%s%s", shortname, &f[cpt]);
        do_umount(f_path);
        f = strtok_r(NULL, " ", &saveptr);
    }
}
/**
 * @brief
 *     Enter into the jail
 * @param in
 */
static void change_dir(data_t * const in)
{
    char *shortname = in->chpath;
    char  path[MAX_PATH_LEN_16];
    ENTER();

    snprintf(path, MAX_PATH_LEN_16,   JAIL_EP "/%s", shortname);

    /* chroot EP shall not be modified */
    chmod(path, 0555);

    if (0 != chdir(path) )
    {
        DIE("Cannot Change dir");
    }
    LOG(LOG_DEBUG, "chroot %s\n", path);
    if (0!= chroot(path) )
    {
        DIE("Cannot Change Root");
    }
    EXIT();
}


/**
 * @brief
 *    copy files instead of binding the directory
 * @param in
 */
static void copy_f(data_t *in)
{
    char *shortname = in->chpath;
    char  f_path[MAX_PATH_LEN_16];
    char *f = NULL;
    int inp, out;
    struct stat fileinfo = {0};
    char *saveptr = NULL;


    f = strtok_r(in->copy_f, " ", &saveptr);
    while(f != NULL)
    {
        int cpt=0;
        off_t bC = 0;
        char *dirp = NULL;
         while (f[cpt]!='/' && f[cpt]!=0 ) cpt++;
        snprintf(f_path, MAX_PATH_LEN_16, JAIL_EP "/%s%s", shortname, &f[cpt]);
        dirp = dirname(f_path);
        mkpath(dirp, 0755);

        if ((inp = open(&f[cpt], O_RDONLY)) == -1)
        {
            DIE("File to copy (%s) does not exist\n", &f[cpt]);
        }

        snprintf(f_path, MAX_PATH_LEN_16, JAIL_EP "/%s%s", shortname, &f[cpt]);
        if ((out = open(f_path, O_RDWR | O_CREAT, 0644)) == -1)
        {
            close(inp);
            DIE("Copy create destination %s\n", f_path);
        }

        stat(&f[cpt], &fileinfo);
        LOG(LOG_DEBUG, "copy File %s in %s (%ld)\n", &f[cpt], f_path,  fileinfo.st_size);
        sendfile(out, inp, &bC, fileinfo.st_size);
        fchmod(out, fileinfo.st_mode);

        close(inp);
        close(out);
        f = strtok_r(NULL, " ", &saveptr);
    }
}


/**
 * @brief
 *    copy the requested binary
 *    !!!! binary shall an not mount directory !!!
 *
 *    It allows
 *    * to run it into the jail and
 *    * to updated it on the root file system while running into the jail
 *       New binary will be take into account at jail restart
 * @param in
 */

static void copy_b(data_t *in)
{
    char *shortname = in->chpath;
    char  f_path[MAX_PATH_LEN_16];
    char  f_sig[MAX_PATH_LEN_16];
    char *saveptr = NULL;
    char *f = NULL;
    int inp, out;
    struct stat fileinfo = {0};
    /* only one binary autorised */
    f = strtok_r(in->name, " ", &saveptr);
    if (f != NULL)
    {
        int cpt=0;
        off_t bC = 0;
        char *dirp = NULL;
        while (f[cpt]!='/' && f[cpt]!=0 ) cpt++;
        snprintf(f_path, MAX_PATH_LEN_16, JAIL_EP "/%s%s", shortname, &f[cpt]);
        snprintf(f_sig, MAX_PATH_LEN_16, "%s.sig", f);
        dirp = dirname(f_path);
        mkpath(dirp, 0755);

        if ((inp = open(&f[cpt], O_RDONLY)) == -1)
        {
            DIE("File to copy (%s) does not exist\n", &f[cpt]);
        }

        snprintf(f_path, MAX_PATH_LEN_16, JAIL_EP "/%s%s", shortname, &f[cpt]);
        if ((out = open(f_path, O_RDWR | O_CREAT, 0644)) == -1)
        {
            close(inp);
            DIE("Copy create destination %s\n", f_path);
        }
        fchmod(out, 0755);
        stat(&f[cpt], &fileinfo);
        LOG(LOG_DEBUG, "copy File %s in %s (%ld)\n", &f[cpt], f_path,  fileinfo.st_size);
        sendfile(out, inp, &bC, fileinfo.st_size);
        LOG(LOG_DEBUG, "Done \n");
        close(inp);
        close(out);
    }
}
/**
 * @brief
 *
 * @param in
 */


/* let us make a recursive function to print the content of a given folder */

void copy_all(char * src, char *dest,data_t *  in)
{
    char  s_path[MAX_PATH_LEN_16];
    char  d_path[MAX_PATH_LEN_16];

    DIR * d = opendir(src); // open source
    struct dirent * dir;
    ENTER();
    if(d==NULL)
    {
      goto out;
    }
    while ((dir = readdir(d)) != NULL) // if we were able to read somehting from the directory*
    {
        snprintf(d_path, MAX_PATH_LEN_16, "/%s/%s", dest, dir->d_name);
        snprintf(s_path, MAX_PATH_LEN_16, "/%s/%s", src,  dir->d_name);

        if(dir->d_type != DT_DIR)
        {
            int inp, out;
            struct stat fileinfo = {0};
            off_t bC = 0;

            if ((inp = open(s_path, O_RDONLY)) == -1)
            {
                DIE("File to copy (%s) does not exist\n", s_path);
            }
            if ((out = open(d_path, O_RDWR | O_CREAT, 0644)) == -1)
            {
                close(inp);
                DIE("Cannot create destination %s\n", d_path);
            }
            /* stat*/
            stat(s_path, &fileinfo);

            LOG(LOG_DEBUG, "copy File %s in %s (%ld)\n", s_path, d_path,  fileinfo.st_size);
            sendfile(out, inp, &bC, fileinfo.st_size);

            close(inp);
            close(out);
            chmod(d_path, fileinfo.st_mode);
            if (-1 == chown(d_path, in->user->pw_uid, in->grp->gr_gid))
            {
                LOG(LOG_DEBUG, "error while chown");
            }
        }
        else if(dir -> d_type == DT_DIR && strcmp(dir->d_name,".")!=0 && strcmp(dir->d_name,"..")!=0 )
        {
            mkpath(d_path, 0755);
            copy_all(s_path, dest, in);
            chmod(d_path, 0555);
        }
    }
    closedir(d); // finally close the directory
out:
    EXIT();
}


static void copy_d(data_t *  in)
{
    char *shortname = in->chpath;
    char  d_path[MAX_PATH_LEN_16];
    char *d = NULL;
    char *saveptr = NULL;
    ENTER();
    d = strtok_r(in->copy_d, " ", &saveptr);
    while(d != NULL)
    {
        int cpt=0;
        while (d[cpt]!='/' && d[cpt]!=0 ) cpt++;
        LOG(LOG_DEBUG, "copy_d: %s", &d[cpt]);
        snprintf(d_path, MAX_PATH_LEN_16, JAIL_EP "/%s%s", shortname, &d[cpt]);
        mkpath(d_path, 0755);

        copy_all(&d[cpt], d_path, in);
        chmod(d_path, 0555);

        d = strtok_r(NULL, " ", &saveptr);
    }
    EXIT();
}

/**
 * @brief
 *
 * @param in
 */
static void delete_jail(data_t *  const in)
{
    char *shortname = in->chpath;
    char  path[MAX_PATH_LEN_16];
    ENTER();
    snprintf(path, MAX_PATH_LEN_16,   JAIL_EP "/%s", shortname);
    chmod(path, 0755);
    delete_dirs(path);
    EXIT();
}
/**
 * @brief
 *    Create (and enter into the jail)
 * @param in
 */
void create_jail(data_t * const in)
{
    ENTER();
    if (NULL == in)
    {
        DIE("parameter is NULL :-( ");
    }
    create_basic_skel(in);
    copy_d(in);
    copy_f(in);
    copy_b(in);
    mount_dirs(in);
    temp(in);
    change_dir(in);

    EXIT();
}


/**
 * @brief
 *    Destroy the jail
 *    !! this can only be done by the parent of the jail
 *    when the child is dead
 * @param in
 */
void destroy_jail(data_t * const in)
{
    exit(0);
    ENTER();

    if (NULL == in)
    {
        DIE("parameter is NULL :-( ");
    }

    umount_dirs(in);
    delete_jail(in);

    EXIT();
}

/*
 * Copyright 2010-2021 Erwan GAUTRON
 */
/**
 * @file parser.c
 * @brief
 * @author Erwan Gautron
 * @version 0.1
 */


#include <string.h>
#include <libxml/parser.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <expat.h>
#include <errno.h>
#include "jail.h"
#define CMP_SEC_LEN 10
/**
 * @brief
 *    Fill process name
 * @param pout
 * @param attr
 */
static void fill_process_name(data_t * const pout , const char **attr)
{
    ENTER();
    if ( 0 ==  strncmp("name", attr[0], CMP_SEC_LEN))
    {
        strncpy(&pout->name[0], attr[1], MAX_NAME_LEN);
    }

    EXIT();
}
/*
 * @brief
 *    Fill process name
 * @param pout
 * @param attr
 */
static void fill_process_chpath(data_t * const pout , const char **attr)
{
    ENTER();
    if ( 0 ==  strncmp("path", attr[0], CMP_SEC_LEN))
    {
        strncpy(&pout->chpath[0], attr[1], MAX_NAME_LEN);
    }

    EXIT();
}


/**
 * @brief
 *    Fill user and group field
 * @param pout
 * @param attr
 */
static void fill_user_group(data_t * const pout , const char **attr)
{
    int i;
    char data[MAX_ID_LEN];
    ENTER();
    for (i=0; attr[i]; i+=2)
    {
        if ( 0 ==  strncmp("username", attr[i], CMP_SEC_LEN))
        {
            strncpy(&data[0], attr[i+1], MAX_ID_LEN);
            if (NULL == pout->user)
                pout->user = getpwnam(data);
            if (NULL == pout->user)
            {
                DIE("User %s unknown %d", data, errno);
            }
        }
        if ( 0 ==  strncmp("group", attr[i], CMP_SEC_LEN))
        {
            strncpy(&data[0], attr[i+1], MAX_ID_LEN);
            if (NULL == pout->grp)
                pout->grp = getgrnam(data);
            if (NULL == pout->grp)
            {
                DIE("User %s unknown %d", data, errno);
            }
        }
    }
    EXIT();
}

/**
 * @brief
 *
 * @param str
 * @param base
 *
 * @return
 */
static long getValue(const char * str, int base)
{
    char *endptr = NULL;
    long val = 0;
    errno = 0; /* musl issue */

    val = strtol(str, &endptr, base);

    /* Check for various possible errors */
    //printf("%s %d %ld\n", str, errno, val);

    if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN))
                   || (errno != 0 && val == 0)) {
        DIE("strtol failure");
    }

    if (endptr == str) {
               DIE("not a number");
    }

    /* If we got here, strtol() successfully parsed a number */
    return val;
}

/**
 * @brief
 *    Fill limits parameters for the process
 * @param pout
 * @param attr
 */
static void fill_limits(data_t * const pout , const char **attr)
{
    int i;
    ENTER();

    for (i=0; attr[i]; i+=2)
    {

        if ( 0 ==  strncmp("as", attr[i], CMP_SEC_LEN))
        {
            pout->limits.as = (rlim_t) getValue(attr[i+1], 10);
            if (0 == pout->limits.as)
            {
                pout->limits.as = RLIM_INFINITY;
            }
        }
        else if ( 0 ==  strncmp("fsize", attr[i], CMP_SEC_LEN))
        {
            pout->limits.fsize =(rlim_t) getValue(attr[i+1], 10);
            if (0 == pout->limits.fsize)
            {
                pout->limits.fsize = RLIM_INFINITY;
            }
        }
        else if ( 0 ==  strncmp("stack", attr[i], CMP_SEC_LEN))
        {
            pout->limits.stack = (rlim_t) getValue(attr[i+1], 10);
            if (0 == pout->limits.stack)
            {
                pout->limits.stack = RLIM_INFINITY;
            }
        }
        else if ( 0 ==  strncmp("mq", attr[i], CMP_SEC_LEN))
        {
            pout->limits.mq = (rlim_t) getValue(attr[i+1], 10);
            if (0 == pout->limits.mq)
            {
                pout->limits.mq = RLIM_INFINITY;
            }
        }
        else if ( 0 ==  strncmp("data", attr[i], CMP_SEC_LEN))
        {
            pout->limits.mq = (rlim_t) getValue(attr[i+1], 10);
            if (0 == pout->limits.data)
            {
                pout->limits.data = RLIM_INFINITY;
            }
        }
        else if ( 0 ==  strncmp("nice", attr[i], CMP_SEC_LEN))
        {
            pout->limits.nice = (int) getValue(attr[i+1], 10);
        }
        else if ( 0 ==  strncmp("arena", attr[i], CMP_SEC_LEN))
        {
            pout->limits.arena = (int) getValue(attr[i+1], 10);
            if (8 < pout->limits.arena)
            {
                pout->limits.arena = 0;
            }
        }



    }
    EXIT();
}

/**
 * @brief
 *    Fill tree parameters for the process
 * @param pout
 * @param attr
 */
static void fill_home(data_t * const pout , const char **attr)
{
    ENTER();
    if ( 0 ==  strncmp("path", attr[0], CMP_SEC_LEN))
    {
        strncpy(&pout->home[0], attr[1], MAX_NAME_LEN);
    }

    EXIT();

}

/**
 * @brief
 *    Fill binding parameters for the process
 * @param pout
 * @param attr
 */
static void fill_bind_ro(data_t * const pout , const char **attr)
{
    ENTER();
    if ( 0 ==  strncmp("path", attr[0], CMP_SEC_LEN))
    {
        strncpy(&pout->bind_ro[0], attr[1], MAX_NAME_LEN);
    }

    EXIT();
}

/**
 * @brief
 *    Fill binding parameters for the process
 * @param pout
 * @param attr
 */
static void fill_copy_f(data_t * const pout , const char **attr)
{
    ENTER();
    if ( 0 ==  strncmp("path", attr[0], CMP_SEC_LEN))
    {
        strncpy(&pout->copy_f[0], attr[1], MAX_NAME_LEN);
    }

    EXIT();
}
/**
 * @brief
 *    Fill binding parameters for the process
 * @param pout
 * @param attr
 */
static void fill_copy_d(data_t * const pout , const char **attr)
{
    ENTER();
    if ( 0 ==  strncmp("path", attr[0], CMP_SEC_LEN))
    {
        strncpy(&pout->copy_d[0], attr[1], MAX_NAME_LEN);
    }

    EXIT();
}

/**
 * @brief
 *    Fill binding parameters for the process
 * @param pout
 * @param attr
 */
static void fill_bind_rw(data_t * const pout , const char **attr)
{
    ENTER();
    if ( 0 ==  strncmp("path", attr[0], CMP_SEC_LEN))
    {
        strncpy(&pout->bind_rw[0], attr[1], MAX_NAME_LEN);
    }

    EXIT();
}

/**
 * @brief
 *    Fill arguments for the process
 * @param pout
 * @param attr
 */
static void fill_caps(data_t * const pout , const char **attr)
{
    ENTER();
    if ( 0 ==  strncmp("name", attr[0], CMP_SEC_LEN))
    {
        strncpy(&pout->caps[0], attr[1], MAX_NAME_LEN);
    }

    EXIT();

}
/**
 * @brief
 *    Fill arguments for the process
 * @param pout
 * @param attr
 */
static void fill_args(data_t * const pout , const char **attr)
{
    ENTER();
    if ( 0 ==  strncmp("name", attr[0], CMP_SEC_LEN))
    {
        unsigned int i = 0;
        strncpy(&pout->args[0], attr[1], MAX_ARGS_LEN);
        /* remove non printable char of argument line ! */
        for (i=0; i<strlen(pout->args); i++)
        {
            if (pout->args[i]<32 || pout->args[i]>126)
            {
                pout->args[i]=32;
            }
        }
    }

    EXIT();

}

/**
 * @brief
 *    Fill retart for the process
 * @param pout
 * @param attr
 */
static void fill_restart(data_t * const pout , const char **attr)
{
    ENTER();
    if ( 0 ==  strncmp("value", attr[0], CMP_SEC_LEN))
    {
        pout->never_die =  attr[1][0] == 'y';
    }

    EXIT();

}

/**
 * @brief
 *    Fill retart for the process
 * @param pout
 * @param attr
 */
static void fill_reboot(data_t * const pout , const char **attr)
{
    ENTER();
    if ( 0 ==  strncmp("value", attr[0], CMP_SEC_LEN))
    {
        pout->reboot_on_die =  attr[1][0] == 'y';
    }

    EXIT();

}
/**
 * @brief
 *     Entry point for expat parser
 * @param data
 * @param el
 * @param attr
 */
static void start(void *data, const char *el, const char **attr)
{
    data_t * const pout = (data_t * const) data;
    if (NULL == pout)
    {
        DIE("");
    }

    if ( 0 ==  strncmp(el, "jail", 10) )
    {
        fill_process_name(data, attr);
    }
    else if ( 0 ==  strncmp(el, "user", 10) )
    {
        fill_user_group(data, attr);
    }
    else if ( 0 ==  strncmp(el, "rlimit", 10) )
    {
        fill_limits(data, attr);
    }
    else if ( 0 ==  strncmp(el, "caps", 10) )
    {
        fill_caps(data, attr);
    }
    else if ( 0 ==  strncmp(el, "args", 10) )
    {
        fill_args(data, attr);
    }
    else if ( 0 ==  strncmp(el, "bind_ro", 10) )
    {
        fill_bind_ro(data, attr);
    }
    else if ( 0 ==  strncmp(el, "bind_rw", 10) )
    {
        fill_bind_rw(data, attr);
    }
    else if ( 0 ==  strncmp(el, "copy_f", 10) )
    {
        fill_copy_f(data, attr);
    }
    else if ( 0 ==  strncmp(el, "copy_d", 10) )
    {
        fill_copy_d(data, attr);
    }
    else if ( 0 ==  strncmp(el, "home", 10) )
    {
        fill_home(data, attr);
    }
    else if (  0 ==  strncmp(el, "restart", 10) )
    {
        fill_restart(data,attr);
    }
    else if (  0 ==  strncmp(el, "reboot", 10) )
    {
        fill_reboot(data,attr);
    }
    else if (  0 ==  strncmp(el, "chpath", 10) )
    {
        fill_process_chpath(data,attr);
    }

    LOG(LOG_DEBUG,"\n");
}

/**
 * @brief
 *
 * @param data
 * @param el
 */
static void end(void *data, const char *el)
{
    data_t * const pout = (data_t * const) data;
    if (( NULL == pout) || (NULL == el))
    {
        DIE("");
    }
}


/**
 * @brief
 *
 * @param pout
 */
static int xml_parse(data_t * const pout, const char * const data)
{
    int retValue = 1;
    XML_Parser  parser  = NULL; /* expat lib */
    ENTER();
    if ( (NULL == pout) || (NULL == data) )
    {
        goto out;
    }
    parser = XML_ParserCreate(NULL);
    if (NULL == parser)
    {
        goto out;
    }

    XML_SetUserData(parser, pout),

    XML_SetElementHandler(parser, start, end);

    if (XML_STATUS_ERROR == XML_Parse(parser, data, (int) strlen(data), XML_TRUE) )
    {
        goto out;
    }

    retValue = 0;
out:
    if (NULL != parser)
    {
        XML_ParserFree(parser);
    }
    EXIT();
    return retValue;
}

/**
 * @brief
 *    Validate the xml structure
 *
 * @param filename
 */
static void validate(const char *filename)
{
    xmlParserCtxtPtr ctxt; /* the parser context */
    xmlDocPtr doc; /* the resulting document tree */
    ENTER();

    /* create a parser context */
    ctxt = xmlNewParserCtxt();
    if (ctxt == NULL)
    {
        DIE("No Memory \n");
    }
    /* parse the file, activating the DTD validation option */
    doc = xmlCtxtReadFile(ctxt, filename, NULL, XML_PARSE_DTDVALID);
    /* check if parsing suceeded */
    if (doc == NULL)
    {
        DIE("Failed to parse %s\n", filename);
    }
    else
    {
        /* check if validation suceeded */
        if (ctxt->valid == 0)
        {
            DIE("Failed to validate %s\n", filename);
        }
        /* free up the resulting document */
        xmlFreeDoc(doc);
    }
    /* free up the parser context */
    xmlFreeParserCtxt(ctxt);
    EXIT();
}




static void display(data_t * const pout)
{
    LOG(LOG_DEBUG,"Process name  : %s\n", pout->name);
    LOG(LOG_DEBUG,"Arguments     : %s\n", pout->args);
    LOG(LOG_DEBUG,"User          : %s\n", pout->user->pw_name);
    LOG(LOG_DEBUG,"Id/Group      : %d %d\n",
            pout->user->pw_uid,
            pout->user->pw_gid);
/*    LOG(LOG_DEBUG,"Limits        : as ," UINT64_FMT ", fsize %lu, stack %lu, mq = %lu\n",
            pout->limits.as,
            pout->limits.fsize,
            pout->limits.stack,
            pout->limits.mq);*/
    LOG(LOG_DEBUG,"home          : %s \n", pout->home);
    LOG(LOG_DEBUG,"dir to copy   : %s \n", pout->copy_d);
    LOG(LOG_DEBUG,"files to copy : %s \n", pout->copy_f);
    LOG(LOG_DEBUG,"bind in ro    : %s \n", pout->bind_ro);
    LOG(LOG_DEBUG,"bind in rw    : %s \n", pout->bind_rw);
    LOG(LOG_DEBUG,"capalibities  : %s \n", pout->caps);

    LOG(LOG_DEBUG,"\n");

}
/**
 * @brief
 *
 * @param in
 * @param out
 *
 * @return
 */
int parse(const char * const in, data_t * const out)
{
    FILE *fin = NULL;
    struct stat buf;
    char * xmldata = NULL;

    ENTER();

    if ((NULL == in) || (NULL == out))
    {
        DIE("Parameter error");
    }
    /* validate in in file is a correct xml file */
    validate(in);
    if (0 == stat(in, &buf))
    {
        /* allocate required memory */
        xmldata = calloc(1,(size_t) buf.st_size + 1u);
        if (NULL == xmldata)
        {
            DIE("No more memory \n");
        }
        /* Get the xml data */
        fin = fopen (in, "r");
        if (NULL == fin)
        {
            DIE("Cannot open file for reading");
        }

        if (0 == fread(xmldata, (size_t) buf.st_size, 1, fin))
        {
            fclose(fin);
            DIE("Error while reading file");
        }
        fclose(fin);
    }
    else
    {
        DIE("File %s not found \n", in);
    }
    /* now parse */
    if (0 != xml_parse(out, xmldata) )
    {
        /* error free before killing */
        free(xmldata);
        DIE("Parsing error");
    }
    /* free */
    free(xmldata);
    display(out);
    return 0;
}

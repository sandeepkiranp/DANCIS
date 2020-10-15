#include "dac.h"
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <sys/time.h>
#include <time.h>
#include <stdarg.h>
#include <pthread.h>

mclBnG1 g1;
mclBnG2 g2;
mclBnG1 system_attributes_g1[MAX_NUM_ATTRIBUTES];
mclBnG2 system_attributes_g2[MAX_NUM_ATTRIBUTES];
mclBnG1 Y1[TOTAL_ATTRIBUTES];
mclBnG2 Y2[TOTAL_ATTRIBUTES];
mclBnG2 root_public_key;
mclBnFr root_secret_key;

#if 0

typedef struct service_location
{
    char service[30];
    char ip[20];
    short int port;
    servicemode mode;
}service_location;

static int num_services = 0;
service_location *svc_loc = NULL;

void mylog(FILE *logfp, char *fmt, ...)
{
    va_list ap; /* points to each unnamed arg in turn */
    char *p, *sval;
    int ival;
    double dval;
    char buffer[200] = {0};
    int index = 0;

    struct timeval curTime;
    gettimeofday(&curTime, NULL);
    int milli = curTime.tv_usec / 1000;

    char tbuffer [80];
    strftime(tbuffer, 80, "%Y-%m-%d %H:%M:%S", localtime(&curTime.tv_sec));

    index = sprintf(buffer, "%s:%03d %d ", tbuffer, milli, (int)pthread_self());

    va_start(ap, fmt); /* make ap point to 1st unnamed arg */
    for (p = fmt; *p; p++)
    {
       if (*p != '%')
       {
          index += sprintf(buffer + index, "%c", *p);
          continue;
       }
       switch (*++p)
       {
          case 'd':
             ival = va_arg(ap, int);
             index += sprintf(buffer + index, "%d", ival);
             break;
         case 'f':
             dval = va_arg(ap, double);
             index += sprintf(buffer + index, "%f", dval);
             break;
         case 's':
             for (sval = va_arg(ap, char *); *sval; sval++) {
               index += sprintf(buffer + index, "%c", *sval);
             }
             break;
         default:
             index += sprintf(buffer + index, "%c", *p);
             break;
       }
    }
    va_end(ap); /* clean up when done */
    fprintf(logfp, "%s", buffer);
    fflush(logfp);
}
#endif

void write_element_to_file(FILE *fp, char *param, void *e, element_type t)
{
    char buf[1600] = {0};

    printf("Writing %s to param.txt...", param);

    switch (t)
    {
	case ELEMENT_FR:
		mclBnFr_getStr(buf, sizeof(buf),(mclBnFr *)e, 16);
		break;
	case ELEMENT_G2:
		mclBnG2_getStr(buf, sizeof(buf),(mclBnG2 *)e, 16);
		break;
	case ELEMENT_G1:
		mclBnG1_getStr(buf, sizeof(buf),(mclBnG1 *)e, 16);
		break;
	case ELEMENT_GT:
		mclBnGT_getStr(buf, sizeof(buf),(mclBnGT *)e, 16);
		break;
    }

    printf("%s = %s\n", param, buf);
    fprintf(fp, "%s = %s\n", param, buf);

    fflush(fp);
    //printf("Done\n");
}

void read_element_from_file(FILE *fp, char *param, void *e, element_type t, int skipline)
{
    char c[500] = {0};
    char str1[20];
    char str2[400] = {0};
    char buf[1600] = {0};

    fgets(c, sizeof(c), fp);

    if (skipline)
        return;
    sscanf(c, "%s = %[^\n]s", str1, str2);

    switch (t)
    {
        case ELEMENT_FR:
                mclBnFr_setStr((mclBnFr *)e, str2, strlen(str2),16);
                break;
        case ELEMENT_G2:
                mclBnG2_setStr((mclBnG2 *)e,  str2, strlen(str2), 16);
                break;
        case ELEMENT_G1:
                mclBnG1_setStr((mclBnG1 *)e,  str2, strlen(str2),16);
                break;
        case ELEMENT_GT:
                mclBnGT_setStr((mclBnGT *)e,  str2, strlen(str2), 16);
                break;
    }

    //printf("Done\n");
}
#if 0
int is_credential_valid(element_t user_cpk_r, element_t user_g2t_r)
{
    size_t len;
    size_t outlen;
    char *base64e;
    unsigned char *buffer;
    char *line = NULL;
    ssize_t read;
    int pos, ret = SUCCESS;
    int end, start=0, found=0;
    FILE *fp = NULL;
    element_t dummy, cpk_r, g2t_r, temp1, temp2;

    //element_printf("User data cpk_r %B, g2t_r %B\n", user_cpk_r,user_g2t_r);

    element_init_G1(cpk_r, pairing);
    element_init_G2(g2t_r, pairing);
    element_init_GT(temp1, pairing);
    element_init_GT(temp2, pairing);

    fp = fopen(REVOKED_FILE, "r");
    if (fp == NULL)
    {
        printf("Error opening %s\n", REVOKED_FILE);
        return FAILURE;
    }

    //skip first two lines
    read_element_from_file(fp, "dummy", dummy, 1);
    read_element_from_file(fp, "dummy", dummy, 1);

    fgetc(fp); //dummy read for "\n"

    //char c[500] = {0};
    while(!feof(fp))
    {

        //fgets(c, sizeof(c), fp);
	//printf("next line =====%s\n", c);

        read_element_from_file(fp, "CPK_r", cpk_r, 0); 
	//element_printf("CPK_r %B\n", cpk_r);
        read_element_from_file(fp, "G2T_r", g2t_r, 0); 
	//element_printf("g2t_r %B\n", g2t_r);
        pairing_apply(temp1, user_cpk_r, g2t_r,pairing);
	pairing_apply(temp2, cpk_r, user_g2t_r, pairing);
	//element_printf("temp1 %B, temp2 %B\n", temp1, temp2);

	if (!element_cmp(temp1, temp2)) {
	    ret = FAILURE;
	    break;
	}
        fgetc(fp); //dummy read for "\n"
	
    }

    fclose(fp);
    element_clear(cpk_r);
    element_clear(g2t_r);
    element_clear(temp1);
    element_clear(temp2);

    return ret;
}

servicemode convert_service_mode(char mode)
{
    switch(mode)
    {
	case 'C' : return CONSTRINED;
	case 'U' : return UNCONSTRAINED;
	default  : return UNCONSTRAINED;
    }
}

int read_services_location()
{
    char port[10];
    FILE *fp = fopen(SERVICES_FILE, "r");
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    int i = 0, j=0;
    char mode;

    if (fp == NULL)
    {
        printf("errno %d, str %s\n", errno, strerror(errno));
        return FAILURE;
    }

    fscanf(fp, "%d\n",&num_services);
    svc_loc = (service_location *) calloc(num_services , sizeof(service_location));

    while ((read = getline(&line, &len, fp)) != -1)
    {
        line[read - 1] = 0; //trim the new line character

        sscanf(line, "%s %s %s %c", svc_loc[i].service, svc_loc[i].ip, port, &mode);
	svc_loc[i].port = atoi(port);
	svc_loc[i].mode = convert_service_mode(mode);

        i++;
    }
    free(line);
    fclose(fp);

    return SUCCESS;
}

char *get_service_ip(char *service)
{
    int i;

    for(i = 0; i < num_services; i++)
    {
	if(!strcmp(svc_loc[i].service, service))
	{
            return svc_loc[i].ip;
	}
    }
    return NULL;
}

short int get_service_port(char *service)
{
    int i;

    for(i = 0; i < num_services; i++)
    {
        if(!strcmp(svc_loc[i].service, service))
        {
	    return svc_loc[i].port;
        }
    }
}

servicemode get_service_mode(char *service)
{
    int i;

    for(i = 0; i < num_services; i++)
    {
        if(!strcmp(svc_loc[i].service, service))
        {
            return svc_loc[i].mode;
        }
    }
}
#endif

#define SYSTEM_CURVE HOME_DIR "/root/a.param"

int initialize_system_params(FILE *logfp)
{
    int i;
    FILE *fp = NULL;
    char buf[1600];

    int ret = mclBn_init(MCL_BN254, MCLBN_COMPILED_TIME_VAR);
    if (ret != 0) {
            printf("err ret=%d\n", ret);
            return 1;
    }

    // check if HOME_DIR/root/params.txt is existing
    if( access( PARAM_FILE, F_OK ) != -1 )
    {
        //Read parameters from file
        char str[10];
        FILE *fp = fopen(PARAM_FILE, "r");

        fprintf(logfp, "root param file %s\n", PARAM_FILE);
        if (fp == NULL)
        {
            printf("errno %d, str %s\n", errno, strerror(errno));
            return FAILURE;
        }
        read_element_from_file(fp, "g1", (void *)&g1, ELEMENT_G1, 0);
        read_element_from_file(fp, "g2", (void *)&g2, ELEMENT_G2, 0);
	read_element_from_file(fp, "private_key", (void *)&root_secret_key, ELEMENT_FR, 0);
        read_element_from_file(fp, "public_key", (void *)&root_public_key, ELEMENT_G2, 0);

        for(i=0; i<MAX_NUM_ATTRIBUTES; i++)
        {
            sprintf(str, "att_g1[%d]", i);
            read_element_from_file(fp, str, (void *)&system_attributes_g1[i], ELEMENT_G1, 0);
            sprintf(str, "att_g2[%d]", i);
            read_element_from_file(fp, str, (void *)&system_attributes_g2[i], ELEMENT_G2, 0);
        }

        for(i=0; i<TOTAL_ATTRIBUTES; i++)
        {
            sprintf(str, "Y1[%d]", i);
            read_element_from_file(fp, str, (void *)&Y1[i], ELEMENT_G1, 0);
        }

        for(i=0; i<TOTAL_ATTRIBUTES; i++)
        {
            sprintf(str, "Y2[%d]", i);
            read_element_from_file(fp, str, (void *)&Y2[i], ELEMENT_G2, 0);
        }
        fclose(fp);
    }
    else
    {
        fprintf(logfp, "error reading %s, %s\n", PARAM_FILE, strerror(errno));
	return -1; //return -1 for root to generate system parameters
    }
    fprintf(logfp, "Done!\n");
    return SUCCESS;
}
#if 0
void setup_credentials_from_file(FILE *fp, credential_t *c)
{
    credential_element_t *ce;
    int i,j;
    int attcount = 0;

    c->cred = (credential_element_t **) malloc (c->levels * sizeof(credential_element_t *));
    for (i = 0; i < c->levels; i++)
    {
        ce = c->cred[i] = (credential_element_t *) malloc(sizeof(credential_element_t));

        if ((i + 1) % 2)
        {
            element_init_G2(ce->R, pairing);
            element_init_G1(ce->S, pairing);
        }
        else
        {
            element_init_G1(ce->R, pairing);
            element_init_G2(ce->S, pairing);
        }
        read_element_from_file(fp, "R", ce->R, 0);
        read_element_from_file(fp, "S", ce->S, 0);

        fscanf(fp,"num_attrs = %d\n", &attcount);

        ce->T = (element_t *) malloc((attcount) * sizeof(element_t));
	ce->ca = (credential_attributes *) malloc (sizeof(credential_attributes));
	ce->ca->attributes = (element_t *) malloc((attcount) * sizeof(element_t));
	ce->ca->num_of_attributes = attcount;

        for(j=0; j<ce->ca->num_of_attributes; j++)
        {
            if ((i + 1) % 2)
            {
                element_init_G1(ce->T[j], pairing);
                element_init_G1(ce->ca->attributes[j], pairing);
            }
            else
            {
                element_init_G2(ce->T[j], pairing);
                element_init_G2(ce->ca->attributes[j], pairing);
            }

            char s[10];
            sprintf(s, "T[%d]", j);
            read_element_from_file(fp, s, ce->T[j], 0);
            sprintf(s, "attr[%d]", j);
            read_element_from_file(fp, s, ce->ca->attributes[j], 0);
        }
    }
}

event_t get_event_from_string(char *evt)
{
    if(!strcmp(evt, "EVENT1"))
        return EVENT1;

    if(!strcmp(evt, "EVENT2"))
        return EVENT2;

    if(!strcmp(evt, "EVENT3"))
        return EVENT3;

    if(!strcmp(evt, "EVENT4"))
        return EVENT4;
}

int attribute_element_to_index(element_t e, int level)
{
    int i = 0;
    int found = 0;

    for(i = 0; i < MAX_NUM_ATTRIBUTES; i++)
    {
	if ((level+1) % 2)
	{
            found = !(element_cmp(e, system_attributes_g1[i]));
	}
	else
	{
            found = !(element_cmp(e, system_attributes_g2[i]));

	}
	if(found)
            return i;
    }
}

int load_policy(char *svc, service_policy *svcplcy)
{
    char str[100];
    char attrs[400];
    char c[200] = {0};
    int i, j;

    int num_policies;
    policy_t *policies;

    sprintf(str, "%s/services/%s/policy.txt", HOME_DIR, svc);

    FILE *fp = fopen(str, "r");
    if (fp == NULL)
    {
        return FAILURE;
    }

    fgets(attrs, sizeof(attrs), fp);

    fgets(c, sizeof(c), fp);
    num_policies = atoi(c);

    char * line = NULL;
    size_t len = 0;
    ssize_t read;

    policies = (policy_t *)calloc(num_policies * sizeof (policy_t), 1);

    for (i = 0; i < num_policies; i++)
    {
	//read the rule
        read = getline(&line, &len, fp);
        policies[i].rule = (char *)calloc(1, read);
        memcpy(policies[i].rule, line, read -1);

	//read the services to be invoked
        read = getline(&line, &len, fp);
	line[read - 1] = 0; //trim the new line character
	j = 0;

        char* token = strtok(line, " ");

        while (token != NULL)
        {
	    policies[i].services[j] = (char *)calloc(1, strlen(token));
	    memcpy(policies[i].services[j], token, strlen(token));
            token = strtok(NULL, " ");
	    j++;
        }
	policies[i].num_services = j;
        //skip empty line
	getline(&line, &len, fp);
    }

    free(line);

    svcplcy->num_policies = num_policies;
    svcplcy->policies = policies;
    strcpy(svcplcy->service, svc);

    fclose(fp);

    return SUCCESS;
}

void mysend(int sockfd, const char *msg, int length, int flags, char *sid, FILE *logfp)
{
    int n = send(sockfd, msg, length, flags);
/*    
    if(n < 0)
    {
	mylog(logfp, "send failed for socket %d, session %s\n", sockfd, sid);
	return;
    }
    mylog(logfp, "sent %d bytes for session %s\n", n, sid);
 */  
}
#endif

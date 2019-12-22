#include "dac.h"
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#define PARAM_FILE HOME_DIR "/root/params.txt"

element_t g1, g2;
pairing_t pairing;
element_t system_attributes_g1[MAX_NUM_ATTRIBUTES];
element_t system_attributes_g2[MAX_NUM_ATTRIBUTES];
element_t Y1[TOTAL_ATTRIBUTES];
element_t Y2[TOTAL_ATTRIBUTES];

void write_element_to_file(FILE *fp, char *param, element_t e)
{
    int len;
    size_t outlen;
    char *base64e;
    unsigned char *buffer;

    printf("Writing %s to param.txt...", param);

    element_printf("%s = %B\n", param, e);

    len = element_length_in_bytes(e);
    buffer =  (unsigned char *)malloc(len);

    element_to_bytes(buffer, e);
    base64e = base64_encode(buffer, len, &outlen);
    fprintf(fp, "%s = %s\n", param, base64e);

    free(base64e);
    free(buffer);
    fflush(fp);
    //printf("Done\n");
}

void read_element_from_file(FILE *fp, char *param, element_t e, int skipline)
{
    int len;
    size_t outlen;
    char *base64e;
    unsigned char *buffer;
    char c[200] = {0};
    char str1[20];
    char str2[200] = {0};

    //printf("Reading %s from param.txt...", param);

    fgets(c, sizeof(c), fp);

    if (skipline)
        return;

    sscanf(c, "%s = %s", str1, str2);
    //printf("%s--->%s\n", str1, str2);

    buffer = base64_decode(str2, strlen(str2), &outlen);
    element_from_bytes(e, buffer);
    //element_printf("%s = %B\n", param, e);
    free(buffer);

    //printf("Done\n");
}


int initialize_system_params()
{
    char param[1024];
    int i;
    element_t dummy;

    printf("Generating System Parameters...");

    int count = fread(param, 1, 1024, stdin);
    if (!count) pbc_die("input error");

    printf("Reading (%d) parameters \n%s \n",count, param);
    pairing_init_set_buf(pairing, param, count);

    element_init_G1(g1, pairing);
    element_init_G2(g2, pairing);

    for(i=0; i<TOTAL_ATTRIBUTES; i++)
    {
        element_init_G1(Y1[i], pairing);
    }

    for(i=0; i<TOTAL_ATTRIBUTES; i++)
    {
        element_init_G2(Y2[i], pairing);
    }

    for(i=0; i<MAX_NUM_ATTRIBUTES; i++)
    {
        element_init_G1(system_attributes_g1[i], pairing);
        element_init_G2(system_attributes_g2[i], pairing);
    }

    // check if HOME_DIR/root/params.txt is existing
    if( access( PARAM_FILE, F_OK ) != -1 )
    {
        //Read parameters from file
        char str[10];
        FILE *fp = fopen(PARAM_FILE, "r");

        printf("param file %s\n", PARAM_FILE);
        if (fp == NULL)
        {
            printf("errno %d, str %s\n", errno, strerror(errno));
            return FAILURE;
        }
        read_element_from_file(fp, "g1", g1, 0);
        read_element_from_file(fp, "g2", g2, 0);
        read_element_from_file(fp, "dummy", dummy, 1);
        read_element_from_file(fp, "dummy", dummy, 1);

        for(i=0; i<MAX_NUM_ATTRIBUTES; i++)
        {
            sprintf(str, "att_g1[%d]", i);
            read_element_from_file(fp, str, system_attributes_g1[i], 0);
            sprintf(str, "att_g2[%d]", i);
            read_element_from_file(fp, str, system_attributes_g2[i], 0);
        }

        for(i=0; i<TOTAL_ATTRIBUTES; i++)
        {
            sprintf(str, "Y1[%d]", i);
            read_element_from_file(fp, str, Y1[i], 0);
        }

        for(i=0; i<TOTAL_ATTRIBUTES; i++)
        {
            sprintf(str, "Y2[%d]", i);
            read_element_from_file(fp, str, Y2[i], 0);
        }
        fclose(fp);
    }
    else
    {
        printf("error reading %s, %s\n", PARAM_FILE, strerror(errno));
	return FAILURE;
    }
    printf("Done!\n");
    return SUCCESS;
}

void setup_credentials_from_file(FILE *fp, int attcount, credential_t *c)
{
    credential_element_t *ce;
    int i,j;

    c->cred = (credential_element_t **) malloc (c->levels * sizeof(credential_element_t *));
    for (i = 0; i < c->levels; i++)
    {
        ce = c->cred[i] = (credential_element_t *) malloc(sizeof(credential_element_t));
        ce->T = (element_t *) malloc((attcount + 2) * sizeof(element_t));
	ce->ca = (credential_attributes *) malloc (sizeof(credential_attributes));
	ce->ca->attributes = (element_t *) malloc((attcount + 2) * sizeof(element_t));
	ce->ca->num_of_attributes = attcount + 2;
    }

    for(i=0; i<c->levels; i++)
    {
        credential_element_t *ce = c->cred[i];
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
        }
    }

    for(i=0; i<c->levels; i++)
    {
        credential_element_t *ce = c->cred[i];
        read_element_from_file(fp, "R", ce->R, 0);
        read_element_from_file(fp, "S", ce->S, 0);
        for(j=0; j<ce->ca->num_of_attributes; j++)
        {
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
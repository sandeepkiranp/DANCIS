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

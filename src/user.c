#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include "dac.h"

#define USER_DIR HOME_DIR "/users"
#define PARAM_FILE HOME_DIR "/root/params.txt"

element_t user_private_key;
element_t user_public_key;

element_t g1, g2;
element_t root_secret_key;
element_t root_public_key;
pairing_t pairing;
element_t system_attributes_g1[MAX_NUM_ATTRIBUTES];
element_t system_attributes_g2[MAX_NUM_ATTRIBUTES];
element_t Y1[TOTAL_ATTRIBUTES];
element_t Y2[TOTAL_ATTRIBUTES];

credential_t ic;

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
    }
    printf("Done!\n");
}
int read_user_params(char *user)
{
    char c[200] = {0};
    char str[50] = {0};
    char luser[30] = {0};
    int levels;
    char attributes[100] = {0};
    credential_attributes ca;
    int a[50];
    int attcount = 0;
    int i = 0, j = 0;
    credential_element_t *ce;

    sprintf(str, "%s/%s/params.txt", USER_DIR, user);
    printf("Reading parameters from %s\n", str);

    FILE *fp = fopen(str, "r");
    if (fp == NULL)
    {
	printf("Error opening file %s\n", strerror(errno));
        return FAILURE;
    }

    fscanf(fp,"user = %s\n", luser);
    fscanf(fp,"levels = %d\n", &ic.levels);
    fscanf(fp,"attributes = %s\n", attributes);

    printf("user = %s, levels = %d, attributes = %s\n", luser, ic.levels, attributes);
    char* token = strtok(attributes, ",");

    while (token != NULL)
    {
        int attrindx = atoi(token + 1);
        a[attcount++] = attrindx;
        token = strtok(NULL, ",");
    }

    element_init_Zr(user_private_key, pairing);

    element_init_G1(user_public_key, pairing);

    read_element_from_file(fp, "private_key", user_private_key, 0);
    read_element_from_file(fp, "public_key", user_public_key, 0);

    ic.cred = (credential_element_t **) malloc (ic.levels * sizeof(credential_element_t *));
    for (i = 0; i < ic.levels; i++)
    {
        ce = ic.cred[i] = (credential_element_t *) malloc(sizeof(credential_element_t));
        ce->T = (element_t *) malloc((attcount + 2) * sizeof(element_t));
	ce->ca = (credential_attributes *) malloc (sizeof(credential_attributes));
	ce->ca->attributes = (element_t *) malloc((attcount + 2) * sizeof(element_t));
	ce->ca->num_of_attributes = attcount + 2;
    }

    for(i=0; i<ic.levels; i++)
    {
        credential_element_t *ce = ic.cred[i];
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

    for(i=0; i<ic.levels; i++)
    {
        credential_element_t *ce = ic.cred[i];
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
    
    fclose(fp);
    return SUCCESS;
}

int main(int argc, char *argv[])
{
    initialize_system_params();
    read_user_params(argv[1]);
    return 0;
}


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
char username[50];
char user_attributes[100];
int attcount = 0;
int attribute_indx_array[50];
int user_level;

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

    fscanf(fp,"user = %s\n", username);
    fscanf(fp,"levels = %d\n", &ic.levels);
    fscanf(fp,"attributes = %s\n", attributes);

    memcpy(user_attributes, attributes, strlen(attributes));
    printf("user = %s, levels = %d, attributes = %s ", 
		    username, ic.levels, attributes);

    user_level = ic.levels;
    char* token = strtok(attributes, ",");

    while (token != NULL)
    {
        int attrindx = atoi(token + 1);
        attribute_indx_array[attcount++] = attrindx;
        token = strtok(NULL, ",");
    }
    printf("attribute count %d\n", attcount);

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

initialize_credential(credential_t *src, credential_t *dst)
{
    dst->levels = src->levels;
    dst->cred = (credential_element_t **) malloc(dst->levels * sizeof(credential_element_t *));
    for(i = 0; i < dst->levels; i++)
    {
        ce = dst->cred[i] = (credential_element_t *)malloc(sizeof(credential_element_t));

	

    }



}

int delegate_credential(char *duser, char *attributes)
{
    // Get duser's public key
    char str[100] = {0};
    element_t dummy;
    int i=0, j=0;
    element_t duser_public_key;
    int a[50];
    char attr[100];
    credential_attributes *ca;
    credential_t dic;
    int ret;

    sprintf(str, "%s/%s", USER_DIR, duser);
    strcat(str, "/params.txt");
    FILE *fp = fopen(str, "r");

    //skip first 4 lines
    for (i=0; i<4; i++)
        read_element_from_file(fp, "dummy", dummy, 1);
    
    element_init_G1(duser_public_key, pairing);
    read_element_from_file(fp, "public_key", duser_public_key, 0);

    fclose(fp);

    if (strcasecmp(attributes, "ALL"))
        memcpy(attr, user_attributes, strlen(user_attributes));
    else
        memcpy(attr, attributes, strlen(attributes));

    char* token = strtok(attr, ",");

    i = 0;
    while (token != NULL)
    {
        int attrindx = atoi(token + 1);
        a[i++] = attrindx;
        token = strtok(NULL, ",");
    }
    ca = set_credential_attributes(user_level + 1, duser_public_key, i, a);

    memset(&dic, 0, sizeof(dic));
    //initialize dic with ic so that we can add the next level credential to dic
    initialize_credential(&dic,&ic);
    ret = issue_credential(user_private_key, user_public_key, ca, &dic); //called by issuer with its private and public key
    if (ret != SUCCESS)
    {
        printf("issue_credential Failed\n");
        exit(FAILURE);
    }

    // Write everything to the file
    sprintf(str, "%s/%s/%s.txt", USER_DIR, duser,username);
    fp = fopen(str, "w");
    fprintf(fp, "delegator = %s\n", username);
    fprintf(fp, "levels = %d\n",ic.levels + 1);
    fprintf(fp, "attributes = ");
    for(i=0; a[i] != 0; i++)
        fprintf(fp, "A%d,", a[i]);
    fprintf(fp, "\n");

    // write the delegated signture details
    for(i=0; i<dic.levels; i++)
    {
        credential_element_t *ce = dic.cred[i];
        write_element_to_file(fp, "R", ce->R);
        write_element_to_file(fp, "S", ce->S);
        for(j=0; j<ce->ca->num_of_attributes; j++)
        {
            char s[10];
            sprintf(s, "T[%d]", j);
            write_element_to_file(fp, s, ce->T[j]);
            sprintf(s, "attr[%d]", j);
            write_element_to_file(fp, s, ce->ca->attributes[j]);
        }
    }
    printf("Finished writing delegated credentials\n");
}

int main(int argc, char *argv[])
{
    initialize_system_params();
    read_user_params(argv[1]);

    //./user user1  DELEGATE user2 all|A1,A2
    if (argc > 2 && !strcmp(argv[2],"DELEGATE"))
    {
        delegate_credential(argv[3],argv[4]);
    }
    return 0;
}


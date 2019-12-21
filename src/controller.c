#include <stdio.h>
#include <string.h>
#include <errno.h>
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
int dusers_count = 0;

typedef struct delegted_credential
{
    char delegator[30];
    int num_dattrs;
    int  dattrs[50];
    credential_t dic;
}delegated_credential_t;
delegated_credential_t *dc;

int read_params()
{
    char c[200] = {0};
    char str[50] = {0};
    char luser[30] = {0};
    int levels;
    char attributes[100] = {0};
    credential_attributes ca;
    int i = 0, j = 0;
    credential_element_t *ce;

    sprintf(str, "%s/controller/params.txt", USER_DIR);
    printf("Reading parameters from %s\n", str);

    FILE *fp = fopen(str, "r");
    if (fp == NULL)
    {
        printf("Error opening file %s\n", strerror(errno));
        return FAILURE;
    }

    fscanf(fp,"user = %s\n", username);
    fscanf(fp,"levels = %d\n", &levels);
    fscanf(fp,"attributes = %s\n", attributes);

    memcpy(user_attributes, attributes, strlen(attributes));
    printf("user = %s, levels = %d, attributes = %s ",
                    username, levels, attributes);

    element_init_Zr(user_private_key, pairing);

    element_init_G1(user_public_key, pairing);

    read_element_from_file(fp, "private_key", user_private_key, 0);
    read_element_from_file(fp, "public_key", user_public_key, 0);

    fclose(fp);
    return SUCCESS;
}

int load_delegated_credentials(char *user)
{
    char c[200] = {0};
    char str[50] = {0};
    char luser[30] = {0};
    int levels;
    char attributes[100] = {0};
    credential_attributes ca;
    int i = 0, j = 0;
    credential_element_t *ce;
    char cmd[100];
    char dusers[100][30];
    char name[30] = {0};
    FILE *fp;
    int old_dusers_count = dusers_count;

    memset(dusers, 0, sizeof(dusers));
    //If user is NULL, load all delegated credentials in the directory
    //else load only that user's delegated credentials

    if (user == NULL)
    {
        sprintf(cmd, "ls %s/%s | grep -v params | sed -e 's/\\.txt$//'", USER_DIR, username);
	fp = popen(cmd, "r");
        while (fgets(name, sizeof(name), fp) != NULL)
	{
	    name[strlen(name) - 1] = 0;
            strcpy(dusers[dusers_count++], name);
	    memset(name, 0, sizeof(name));
        }
	pclose(fp);
    }
    else
    {
	//check if the we already have the delegated credential for this delegator
	for (i = 0; i < dusers_count; i++)
	{
            if(!strcmp(dc[i].delegator, user))
	    {
	        printf("Delegated credentials from %s are already loaded\n", user);
		return SUCCESS;
	    }
	}

        strcpy(dusers[old_dusers_count],user);
	dusers_count++;
    }

    dc = (delegated_credential_t *)realloc(dc, dusers_count * (sizeof(delegated_credential_t)));

    for(i = old_dusers_count; i<dusers_count; i++)
    {
	printf("\nLoading Delegated Credentials for %s\n", dusers[i]);
	memset(&dc[i], 0, sizeof(dc[i]));
        sprintf(str, "%s/%s/%s.txt", USER_DIR, username,dusers[i]);
        printf("Reading parameters from %s\n", str);

        fp = fopen(str, "r");
        if (fp == NULL)
        {
            printf("Error opening file %s\n", strerror(errno));
            return FAILURE;
        }

        fscanf(fp,"delegator = %s\n", dc[i].delegator);
        fscanf(fp,"levels = %d\n", &levels);
        fscanf(fp,"attributes = %s\n", attributes);

        printf("duser = %s, levels = %d, attributes = %s\n",
                        dc[i].delegator, levels, attributes);

        char* token = strtok(attributes, ",");

        while (token != NULL)
        {
            int attrindx = atoi(token + 1);
            dc[i].dattrs[dc[i].num_dattrs++] = attrindx;
            token = strtok(NULL, ",");
        }

	dc[i].dic.levels = levels;
        setup_credentials_from_file(fp,dc[i].num_dattrs,&dc[i].dic);
    }
    printf("Finished loading Delegated credentials for all users\n");

}

int main(int argc, char *argv[])
{
    initialize_system_params();
    read_params();

    load_delegated_credentials(NULL);
}

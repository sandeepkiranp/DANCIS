#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "dac.h"

#define USER_DIR HOME_DIR "/users"

#define PARAM_FILE HOME_DIR "/root/params.txt"

element_t g1, g2;
element_t root_secret_key;
element_t root_public_key;
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

    //printf("Writing %s to param.txt...", param);

    //element_printf("%s = %B\n", param, e);

    len = element_length_in_bytes(e);
    buffer =  (unsigned char *)malloc(len);

    element_to_bytes(buffer, e);
    base64e = base64_encode(buffer, len, &outlen);
    //fprintf(fp, "%s = %s\n", param, base64e);

    free(base64e);
    free(buffer);
    fflush(fp);
    //printf("Done\n");
}

void read_element_from_file(FILE *fp, char *param, element_t e)
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
    sscanf(c, "%s = %s", str1, str2);
    //printf("%s--->%s\n", str1, str2);

    buffer = base64_decode(str2, strlen(str2), &outlen);
    element_from_bytes(e, buffer);
    //element_printf("%s = %B\n", param, e);
    free(buffer);

    //printf("Done\n");
}

void dac_generate_parameters()
{
    char param[1024];
    int i;

    printf("Generating System Parameters...");

    int count = fread(param, 1, 1024, stdin);
    if (!count) pbc_die("input error");

    printf("Reading (%d) parameters \n%s \n",count, param);
    pairing_init_set_buf(pairing, param, count);

    element_init_G1(g1, pairing);
    element_init_G2(g2, pairing);

    //root key (g2^sk,sk)
    element_init_Zr(root_secret_key, pairing);
    element_init_G2(root_public_key, pairing);

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
            return;
        }
	read_element_from_file(fp, "g1", g1);
	read_element_from_file(fp, "g2", g2);
	read_element_from_file(fp, "private_key", root_secret_key);
	read_element_from_file(fp, "public_key", root_public_key);

        for(i=0; i<MAX_NUM_ATTRIBUTES; i++)
        {
            sprintf(str, "att_g1[%d]", i);
            read_element_from_file(fp, str, system_attributes_g1[i]);
            sprintf(str, "att_g2[%d]", i);
            read_element_from_file(fp, str, system_attributes_g2[i]);
        }

        for(i=0; i<TOTAL_ATTRIBUTES; i++)
        {
            sprintf(str, "Y1[%d]", i);
            read_element_from_file(fp, str, Y1[i]);
        }

        for(i=0; i<TOTAL_ATTRIBUTES; i++)
        {
            sprintf(str, "Y2[%d]", i);
            read_element_from_file(fp, str, Y2[i]);
        }
    }
    else
    {
	char str[10];
        FILE *fp = fopen(PARAM_FILE, "w");

	printf("param file %s\n", PARAM_FILE);
	if (fp == NULL)
	{
            printf("errno %d, str %s\n", errno, strerror(errno));
	    return;
	}

        element_random(g1);
	write_element_to_file(fp, "g1", g1);
        element_random(g2);
	write_element_to_file(fp, "g2", g2);

        element_random(root_secret_key);
	write_element_to_file(fp, "private_key", root_secret_key);
        element_pow_zn(root_public_key, g2, root_secret_key);
	write_element_to_file(fp, "public_key", root_public_key);

        //Generate system attributes
        for(i=0; i<MAX_NUM_ATTRIBUTES; i++)
        {
            element_random(system_attributes_g1[i]);
            element_random(system_attributes_g2[i]);
            sprintf(str, "att_g1[%d]", i);
            write_element_to_file(fp, str, system_attributes_g1[i]);
            sprintf(str, "att_g2[%d]", i);
            write_element_to_file(fp, str, system_attributes_g2[i]);
        }

        //Generate y1[n] and y2[n]
        for(i=0; i<TOTAL_ATTRIBUTES; i++)
        {
            element_random(Y1[i]);
	    sprintf(str, "Y1[%d]", i);
	    write_element_to_file(fp, str, Y1[i]);
        }

        for(i=0; i<TOTAL_ATTRIBUTES; i++)
        {
            element_random(Y2[i]);
	    sprintf(str, "Y2[%d]", i);
	    write_element_to_file(fp, str, Y2[i]);
        }
	fclose(fp);
    }

    printf("Done!\n\n");
}

void get_root_public_key(element_t x)
{
    element_init_same_as(x,root_public_key);
    element_set(x,root_public_key);
}

void get_root_secret_key(element_t x)
{
    element_init_same_as(x,root_secret_key);
    element_set(x,root_secret_key);
}


static int issue_user_credential(char *user, char *attributes)
{
    char str[30];

    sprintf(str, "%s/%s", USER_DIR, user);
    DIR* dir = opendir(str);
    if (dir)
    {
        /* User already exists. */
	printf("%s already issued credentials\n", user);
        closedir(dir);
	return FAILURE;
    }
    else if (ENOENT == errno) 
    {
	credential_attributes ca;
	int a[50] = {0};
        printf("Issuing credentials to %s with attributes %s\n", user, attributes);

        /* Directory does not exist. */
        element_t priv, pub;
	mkdir(str, 0766);

	// Generate Pub/Priv Key pair
        element_init_Zr(priv, pairing);
        element_random(priv);

        element_init_G1(pub, pairing);
        element_pow_zn(pub, g1, priv);

	// Generate Attributes
        // Returns first token 
        char* token = strtok(attributes, ","); 
  
        // Keep printing tokens while one of the 
        // delimiters present in str[]. 
        while (token != NULL) 
	{
	    int attrindx = atoi(token + 1);
	    a[i++] = attrindx;
            printf("attribute %s index %d\n", token, attrindx);
            token = strtok(NULL, ","); 
        }
	set_credential_attributes(1, pub, a, &ca)

	// Generate Groth Signature
	

	// Write everything to the file


	return SUCCESS;
    } 
    else 
    {
        /* opendir() failed for some other reason. */
	printf("opendir failed! %s\n", strerror(errno));
	return FAILURE;
    }

}

int main(int argc, char *argv[])
{
    credential_attributes ca;
    credential_t ic;
    element_t x,y;
    element_t priv, pub;
    token_t tok;
    int i;
    int ret = FAILURE;

    memset(&ic, 0, sizeof(ic));

    dac_generate_parameters();

    get_root_secret_key(x);
    get_root_public_key(y);

    if(argc < 2)
    {
        printf("Check Usage\n");
        exit(-1);
    }

    // ./root ISSUE user1 A1,A3,A4
    if (!strcasecmp(argv[1], "ISSUE"))
    {
        ret = issue_user_credential(argv[2], argv[3]);
    }
    
/*
    for(i=1; i<=5; i++)
    {
        generate_user_keys(i, priv, pub);

        set_credential_attributes(i, pub, &ca);

        ret = issue_credential(x, y, &ca, &ic); //called by issuer with its private key
	if (ret != SUCCESS)
	{
	    printf("issue_credential Failed\n");
            exit(FAILURE);
        }

        credential_set_private_key(priv, &ic); //called by issuee with its private key

        generate_attribute_token(&tok, &ic);
        verify_attribute_token(&tok);

        element_init_same_as(x, priv);
        element_set(x, priv);

        element_init_same_as(y, pub);
        element_set(y, pub);
    }
*/

    printf("Exit from main\n");
    return 0;
}

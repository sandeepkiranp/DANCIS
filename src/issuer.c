#include "dac.h"
#include <unistd.h>
#include <errno.h>
#include <string.h>

#define PARAM_FILE HOME_DIR "/root/params.txt"

element_t g1, g2;
element_t root_secret_key;
element_t root_public_key;
pairing_t pairing;
element_t Y1[n+2]; //cpk(i-1) + credential hash + n attributes = n+2 attrbutes
element_t Y2[n+2]; //cpk(i-1) + credential hash + n attributes = n+2 attrbutes

void write_element_to_file(FILE *fp, char *param, element_t e)
{
    int len;
    size_t outlen;
    char *base64e;
    unsigned char *buffer;

    printf("Writing %s to param.txt...", param);

    //element_printf("%s = %B\n", param, e);

    len = element_length_in_bytes(e);
    buffer =  (unsigned char *)malloc(len);

    element_to_bytes(buffer, e);
    base64e = base64_encode(buffer, len, &outlen);
    fprintf(fp, "%s = %s\n", param, base64e); 

    free(base64e);
    free(buffer);
    fflush(fp);
    printf("Done\n");
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

    printf("Reading %s from param.txt...", param);

    //fscanf(fp,"%[^\n]", c);
    fgets(c, sizeof(c), fp);
    sscanf(c, "%s = %s", str1, str2);
    printf("%s--->%s\n", str1, str2);

    buffer = base64_decode(str2, strlen(str2), &outlen);
    element_from_bytes(e, buffer);
    //element_printf("%s = %B\n", param, e);
    free(buffer);

    printf("Done\n");
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

    for(i=0; i<n+2; i++)
    {
        element_init_G1(Y1[i], pairing);
    }

    for(i=0; i<n+2; i++)
    {
        element_init_G2(Y2[i], pairing);
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
        for(i=0; i<n+2; i++)
        {
            sprintf(str, "Y1[%d]", i);
            read_element_from_file(fp, str, Y1[i]);
        }

        for(i=0; i<n+2; i++)
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

        //Generate y1[n] and y2[n]
        for(i=0; i<n+2; i++)
        {
            element_random(Y1[i]);
	    sprintf(str, "Y1[%d]", i);
	    write_element_to_file(fp, str, Y1[i]);
        }

        for(i=0; i<n+2; i++)
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

int issue_credential(element_t secret_key, element_t public_key, credential_attributes *ca, credential_t *ic)
{
    int i;
    credential_element_t *ce = (credential_element_t *)malloc(sizeof(credential_element_t));

    ic->levels++;
    if (ic->levels % 2)
    {
        groth_generate_signature_1(secret_key, ca, ce);
        if(groth_verify_signature_1(public_key, ca, ce) != SUCCESS)
            return FAILURE;
    }
    else
    {
        groth_generate_signature_2(secret_key, ca, ce);
        if(groth_verify_signature_2(public_key, ca, ce) != SUCCESS)
	    return FAILURE;
    }

    for(i=0; i<n+2; i++) // CPK + credential hash + n attributes
    {
        element_init_same_as(ce->attributes[i], ca->attributes[i]);
        element_set(ce->attributes[i], ca->attributes[i]);
    }
    ic->cred = (credential_element_t **) realloc(ic->cred, ic->levels * sizeof(credential_element_t *));
    ic->cred[ic->levels - 1] = ce;

    return SUCCESS;
}

void credential_set_private_key(element_t secret_key, credential_t *ic)
{
    element_init_same_as(ic->secret_key, secret_key);
    element_set(ic->secret_key, secret_key);
}

#include "dac.h"
#include <unistd.h>
#include <errno.h>
#include <string.h>

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

credential_attributes * set_credential_attributes(int level, element_t pub, int num_attr, int *attr)
{
    int i=0,j=0;
    char buffer[150] = {0};
    int size = 100;
    char hash[50] = {0};
    credential_attributes *ca;


    printf("Generating User Credential Attributes...");

    ca = (credential_attributes *) malloc(sizeof(credential_attributes));

    //total attrs = num_attr + 2 (one for cpk, one for cred hash)
    ca->attributes = (element_t *) malloc((num_attr + 2)* sizeof(element_t));

    for(i=0; i<num_attr + 2; i++)
    {
        if (level % 2)
	{
            element_init_G1(ca->attributes[i], pairing);
	}
        else
	{
            element_init_G2(ca->attributes[i], pairing);
	}
    }

    element_set(ca->attributes[0],pub);

    element_snprintf(buffer,size,"%B",ca->attributes[0]);
    SHA1(hash, buffer);

    for(i=2; i<num_attr + 2; i++)
    {
        element_random(ca->attributes[i]);
	if (level % 2)
	    element_set(ca->attributes[i], system_attributes_g1[attr[j++]]);
	else
	    element_set(ca->attributes[i], system_attributes_g2[attr[j++]]);

        element_snprintf(buffer,size,"%B",ca->attributes[i]);
        strcat(buffer, hash);
        SHA1(hash, buffer);
    }

    //attributes[1] is the hash of all the attributes including public key
    element_from_hash(ca->attributes[1], hash, strlen(hash));

    ca->num_of_attributes = num_attr + 2;

    printf("Done!\n\n");
    return ca;
}

int issue_credential(element_t secret_key, element_t public_key, credential_attributes *ca, credential_t *ic)
{
    int i;
    credential_element_t *ce = (credential_element_t *)malloc(sizeof(credential_element_t));

    ce->ca = ca;

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

    ic->cred = (credential_element_t **) realloc(ic->cred, ic->levels * sizeof(credential_element_t *));
    ic->cred[ic->levels - 1] = ce;

    return SUCCESS;
}

void credential_set_private_key(element_t secret_key, credential_t *ic)
{
    element_init_same_as(ic->secret_key, secret_key);
    element_set(ic->secret_key, secret_key);
}

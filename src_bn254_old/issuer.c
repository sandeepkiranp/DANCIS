#include "dac.h"
#include <unistd.h>
#include <errno.h>
#include <string.h>

credential_attributes * set_credential_attributes(int level, (void )pub, int num_attr, int *attr)
{
    int i=0,j=0;
    char buffer[150] = {0};
    int size = 100;
    char hash[50] = {0};
    credential_attributes *ca;


    printf("Generating User Credential Attributes...");

    ca = (credential_attributes *) malloc(sizeof(credential_attributes));


    for(i=0; i<num_attr + 1; i++)
    {
        if (level % 2)
	{
            //total attrs = num_attr + 1 (one for cpk)
            ca->attributes = (mclBnG1 *) malloc((num_attr + 1)* sizeof(mclBnG1));
	}
        else
	{
            ca->attributes = (mclBnG2 *) malloc((num_attr + 1)* sizeof(mclBnG2));
	}
    }

    ca->attributes[0] = (level % 2) ? (mclBnG1)pub : (mclBnG2) pub;

    for(i=1; i<num_attr + 1; i++)
    {
        element_random(ca->attributes[i]);
	if (level % 2)
	    ca->attributes[i] = system_attributes_g1[attr[j++]];
	else
	    ca->attributes[i] = system_attributes_g2[attr[j++]];
    }

    ca->num_of_attributes = num_attr + 1;

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

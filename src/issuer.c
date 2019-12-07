#include "dac.h"
#include <unistd.h>
#include <errno.h>
#include <string.h>

void set_credential_attributes(int level, element_t pub, int *attr, credential_attributes *ca)
{
    int i;
    char buffer[150] = {0};
    int size = 100;
    char hash[50] = {0};

    printf("Generating User Credential Attributes...");

    for(i=0; i<n+2; i++)
    {
        if (level % 2)
            element_init_G1(ca->attributes[i], pairing);
        else
            element_init_G2(ca->attributes[i], pairing);
    }

    element_set(ca->attributes[0],pub);

    element_snprintf(buffer,size,"%B",ca->attributes[0]);
    SHA1(hash, buffer);

    for(i=2; i<n+2; i++)
    {
        // TODO take a text attribute and convert it to a hash element
        element_random(ca->attributes[i]);
        element_snprintf(buffer,size,"%B",ca->attributes[i]);
        strcat(buffer, hash);
        SHA1(hash, buffer);
    }

    //attributes[1] is the hash of all the attributes including public key
    element_from_hash(ca->attributes[1], hash, strlen(hash));

    ca->num_of_attributes = n+2; //for now

    printf("Done!\n\n");
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

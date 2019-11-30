#include "dac.h"

element_t g1, g2;
static element_t root_secret_key;
element_t root_public_key;
pairing_t pairing;
element_t Y1[n+2]; //cpk(i-1) + credential hash + n attributes = n+2 attrbutes
element_t Y2[n+2]; //cpk(i-1) + credential hash + n attributes = n+2 attrbutes

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

    element_random(g1);
    element_random(g2);

    //root key (g2^sk,sk)
    element_init_Zr(root_secret_key, pairing);
    element_init_G2(root_public_key, pairing);

    element_random(root_secret_key);
    element_pow_zn(root_public_key, g2, root_secret_key);

    //Generate y1[n] and y2[n]
    for(i=0; i<n+2; i++)
    {
        element_init_G1(Y1[i], pairing);
        element_random(Y1[i]);
    }

    for(i=0; i<n+2; i++)
    {
        element_init_G2(Y2[i], pairing);
        element_random(Y2[i]);
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

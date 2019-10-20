#include <stdio.h>
#include "dac.h"

static element_t user_secret_key;
static element_t user_public_key;

void generate_user_keys()
{
    printf("Generating User Keys...");

    element_init_Zr(user_secret_key, pairing);
    element_init_G1(user_public_key, pairing);

    element_random(user_secret_key);
    element_pow_zn(user_public_key, g1, user_secret_key);
    
    printf("Done!\n\n");
}

void get_user_credential_attributes(credential_attributes *ca)
{
    int i;

    printf("Generating User Credential Attributes...");

    for(i=0; i<n+1; i++)
    {
        element_init_G1(ca->attributes[i], pairing);	    
    }

    element_set(ca->attributes[0],user_public_key);

    // user attributes from G1
    for(i=1; i<n+1; i++)
    {
        element_init_G1(ca->attributes[i], pairing);
	// TODO take a text attribute and convert it to a hash element
        element_random(ca->attributes[i]);
    }
    ca->num_of_attributes = n+1; //for now

    printf("Done!\n\n");
}

void generate_attribute_token(credential_attributes *ca, issued_credential *ic)
{
    int i;
    element_t rhosig, r1, s1, t1[n+1];
    element_t one_by_r, one;
    element_t rhos, rhot[n+1], rhoa[n], rhocsk;
    element_t com[n+2];

    printf("Generating Attribute token\n");

    printf("\t1. Generate Randomized signature...");

    //Randomize Signature

    element_init_Zr(rhosig, pairing);
    element_init_Zr(r1, pairing);
    element_init_Zr(s1, pairing);
    element_init_Zr(one_by_r, pairing);
    element_init_Zr(one, pairing);

    for(i=0; i<n+1; i++)
    {
        element_init_Zr(t1[i], pairing);
    }

    element_random(rhosig);

    element_pow_zn(r1, ic->R, rhosig);

    // 1/r
    element_set1(one);
    element_div(one_by_r, one, rhosig);

    element_pow_zn(s1, ic->S, one_by_r);

    for(i=0; i<n+1; i++)
    {
        element_pow_zn(t1[i], ic->T[i], one_by_r);
    }

    printf("Done!\n");

    printf("\t2. Compute com-values...");
    element_init_Zr(rhos, pairing);
    element_random(rhos);

    for(i=0; i<n+1; i++)
    {
        element_init_Zr(rhot[i], pairing);
	element_random(rhot[i]);
    }
    for(i=0; i<n; i++)
    {
        element_init_Zr(rhoa[i], pairing);
	element_random(rhoa[i]);
    }    

    element_init_Zr(rhocsk, pairing);
    element_random(rhocsk);

    for(i=0; i<n+2; i++) //for s, cpk, and n attributes
    {
        element_init_GT(com[i], pairing);
    }


    //compute e(g1,ic->R)
    element_t eg1R;
    element_t temp1;

    element_init_Zr(temp1, pairing);
    element_init_GT(eg1R, pairing);
    pairing_apply(eg1R, g1, ic->R, pairing);

    //com[0] = e(g1,ic->R)^(rhosig*rhos)
    element_mul(temp1, rhosig, rhos);
    element_pow_zn(com[0], eg1R, temp1);

}

void delegate_credential()
{


}

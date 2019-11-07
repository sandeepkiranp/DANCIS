#include <stdio.h>
#include <string.h>
#include "dac.h"

void generate_user_keys(int level, element_t priv, element_t pub)
{
    printf("Generating User Keys...");

    element_init_Zr(priv, pairing);
    element_random(priv);

    if (level % 2)
    {
        element_init_G1(pub, pairing);
        element_pow_zn(pub, g1, priv);
    }
    else
    {
        element_init_G2(pub, pairing);
        element_pow_zn(pub, g2, priv);
    }
    
    printf("Done!\n\n");
}

void set_credential_attributes(int level, element_t pub, credential_attributes *ca)
{
    int i;

    printf("Generating User Credential Attributes...");

    for(i=0; i<n+1; i++)
    {
	if (level % 2)
            element_init_G1(ca->attributes[i], pairing);	    
	else
            element_init_G2(ca->attributes[i], pairing);
    }

    element_set(ca->attributes[0],pub);

    // user attributes from G1
    for(i=1; i<n+1; i++)
    {
	// TODO take a text attribute and convert it to a hash element
        element_random(ca->attributes[i]);
    }
    ca->num_of_attributes = n+1; //for now

    printf("Done!\n\n");
}

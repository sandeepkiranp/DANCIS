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

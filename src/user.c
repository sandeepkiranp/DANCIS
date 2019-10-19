#include <stdio.h>
#include "dac.h"

static element_t user_secret_key;
static element_t user_public_key;

void generate_user_keys()
{
    element_init_Zr(user_secret_key, pairing);
    element_init_G2(user_public_key, pairing);

    element_random(user_secret_key);
    element_pow_zn(user_public_key, g1, user_secret_key);

}

void get_user_credential_attributes(credential_attributes *ca)
{
    int i;

    element_set(ca->attributes[0],user_public_key);

    // user attributes from G1
    for(i=1; i<n+1; i++)
    {
        element_init_G1(ca->attributes[i], pairing);
	// TODO take a text attribute and convert it to a hash element
        element_random(ca->attributes[i]);
    }
    ca->num_of_attributes = n+1; //for now
}

void delegate_credential()
{


}

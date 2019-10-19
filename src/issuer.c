#include "dac.h"

element_t g1, g2;
element_t root_secret_key
element_t root_public_key;
pairing_t pairing;
element_t y1[n+1]; //cpk(i-1) + n attributes = n+1 attrbutes
element_t y2[n+1]; //cpk(i-1) + n attributes = n+1 attrbutes

void dac_generate_parameters()
{
    char param[1024];

    printf("Generating System Parameters\n");

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
    element_pow_zn(root_public_key, g2, secret_key);

    //Generate y1[n] and y2[n]
    for(i=0; i<n+1; i++)
    {
        element_init_G1(y1[i], pairing);
        element_random(y1[i]);
    }

    for(i=0; i<n+1; i++)
    {
        element_init_G2(y2[i], pairing);
        element_random(y2[i]);
    }    

    printf("Generated System Parameters\n");

}

dac_issue_user_credential(credential_attributes ca*, issued_credential *ic)
{
    groth_generate_signature_1(root_secret_key, ca, ic);
    groth_verify_signature_1(root_public_key, ca, ic)

}

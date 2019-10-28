#include "dac.h"

element_t g1, g2;
static element_t root_secret_key;
element_t root_public_key;
pairing_t pairing;
element_t Y1[n+1]; //cpk(i-1) + n attributes = n+1 attrbutes
element_t Y2[n+1]; //cpk(i-1) + n attributes = n+1 attrbutes

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
    for(i=0; i<n+1; i++)
    {
        element_init_G1(Y1[i], pairing);
        element_random(Y1[i]);
    }

    for(i=0; i<n+1; i++)
    {
        element_init_G2(Y2[i], pairing);
        element_random(Y2[i]);
    }    

    printf("Done!\n\n");
}
/*
element_t get_root_issuer_public_key()
{
    return root_public_key;
}
*/

int dac_issue_user_credential(credential_attributes *ca, issued_credential *ic)
{
    groth_generate_signature_1(root_secret_key, ca, ic);
    groth_verify_signature_1(root_public_key, ca, ic);

}

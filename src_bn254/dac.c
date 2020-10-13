#include <string.h>
#include "dac.h"

#define n 3

element_t root_secret_key;
element_t root_public_key;
pairing_t pairing;
element_t g1, g2;
element_t system_attributes_g1[MAX_NUM_ATTRIBUTES];
element_t system_attributes_g2[MAX_NUM_ATTRIBUTES];
element_t Y1[TOTAL_ATTRIBUTES], Y2[TOTAL_ATTRIBUTES];

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

        for(i=0; i<MAX_NUM_ATTRIBUTES; i++)
        {
            element_init_G1(system_attributes_g1[i], pairing);
            element_init_G2(system_attributes_g2[i], pairing);
            element_random(system_attributes_g1[i]);
            element_random(system_attributes_g2[i]);
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

int main()
{
    credential_attributes *ca;
    credential_t ic;
    element_t x,y;
    element_t priv, pub;
    token_t tok;
    int i;
    int ret = FAILURE;

    memset(&ic, 0, sizeof(ic));

    dac_generate_parameters();

    get_root_secret_key(x);
    get_root_public_key(y);

    for(i=1; i<=2; i++)
    {
        generate_user_keys(i, priv, pub);
        int a[3] = {4,5,6};
	char rev1[] = {0,1,0,0,1};
	char rev2[] = {1,1,0,1,0};
	char *revealed[] = {rev1,rev2};

        ca = set_credential_attributes(i, pub, 3, a);

        ret = issue_credential(x, y, ca, &ic); //called by issuer with its private key
	if (ret != SUCCESS)
	{
	    printf("issue_credential Failed\n");
            exit(FAILURE);
        }

        credential_set_private_key(priv, &ic); //called by issuee with its private key

        generate_attribute_token(&tok, &ic, revealed);
        verify_attribute_token(&tok);

        element_init_same_as(x, priv);
        element_set(x, priv);

        element_init_same_as(y, pub);
        element_set(y, pub);
    }

    printf("Exit from main\n");
    return 0;
}

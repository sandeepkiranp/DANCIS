#include <string.h>
#include "dac.h"

int main()
{
    credential_attributes ca;
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

/*
    for(i=1; i<=5; i++)
    {
        generate_user_keys(i, priv, pub);

        set_credential_attributes(i, pub, &ca);

        ret = issue_credential(x, y, &ca, &ic); //called by issuer with its private key
	if (ret != SUCCESS)
	{
	    printf("issue_credential Failed\n");
            exit(FAILURE);
        }

        credential_set_private_key(priv, &ic); //called by issuee with its private key

        generate_attribute_token(&tok, &ic);
        verify_attribute_token(&tok);

        element_init_same_as(x, priv);
        element_set(x, priv);

        element_init_same_as(y, pub);
        element_set(y, pub);
    }
*/

    printf("Exit from main\n");
    return 0;
}

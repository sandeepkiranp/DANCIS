#include <string.h>
#include "dac.h"

int main()
{
    credential_attributes ca;
    credential_t ic;
    element_t x;
    element_t priv, pub;
    token_t tok;
    int i;

    memset(&ic, 0, sizeof(ic));

    dac_generate_parameters();

    get_root_secret_key(x);

    for(i=1; i<=1; i++)
    {
        generate_user_keys(i, priv, pub);

        set_credential_attributes(i, pub, &ca);

	if (i != 1)
	{
	    element_init_same_as(x, priv);
            element_set(x, priv);
	}
        issue_credential(x, &ca, &ic); //called by issuer with its private key

        credential_set_private_key(priv, &ic); //called by issuee with its private key

        generate_attribute_token(&tok, &ic);
        verify_attribute_token(&tok);
    }

    printf("Exit from main\n");
    return 0;
}

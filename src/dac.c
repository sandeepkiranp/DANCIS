#include "dac.h"

int main()
{
    credential_attributes ca;
    credential_t ic;
    element_t x;

    dac_generate_parameters();

    generate_user_keys();

    get_credential_attributes(&ca);

    get_root_secret_key(x);
    issue_credential(x, &ca, &ic); //called by issuer with its private key

    get_user_secret_key(x);
    credential_set_private_key(x, &ic); //called by issuee with its private key

    generate_attribute_token(&ic);
    printf("Exit from main\n");
    return 0;
}

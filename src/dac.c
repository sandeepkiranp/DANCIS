#include "dac.h"

int main()
{
    credential_attributes ca;
    issued_credential ic;

    dac_generate_parameters();

    generate_user_keys();

    get_user_credential_attributes(&ca);
    dac_issue_user_credential(&ca, &ic);

    generate_attribute_token(&ca, &ic);
    printf("Exit from main\n");
    return 0;
}

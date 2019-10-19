#include "dac.h"

void generate_attribute_token()
{



}

main()
{

    dac_generate_parameters();

    dac_issue_user_credential();

    groth_generate_parameters_2();

    groth_generate_signature_2();

    if (groth_verify_signature_2())
        return 1;

    groth_generate_parameters_1();

    groth_generate_signature_1();

    if (groth_verify_signature_1())
        return 1;

    printf("Exit from main\n");
    return 0;
}

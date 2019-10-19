#include <stdio.h>
#include <pbc/pbc.h>

#define SUCCESS 0
#define FAILURE 1
#define n 3

typedef struct attributes
{
    element_t attributes[n+1]; //attributes[0] represents the public key
    int num_of_attributes;
}credential_attributes;

typedef struct credential
{
    element_t R;
    element_t S;
    element_t T[n+1]; //CPK + n attributes
    int num_of_attributes;
}issued_credential;

extern element_t g1, g2;
extern element_t y1[n], y2[n];
extern pairing_t pairing;

extern dac_generate_parameters();

extern dac_issue_user_credential();

extern generate_user_keys();

extern void groth_generate_parameters_2();

extern void groth_generate_signature_2();

extern int groth_verify_signature_2();


extern void groth_generate_parameters_1();

extern void groth_generate_signature_1();

extern int groth_verify_signature_1();


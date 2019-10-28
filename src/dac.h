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
extern element_t Y1[n+1], Y2[n+1];
extern pairing_t pairing;
extern element_t root_public_key;

extern void dac_generate_parameters();

extern void get_user_credential_attributes(credential_attributes *ca);

extern int dac_issue_user_credential(credential_attributes *ca, issued_credential *ic);

extern void generate_user_keys();

extern void generate_attribute_token(credential_attributes *ca, issued_credential *ic);

extern void groth_generate_signature_1(element_t secret_key, credential_attributes *ca, issued_credential *ic);

extern int groth_verify_signature_1(element_t public_key, credential_attributes *ca, issued_credential *ic);


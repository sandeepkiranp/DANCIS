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
    element_t attributes[n+1]; //attributes[0] represents the public key
    int num_of_attributes;
    element_t secret_key;
}credential_t;

extern element_t g1, g2;
extern element_t Y1[n+1], Y2[n+1];
extern pairing_t pairing;
extern element_t root_public_key;

extern void dac_generate_parameters();

extern void get_credential_attributes(credential_attributes *ca);

extern int issue_credential(element_t key, credential_attributes *ca, credential_t *ic);

extern void generate_user_keys();

extern void get_user_secret_key(element_t x);
extern void get_root_secret_key(element_t x);

extern void credential_set_private_key(element_t secret_key, credential_t *ic);

extern void generate_attribute_token(credential_t *ic);

extern void groth_generate_signature_1(element_t secret_key, credential_attributes *ca, credential_t *ic);

extern int groth_verify_signature_1(element_t public_key, credential_attributes *ca, credential_t *ic);


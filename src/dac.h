#include <stdio.h>
#include <pbc/pbc.h>

#define SUCCESS 0
#define FAILURE 1
#define n 3

#define HOME_DIR "/root/dac"
#define MAX_NUM_ATTRIBUTES 50
#define TOTAL_ATTRIBUTES (MAX_NUM_ATTRIBUTES + 2) //cpk(i-1) + credential hash + MAX_NUM_ATTRIBUTES attributes

typedef struct attributes
{
    element_t *attributes;     //attributes[0] represents the public key
                               //attribute[1] represents the hashed credential
    int num_of_attributes;
}credential_attributes;

typedef struct credential_element
{
    element_t R;
    element_t S;
    element_t *T; //CPK + credential hash + n attributes
    credential_attributes *ca;
}credential_element_t;

typedef struct credential
{
    int levels;
    credential_element_t **cred; 
    element_t secret_key;
}credential_t;

typedef struct token_element
{
    element_t r1;
    element_t ress;
    element_t rescpk;
    element_t rescsk;
    element_t rest[n+2];
    element_t credhash;
    int revealed[n];
    element_t *attributes;
    element_t *resa;
}token_element_t;

typedef struct token
{
    int levels;
    token_element_t *te;
    element_t c;
    element_t rescsk;
}token_t;

extern element_t g1, g2;
extern element_t system_attributes_g1[MAX_NUM_ATTRIBUTES];
extern element_t system_attributes_g2[MAX_NUM_ATTRIBUTES];
extern element_t Y1[TOTAL_ATTRIBUTES], Y2[TOTAL_ATTRIBUTES];
extern pairing_t pairing;
extern element_t root_public_key;

extern void read_element_from_file(FILE *fp, char *param, element_t e, int skipline);

extern void write_element_to_file(FILE *fp, char *param, element_t e);

extern char *base64_encode(const unsigned char *data,
                    size_t input_length,
                    size_t *output_length) ;
extern unsigned char *base64_decode(const char *data,
                             size_t input_length,
                             size_t *output_length) ;

extern void dac_generate_parameters();

extern credential_attributes *set_credential_attributes(int level, element_t pub, int num_attr, int *attr);

extern int issue_credential(element_t secret_key, element_t public_key, credential_attributes *ca, credential_t *ic);

extern void generate_user_keys(int level, element_t priv, element_t pub);

extern void get_root_secret_key(element_t x);

extern void get_root_public_key(element_t x);

extern void credential_set_private_key(element_t secret_key, credential_t *ic);

extern void generate_attribute_token(token_t *tok, credential_t *ic);

extern void verify_attribute_token(token_t *tok);

extern void groth_generate_signature_1(element_t secret_key, credential_attributes *ca, credential_element_t *ic);

extern int groth_verify_signature_1(element_t public_key, credential_attributes *ca, credential_element_t *ic);

extern void groth_generate_signature_2(element_t secret_key, credential_attributes *ca, credential_element_t *ic);

extern int groth_verify_signature_2(element_t public_key, credential_attributes *ca, credential_element_t *ic);

extern void SHA1(char *hash, unsigned char * str1);

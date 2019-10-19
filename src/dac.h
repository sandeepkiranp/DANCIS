#include <stdio.h>
#include <pbc/pbc.h>

#define SUCCESS 0
#define FAILURE 1
#define n 3

extern int g1_g2_initialized;

extern element_t g1, g2, h;
extern element_t y[n];
extern element_t public_key, secret_key;
extern pairing_t pairing;

extern void groth_generate_parameters_2();

extern void groth_generate_signature_2();

extern int groth_verify_signature_2();


extern void groth_generate_parameters_1();

extern void groth_generate_signature_1();

extern int groth_verify_signature_1();


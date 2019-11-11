#include "dac.h"

/*
void groth_generate_parameters()
{
    if (g1_g2_initialized)
        return;

    printf("Generating System Parameters\n");

    element_init_G1(g1, pairing);
    element_init_G2(g2, pairing);

    element_random(g1);
    element_random(g2);

    g1_g2_initialized = 1;
    printf("Generated System Parameters\n");

}
void groth_generate_parameters_2()
{
    int i;

    groth_generate_parameters();
    printf("Generating Groth2 Parameters\n");

    for(i=0; i<n; i++)
    {
        element_init_G2(y[i], pairing);
        element_random(y[i]);
    }

    element_init_Zr(secret_key, pairing);
    element_random(secret_key);

    //pk = g1^sk
    element_init_G1(public_key, pairing);
    element_pow_zn(public_key, g1, secret_key);
}

*/

void groth_generate_signature_2(element_t secret_key, credential_attributes *ca, credential_element_t *ic)
{
    int i;
    element_t r;
    element_t one_by_r, one;

    printf("Generating Groth2 Signature\n");	

    element_init_Zr(r, pairing);

    element_init_G1(ic->R, pairing);
    element_init_G2(ic->S, pairing);

    for(i=0; i<n+1; i++)
        element_init_G2(ic->T[i], pairing);

    element_init_Zr(one_by_r, pairing);
    element_init_Zr(one, pairing);

    //R = g1^r
    element_random(r);
    element_pow_zn(ic->R, g1, r);

    //S = y1 * g2^sk
    element_pow_zn(ic->S, g2, secret_key);
    element_mul(ic->S, Y2[0], ic->S);

    // 1/r
    element_set1(one);
    element_div(one_by_r, one, r); 

    //S = S^(1/r). Therefore S = (y * g2^sk)^(1/r)
    element_pow_zn(ic->S, ic->S, one_by_r);

    //T = (y^sk * m)^(1/r)
    for(i=0; i<n+1; i++) //n+1 attributes including CPK
    {
        element_pow_zn(ic->T[i], Y2[i], secret_key);
        element_mul(ic->T[i], ic->T[i], ca->attributes[i]);
        element_pow_zn(ic->T[i], ic->T[i], one_by_r);
    }
    printf("Done!\n\n");
}

int groth_verify_signature_2(element_t public_key, credential_attributes *ca, credential_element_t *ic)
{
    element_t temp1, temp2, temp3, temp4;
    int i;

    element_init_GT(temp1, pairing);
    element_init_GT(temp2, pairing);
    element_init_GT(temp3, pairing);
    element_init_GT(temp4, pairing);

    printf("Verifying Groth2 Signature\n");	
    //Check if e(R, S) = e(g1 , y )e(V , g2 )
    
    //e(R,S)
    pairing_apply(temp1, ic->R, ic->S, pairing);

    //e(g1,y1)
    pairing_apply(temp2, g1, Y2[0], pairing);
    //e(pk,g2)
    pairing_apply(temp3, public_key, g2, pairing);
    // e(g1,y1) * e(pk,g2)
    element_mul(temp4, temp2, temp3);

    if (element_cmp(temp1, temp4))
    {
        printf("Failed! File %s line %d\n\n", __FILE__, __LINE__);
	return FAILURE;
    }

    for(i=0; i<n+1; i++) //cpk(i-1) + n attributes
    {
        //Check if e(R,Ti ) = e(V, yi )e(g1, mi )
        pairing_apply(temp1, ic->R, ic->T[i], pairing);
        //e(pk,y1)
        pairing_apply(temp2, public_key, Y2[i], pairing);
        //e(g1,m)
        pairing_apply(temp3, g1, ca->attributes[i], pairing);
        // e(V, yi )*e(g1, mi )
        element_mul(temp4, temp2, temp3);    

        if (element_cmp(temp1, temp4))
        {
            printf("Failed! File %s line %d\n\n", __FILE__, __LINE__);
            return FAILURE;
        }
    }

    printf("Done\n\n");
    return SUCCESS;
}

/*

void groth_generate_parameters_1()
{
    int i;

    groth_generate_parameters();
    printf("Generating Groth1 Parameters\n");	

    for(i=0; i<n; i++)
    {
        element_init_G1(y[i], pairing);
        element_random(y[i]);
    }

    element_init_Zr(secret_key, pairing);
    element_init_G2(public_key, pairing);

    element_random(secret_key);
    element_pow_zn(public_key, g2, secret_key);
}

*/

void groth_generate_signature_1(element_t secret_key, credential_attributes *ca, credential_element_t *ic)
{
    int i;
    element_t r;
    element_t one_by_r, one;

    printf("Generating Groth1 Signature...");	

    element_init_Zr(r, pairing);

    element_init_G2(ic->R, pairing);
    element_init_G1(ic->S, pairing);

    for(i=0; i<n+1; i++)
        element_init_G1(ic->T[i], pairing);

    element_init_Zr(one_by_r, pairing);
    element_init_Zr(one, pairing);

    //R = g2^r
    element_random(r);
    element_pow_zn(ic->R, g2, r);

    //S = y1 * g1^sk
    element_pow_zn(ic->S, g1, secret_key);
    element_mul(ic->S, Y1[0], ic->S);

    // 1/r
    element_set1(one);
    element_div(one_by_r, one, r); 

    //S = S^(1/r). Therefore S = (y * g2^sk)^(1/r)
    element_pow_zn(ic->S, ic->S, one_by_r);

    //T = (y^sk * m)^(1/r)
    for(i=0; i<n+1; i++) //n+1 attributes
    {
        element_pow_zn(ic->T[i], Y1[i], secret_key);
        element_mul(ic->T[i], ic->T[i], ca->attributes[i]);
        element_pow_zn(ic->T[i], ic->T[i], one_by_r);
    }
    printf("Done!\n\n");

}

int groth_verify_signature_1(element_t public_key, credential_attributes *ca, credential_element_t *ic)
{
    element_t temp1, temp2, temp3, temp4;
    int i;

    element_init_GT(temp1, pairing);
    element_init_GT(temp2, pairing);
    element_init_GT(temp3, pairing);
    element_init_GT(temp4, pairing);

    printf("Verifying Groth1 Signature...");	
    //Check if e(S, R) = e(y1, g2) * e(g1 , V )
    
    //e(S,R)
    pairing_apply(temp1, ic->S, ic->R, pairing);

    //e(y1, g2)
    pairing_apply(temp2, Y1[0], g2, pairing);
    //e(g1, pk)
    pairing_apply(temp3, g1, public_key, pairing);
    // e(y1,g2) * e(g1, pk)
    element_mul(temp4, temp2, temp3);

    if (element_cmp(temp1, temp4))
    {
        printf("Failed!\n\n");
	return FAILURE;
    }
    //element_printf("e(S,R) = %B\n", temp1);

    for(i=0; i<n+1; i++) //cpk(i-1) + n attributes
    {
        //Check if e(Ti,R ) = e(yi,V )e(mi,g2 )
        pairing_apply(temp1, ic->T[i], ic->R, pairing);
        //e(y1,pk)
        pairing_apply(temp2, Y1[i], public_key, pairing);
        //e(g1,mi)
        pairing_apply(temp3, ca->attributes[i], g2, pairing);
        // e(yi,V )*e(mi,g2)
        element_mul(temp4, temp2, temp3);    

        if (element_cmp(temp1, temp4))
        {
            printf("Failed!\n\n");
            return FAILURE;
        }
    }

    printf("Done!\n\n");
    return SUCCESS;
}

/*
int main()
{
    char param[1024];

    int count = fread(param, 1, 1024, stdin);
    if (!count) pbc_die("input error");

    printf("Reading (%d) parameters \n%s \n",count, param);
    pairing_init_set_buf(pairing, param, count);	

    
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
*/

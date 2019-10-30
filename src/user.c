#include <stdio.h>
#include <string.h>
#include "dac.h"

static element_t user_secret_key;
static element_t user_public_key;

void generate_user_keys()
{
    printf("Generating User Keys...");

    element_init_Zr(user_secret_key, pairing);
    element_init_G1(user_public_key, pairing);

    element_random(user_secret_key);
    element_pow_zn(user_public_key, g1, user_secret_key);
    
    printf("Done!\n\n");
}

void get_user_credential_attributes(credential_attributes *ca)
{
    int i;

    printf("Generating User Credential Attributes...");

    for(i=0; i<n+1; i++)
    {
        element_init_G1(ca->attributes[i], pairing);	    
    }

    element_set(ca->attributes[0],user_public_key);

    // user attributes from G1
    for(i=1; i<n+1; i++)
    {
        element_init_G1(ca->attributes[i], pairing);
	// TODO take a text attribute and convert it to a hash element
        element_random(ca->attributes[i]);
    }
    ca->num_of_attributes = n+1; //for now

    printf("Done!\n\n");
}

void generate_attribute_token(credential_attributes *ca, issued_credential *ic)
{
    int i, j;
    element_t rhosig, r1, s1, t1[n+1];
    element_t one_by_r, one;
    element_t rhos, rhot[n+1], rhoa[n], rhocsk;
    element_t com[n+2];

    printf("Generating Attribute token\n");

    printf("\t1. Generate Randomized signature...");

    //Randomize Signature

    element_init_Zr(rhosig, pairing);
    element_init_G2(r1, pairing);
    element_init_G1(s1, pairing);
    element_init_Zr(one_by_r, pairing);
    element_init_Zr(one, pairing);

    for(i=0; i<n+1; i++)
    {
        element_init_G1(t1[i], pairing);
    }

    element_random(rhosig);

    element_pow_zn(r1, ic->R, rhosig);

    // 1/r
    element_set1(one);
    element_div(one_by_r, one, rhosig);

    element_pow_zn(s1, ic->S, one_by_r);

    for(i=0; i<n+1; i++)
    {
        element_printf("ic->T[%d] = %B\n", i, ic->T[i]);
        element_pow_zn(t1[i], ic->T[i], one_by_r);
        element_printf("t1[%d] = %B\n", i, t1[i]);
    }

    printf("Done!\n");

    printf("\t2. Compute com-values...");
    element_init_Zr(rhos, pairing);
    element_random(rhos);

    for(i=0; i<n+1; i++)
    {
        element_init_Zr(rhot[i], pairing);
	element_random(rhot[i]);
    }
    for(i=0; i<n; i++)
    {
        element_init_Zr(rhoa[i], pairing);
	element_random(rhoa[i]);
    }    

    element_init_Zr(rhocsk, pairing);
    element_random(rhocsk);

    for(i=0; i<n+2; i++) //for s, cpk, and n attributes
    {
        element_init_GT(com[i], pairing);
    }


    //compute e(g1,ic->R)
    element_t eg1R;
    element_t eg1g2;
    element_t temp1, temp2, temp5;
    element_t negrhocsk;

    element_init_Zr(temp1, pairing);
    element_init_GT(eg1R, pairing);
    pairing_apply(eg1R, g1, ic->R, pairing);

    //com[0] = e(g1,ic->R)^(rhosig*rhos)
    element_mul(temp1, rhosig, rhos);
    element_pow_zn(com[0], eg1R, temp1);
    //element_printf("eg1R = %B\n", eg1R);


    //e(g1,ic->R)^(rhosig*rhot[0])
    element_mul(temp1, rhosig, rhot[0]);
    element_pow_zn(com[1], eg1R, temp1);

    //e(g1,g2)^(-rhocsk)
    element_init_GT(temp2, pairing);
    element_init_GT(eg1g2, pairing);
    pairing_apply(eg1g2, g1, g2, pairing);
    element_init_Zr(negrhocsk, pairing);
    element_neg(negrhocsk, rhocsk);
    element_pow_zn(temp2, eg1g2, negrhocsk);
    element_printf("rhocsk temp2 = %B\n", temp2);

    //com[1] = e(g1,ic->R)^(rhosig*rhot[0]) * e(g1,g2)^(-rhocsk)
    element_mul(com[1], com[1], temp2);
    element_printf("com[1] = %B\n", com[1]);

    //we have n attributes. Let's assume half of them are disclosed and rest half not.
    //TODO 0th attribute is the cpk
    for(i=0; i<n; i++)
    {
        element_mul(temp1, rhosig, rhot[i+1]);
	element_pow_zn(com[i+2], eg1R, temp1);
        if (i%2 == 0) //attribute revealed
	{
	    continue;
	}
	else //attribute not revealed
	{
	    element_t negrhoa;
            element_init_Zr(negrhoa, pairing);
            element_neg(negrhoa, rhoa[i]);
            element_pow_zn(temp2, eg1g2, negrhoa);
	    element_mul(com[i+2], com[i], temp2);
	}

    }
    printf("Done!\n");


    printf("\t3. Compute c...");
    element_t c;
    char buffer[4096] = {0};
    int size = 4096;

    //c = Hash(com[i] for i=0 to n+2)
    element_init_Zr(c, pairing);

    for(i=0; i<n+2; i++)
    {
        element_snprintf(buffer+(strlen(buffer)),size,"%B",com[i]);
    }
    element_from_hash(c, buffer, strlen(buffer));
    element_printf("c = %B\n", c);

    printf("Done!\n");

    printf("\t4. Compute res values...");
    element_t ress, resst;
    element_t rescsk;
    element_t rest[n+1];
    element_t resa[n/2];

    element_init_G1(ress, pairing);
    element_init_G1(temp5, pairing);
    element_init_Zr(rescsk, pairing);

    //ress = g1^rhos * s1^c
    element_pow_zn(ress, g1, rhos); 
    //element_printf("g1^rhos = %B\n", ress);
    element_pow_zn(temp5, s1, c);
    //element_printf("temp5 = %B\n", temp5);
    element_mul(ress, ress, temp5);

    //element_printf("ress = %B\n", ress);

    //rescsk = rhocsk + c * secret_key
    element_set(rescsk, rhocsk);
    element_mul(temp1, c, user_secret_key);
    element_add(rescsk, rescsk, temp1);

    element_printf("rescsk = %B\n", ress);

    for(i=0; i<n+1; i++)
    {
        element_init_G1(rest[i], pairing);
        element_pow_zn(rest[i], g1, rhot[i]);
        element_pow_zn(temp5, t1[i], c);
	element_mul(rest[i], rest[i], temp5);

	element_printf("rest[%d] = %B\n", i, rest[i]);
    }

    for(i=0,j=0; i<n; i++)
    {
        if (i%2 != 0)
        {
            element_init_Zr(resa[j], pairing);
            element_pow_zn(resa[j], g1, rhoa[i]);
            element_pow_zn(temp1, ca->attributes[i+1], c);
            element_mul(resa[j], resa[j], temp1);
	    j++;
	}
    }
    printf("Done!\n");

    printf("\t5. Testing if everything is fine...");

    element_t comt[n+2];
    element_t temp3, temp4;

    element_init_GT(temp3, pairing);
    element_init_GT(temp4, pairing);

    for(i=0; i<n+2; i++) //for s, cpk, and n attributes
    {
        element_init_GT(comt[i], pairing);
    }    
    //t(ress,r1) (e(y1[0],g2) * (e(g1,root_public_key))^(-c)
    pairing_apply(temp2, ress, r1, pairing);

    pairing_apply(temp3, Y1[0], g2, pairing);
    pairing_apply(temp4, g1, root_public_key, pairing);
    element_mul(temp3, temp3, temp4);
    //element_printf("temp2 = %B\ntemp3 = %B\n", temp2, temp3);
    element_neg(temp1, c);
    element_pow_zn(temp3, temp3, temp1); 
    element_mul(comt[0], temp2, temp3);

    if (element_cmp(comt[0], com[0]))
    {
        printf("Com values comparison Failed!\n\n");
	element_printf("com[0] = %B\ncomt[0] = %B\n", com[0], comt[0]); 
	return;
    }    

    //e(rest[0],r1) * e(g1,g2)^(-rescsk) * (e(y1[0],root_public_key))^(-c)
    pairing_apply(temp2, rest[0], r1, pairing);
    element_neg(temp1, rescsk);
    element_pow_zn(temp3, eg1g2, temp1);
    element_mul(temp2, temp2, temp3);

    pairing_apply(temp3, Y1[0], root_public_key, pairing);
    element_neg(temp1, c);
    element_pow_zn(temp4, temp3, temp1);

    element_mul(comt[1], temp2, temp4);
   
    if (element_cmp(comt[1], com[1]))
    {
        printf("Com values comparison Failed!\n\n");
        element_printf("com[1] = %B\ncomt[1] = %B\n", com[1], comt[1]);
        return;
    }

    printf("Hurray!\n");

}

void delegate_credential()
{


}

#include <string.h>
#include "dac.h"


void generate_attribute_token(credential_t *ic)
{
    int i, j, k;
    element_t rhosig, r1, s1, t1[n+1];
    element_t one_by_r, one;
    element_t rhos, rhot[n+1], rhoa[n], rhocsk;
    element_t com[n+2];
    int revealed[n];

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
    for(i=0; i<n; i++)
    {
        //com[i+2] = e(g1,r) ^ (rhosig * rhot[i+1])
        element_mul(temp1, rhosig, rhot[i+1]);
	element_pow_zn(com[i+2], eg1R, temp1);
        if (i%2 == 0) //attribute revealed
	{

	}
	else //attribute not revealed
	{
            //com[i+2] = e(g1,r) ^ (rhosig * rhot[i+1]) * e(g1,g2) ^ (-rhoa[i]) 
	    element_t negrhoa;
            element_init_Zr(negrhoa, pairing);
            element_neg(negrhoa, rhoa[i]);
            element_pow_zn(temp2, eg1g2, negrhoa);
	    element_mul(com[i+2], com[i+2], temp2);
	}
	element_printf("com[%d] = %B\n", i+2, com[i+2]);

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
    element_t *resa;
    element_t *attributes;

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
    element_mul(temp1, c, ic->secret_key);
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

    resa = (element_t *) malloc((n/2) * sizeof(element_t *));
    if (n%2 ==0)
	    attributes = (element_t *) malloc((n/2) * sizeof(element_t *));
    else
	    attributes = (element_t *) malloc(((n/2)+1) * sizeof(element_t *));

    for(i=0,j=0,k=0; i<n; i++) //attributes[0] represents CPK
    {
	revealed[i] = 1;
        if (i%2 != 0)
        {
            element_init_G1(resa[j], pairing);
            element_pow_zn(resa[j], g1, rhoa[i]);
            element_pow_zn(temp5, ic->attributes[i+1], c);
            element_mul(resa[j], resa[j], temp5);
	    revealed[i] = 0;
	    j++;
	}
	else
            element_set(attributes[k++],ic->attributes[i+1]);
    }

    printf("Done!\n");
}

void verify_attribute_token(element_t r1, element_t c, element_t ress, 
		            element_t rescsk, element_t rest[n+1],
			    int revealed[n],
		            element_t *attributes, element_t *resa)
{
    printf("\t5. Testing if everything is fine...");

    int i, j, k;
    element_t comt[n+2];
    element_t temp1, temp2, temp5;
    element_t temp3, temp4;
    element_t ct;
    element_t eg1g2;
    element_t one;

    element_init_GT(temp3, pairing);
    element_init_GT(temp4, pairing);
    element_init_Zr(one, pairing);    
    element_set1(one);
    element_init_GT(eg1g2, pairing);
    pairing_apply(eg1g2, g1, g2, pairing);    

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

    //e(rest[0],r1) * e(g1,g2)^(-rescsk) * (e(y1[0],root_public_key))^(-c)
    pairing_apply(temp2, rest[0], r1, pairing);
    element_neg(temp1, rescsk);
    element_pow_zn(temp3, eg1g2, temp1);
    element_mul(temp2, temp2, temp3);

    pairing_apply(temp3, Y1[0], root_public_key, pairing);
    element_neg(temp1, c);
    element_pow_zn(temp4, temp3, temp1);

    element_mul(comt[1], temp2, temp4);
   
    for(i=0,j=0,k=0; i<n; i++)
    {
        pairing_apply(comt[i+2], rest[i+1], r1, pairing);
        if(revealed[i])
	{
            //com[i+2] = e(rest[i+1], r1) * (e(attributes[i+1],g2) * e(y1[i+1],root_public_key)) ^ (-c)
	    pairing_apply(temp2, attributes[j++],g2, pairing);
	    pairing_apply(temp3, Y1[i+1],root_public_key, pairing);
	    element_mul(temp2, temp2, temp3);
	    element_neg(temp1, c);
	    element_pow_zn(temp2, temp2, temp1);

	    element_mul(comt[i+2], comt[i+2], temp2);

	}
	else
	{
            //com[i+2] = e(rest[i+1], r1) * (e(resa[i],g2)^(-1)) * (e(y1[i+1],root_public_key)) ^ (-c)
            pairing_apply(temp2, resa[k++],g2, pairing);
	    element_neg(temp1, one);
	    element_pow_zn(temp2, temp2, temp1);
            element_mul(comt[i+2], comt[i+2], temp2);

            pairing_apply(temp3, Y1[i+1],root_public_key, pairing);
            element_neg(temp1, c);
            element_pow_zn(temp3, temp3, temp1);
            element_mul(comt[i+2], comt[i+2], temp3);
	}
	element_printf("comt[%d] = %B\n", i+2,comt[i+2]);
    }

    printf("\t3. Compute c...");
    char buffer[4096] = {0};
    int size = 4096;

    //c = Hash(com[i] for i=0 to n+2)
    element_init_Zr(ct, pairing);

    for(i=0; i<n+2; i++)
    {
        element_snprintf(buffer+(strlen(buffer)),size,"%B",comt[i]);
    }
    element_from_hash(ct, buffer, strlen(buffer));

    if (element_cmp(c, ct))
    {
        printf("c values comparison Failed!\n\n");
	element_printf("c = %B\nct = %B\n", c, ct); 
	return;
    }
    printf("Hurray!\n");
}


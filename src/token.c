#include <string.h>
#include "dac.h"

void generate_attribute_token(token_t *tok, credential_t *ci, char **revealed)
{
    int i, j, k, l;
    element_t *r1, *rhosig, *s1, **t1;
    element_t one_by_r, one;
    element_t *rhos, **rhot, **rhoa, *rhocpk, rhocsk;
    element_t **com;
    credential_element_t *ic;
    int num_attrs;

    printf("Generating Attribute token\n");

    printf("\t1. Generate Randomized signature...");

    //Randomize Signature

    rhosig  = (element_t *)malloc(ci->levels * sizeof(element_t));
    r1      = (element_t *)malloc(ci->levels * sizeof(element_t));
    s1      = (element_t *)malloc(ci->levels * sizeof(element_t));
    t1      = (element_t **)malloc(ci->levels * sizeof(element_t *));
    com     = (element_t **)malloc(ci->levels * sizeof(element_t *));
    rhos    = (element_t *)malloc(ci->levels * sizeof(element_t));
    rhocpk  = (element_t *)malloc(ci->levels * sizeof(element_t));
    rhot    = (element_t **)malloc(ci->levels * sizeof(element_t *));
    rhoa    = (element_t **)malloc(ci->levels * sizeof(element_t *));

    for(i=0; i<ci->levels; i++)
    { 
        //num_attrs includes cpk + credhash + all attributes
	num_attrs = ci->cred[i]->ca->num_of_attributes;
        t1[i]   = (element_t *)malloc(num_attrs * sizeof(element_t));
        rhot[i] = (element_t *)malloc(num_attrs * sizeof(element_t));
        rhoa[i] = (element_t *)malloc((num_attrs - 2)   * sizeof(element_t));
        com[i]  = (element_t *)malloc((num_attrs + 1) * sizeof(element_t));
    }

    element_init_Zr(one_by_r, pairing);
    element_init_Zr(one, pairing);
    // 1/r
    element_set1(one);

    for (l=0; l< ci->levels; l++)
    {
        ic = ci->cred[l];
	num_attrs = ic->ca->num_of_attributes;

        element_init_Zr(rhosig[l], pairing);
        if ((l+1) % 2)
	{
            element_init_G2(r1[l], pairing);
            element_init_G1(s1[l], pairing);

            for(i=0; i<num_attrs; i++)
            {
                element_init_G1(t1[l][i], pairing);
            }
	}
	else
        {
            element_init_G1(r1[l], pairing);
            element_init_G2(s1[l], pairing);

            for(i=0; i<num_attrs; i++)
            {
                element_init_G2(t1[l][i], pairing);
            }
        }

        element_random(rhosig[l]);
        element_div(one_by_r, one, rhosig[l]);

        element_pow_zn(r1[l], ic->R, rhosig[l]);

        element_pow_zn(s1[l], ic->S, one_by_r);

        for(i=0; i<num_attrs; i++)
        {
            //element_printf("level - %d, ic->T[%d] = %B\n", l, i, ic->T[i]);
            element_pow_zn(t1[l][i], ic->T[i], one_by_r);
            //element_printf("t1[%d][%d] = %B\n", l, i, t1[l][i]);
        }
    }

    printf("Done!\n");

    printf("\t2. Compute com-values...");

    element_t eg1R;
    element_t eg1g2;
    element_t ey1g2;
    element_t temp1, temp2, temp5;
    element_t negrhocsk;
    element_t negrhocpk;
    element_t negrhoa;

    element_init_Zr(temp1, pairing);
    element_init_GT(eg1R, pairing);
    element_init_GT(temp2, pairing);
    element_init_GT(eg1g2, pairing);
    element_init_GT(ey1g2, pairing);
    element_init_Zr(negrhocsk, pairing);
    element_init_Zr(negrhocpk, pairing);
    element_init_Zr(negrhoa, pairing);

    element_init_Zr(rhocsk, pairing);
    element_random(rhocsk);

    pairing_apply(eg1g2, g1, g2, pairing);

    for (l=0; l< ci->levels; l++)
    {
        ic = ci->cred[l];
	num_attrs = ic->ca->num_of_attributes;

        element_init_Zr(rhos[l], pairing);
        element_random(rhos[l]);

        element_init_Zr(rhocpk[l], pairing);
        element_random(rhocpk[l]);

        for(i=0; i<num_attrs; i++)
        {
            element_init_Zr(rhot[l][i], pairing);
	    element_random(rhot[l][i]);
        }
	// total attrs - 2 (one for CPK, one for cred hash)
        for(i=0; i<num_attrs - 2; i++)
        {
            element_init_Zr(rhoa[l][i], pairing);
	    element_random(rhoa[l][i]);
        }    

        for(i=0; i<num_attrs + 1; i++) //for s, cpk, credential hash and n attributes
                                       // num_attrs includes cpk and credenial hash
        {
            element_init_GT(com[l][i], pairing);
        }

	if( (l+1) % 2)
        {
            //compute e(g1,ic->R)
            pairing_apply(eg1R, g1, ic->R, pairing);
        }
	else
        {
            //compute e(ic->R,g2)
            pairing_apply(eg1R, ic->R, g2, pairing);
        }

        //com[0] = e(g1,ic->R)^(rhosig*rhos)
        element_mul(temp1, rhosig[l], rhos[l]);
        element_pow_zn(com[l][0], eg1R, temp1);
	if(l != 0)
        {
            //com[0] = e(g1,ic->R)^(rhosig*rhos) * e(g1,g2) ^ (-rhocpk[l-1])
            element_neg(negrhocpk, rhocpk[l-1]);
	    element_pow_zn(temp2, eg1g2, negrhocpk);     
	    element_mul(com[l][0], com[l][0], temp2);
	}
        element_printf("com[%d][0] = %B\n", l, com[l][0]);

        //com[1] = e(g1,ic->R)^(rhosig*rhot[0])
        element_mul(temp1, rhosig[l], rhot[l][0]);
        element_pow_zn(com[l][1], eg1R, temp1);

	if (l == ci->levels - 1)
        {
            //com[1] = com[1] * e(g1,g2)^(-rhocsk)
            //e(g1,g2)^(-rhocsk)
            element_neg(negrhocsk, rhocsk);
            element_pow_zn(temp2, eg1g2, negrhocsk);
            element_mul(com[l][1], com[l][1], temp2);
        }
	else
        {
            //com[1] = com[1] * e(g1,g2) ^ (-rhocpk[l])
            element_neg(negrhocpk, rhocpk[l]);
            element_pow_zn(temp2, eg1g2, negrhocpk);
            element_mul(com[l][1], com[l][1], temp2);
        }

	if (l != 0)
	{
            //com[1] = com[1] * e(Y1[0],g2) ^ (-rhocpk[l-1])
            element_neg(negrhocpk, rhocpk[l-1]);
	    if((l+1) % 2)
                pairing_apply(ey1g2, Y1[0], g2, pairing);
	    else
                pairing_apply(ey1g2, g1, Y2[0], pairing);

            element_pow_zn(temp2, ey1g2, negrhocpk);
            element_mul(com[l][1], com[l][1], temp2);
	}

        element_printf("com[%d][1] = %B\n", l, com[l][1]);

	element_mul(temp1, rhosig[l], rhot[l][1]);
        element_pow_zn(com[l][2], eg1R, temp1);
        if (l != 0)
        {
            //com[2] = com[2] * e(Y1[1],g2) ^ (-rhocpk[l-1])
            element_neg(negrhocpk, rhocpk[l-1]);
            if((l+1) % 2)
                pairing_apply(ey1g2, Y1[1], g2, pairing);
            else
                pairing_apply(ey1g2, g1, Y2[1], pairing);

            element_pow_zn(temp2, ey1g2, negrhocpk);
            element_mul(com[l][2], com[l][2], temp2);
        }
        element_printf("com[%d][2] = %B\n", l, com[l][2]);

        for(i=0; i< num_attrs - 2; i++)
        {
            //com[i+3] = e(g1,r) ^ (rhosig * rhot[i+1])
            element_mul(temp1, rhosig[l], rhot[l][i+2]);
	    element_pow_zn(com[l][i+3], eg1R, temp1);
            if (revealed[l][i]) //attribute revealed
	    {

	    }
	    else //attribute not revealed
	    {
                //com[i+3] = e(g1,r) ^ (rhosig * rhot[i+1]) * e(g1,g2) ^ (-rhoa[i]) 
                element_neg(negrhoa, rhoa[l][i]);
                element_pow_zn(temp2, eg1g2, negrhoa);
	        element_mul(com[l][i+3], com[l][i+3], temp2);
	    }
	    if (l !=0)
	    {
		if ((l+1) % 2)
                    pairing_apply(ey1g2, Y1[i+2], g2, pairing);
		else
                    pairing_apply(ey1g2, g1, Y2[i+2], pairing);

		element_neg(negrhocpk, rhocpk[l-1]);
		element_pow_zn(temp2, ey1g2, negrhocpk);
		element_mul(com[l][i+3], com[l][i+3], temp2);

	    }
	    element_printf("com[%d][%d] = %B\n", l, i+3, com[l][i+3]);
        }
    }
    printf("Done!\n");


    printf("\t3. Compute c...");
    char buffer[150] = {0};
    int size = 100;
    char hash[50] = {0};

    //c = Hash(com[i] for i=0 to n+2)
    element_init_Zr(tok->c, pairing);

    for (l=0; l< ci->levels; l++)
    {
        for(i=0; i<ci->cred[l]->ca->num_of_attributes+1; i++)
        {
            element_snprintf(buffer,size,"%B",com[l][i]);
	    strcat(buffer, hash);
	    SHA1(hash, buffer);
	    //printf("Buffer = %s, Hash = %s\n", buffer, hash);
        }
    }
    element_from_hash(tok->c, hash, strlen(hash));
    element_printf("c = %B\n", tok->c);

    printf("Done!\n");

    printf("\t4. Compute res values...");

    token_element_t *te;
    tok->te = (token_element_t *)malloc(ci->levels * sizeof(token_element_t));
    tok->levels = ci->levels;

    for (l=0; l< ci->levels; l++)
    {
        ic = ci->cred[l];
	num_attrs = ic->ca->num_of_attributes;
        te = &tok->te[l];

	//set r'
	element_init_same_as(te->r1,r1[l]);
	element_set(te->r1,r1[l]);

        if((l+1) % 2)
        {
            element_init_G1(te->ress, pairing);
            element_init_G1(te->rescpk, pairing);
            element_init_G1(temp5, pairing);

            //ress = g1^rhos * s1^c
            element_pow_zn(te->ress, g1, rhos[l]); 
            //rescpk = g1^rhocpk * cpk^c
            element_pow_zn(te->rescpk, g1, rhocpk[l]); 
	}
	else
        {
            element_init_G2(te->ress, pairing);
            element_init_G2(te->rescpk, pairing);
            element_init_G2(temp5, pairing);

            //ress = g2^rhos * s1^c
            element_pow_zn(te->ress, g2, rhos[l]); 
            //rescpk = g2^rhocpk * cpk^c
            element_pow_zn(te->rescpk, g2, rhocpk[l]);
        }

        element_pow_zn(temp5, s1[l], tok->c);
        element_mul(te->ress, te->ress, temp5);
    
        //element_printf("ress[%d] = %B\n", l, te->ress);
    
	if (l == ci->levels - 1) 
	{
            //rescsk = rhocsk + c * secret_key
            element_init_Zr(te->rescsk, pairing);
            element_set(te->rescsk, rhocsk);
            element_mul(temp1, tok->c, ci->secret_key);
            element_add(te->rescsk, te->rescsk, temp1);
	}
	else
	{
            //cpk[l] ^ c
            element_pow_zn(temp5, ic->ca->attributes[0], tok->c);
            element_mul(te->rescpk, te->rescpk, temp5);
            //element_printf("rescpk[%d] = %B\n", l, te->rescpk);
	}

	// reveal credential hash
        element_init_same_as(te->credhash, ic->ca->attributes[1]);
        element_set(te->credhash, ic->ca->attributes[1]);

        for(i=0; i<num_attrs; i++)
        {
            if((l+1) % 2)
            {
                element_init_G1(te->rest[i], pairing);
                element_pow_zn(te->rest[i], g1, rhot[l][i]);
	    }
	    else
            {
                element_init_G2(te->rest[i], pairing);
                element_pow_zn(te->rest[i], g2, rhot[l][i]);
	    }
            element_pow_zn(temp5, t1[l][i], tok->c);
            element_mul(te->rest[i], te->rest[i], temp5);

       	    //element_printf("rest[%d][%d] = %B\n", l, i, te->rest[i]);
        }

	int num_revealed = 0;
        for(i=2; i<num_attrs; i++) //attributes[0] represents CPK
        {
            if(revealed[l][i])
                num_revealed++;
        }	    

    	te->attributes = (element_t *) malloc( num_revealed * sizeof(element_t));
        te->resa = (element_t *) malloc((num_attrs - num_revealed - 2) * sizeof(element_t)); 
	                                 //2 attributes have already been accounted for

        for(i=2,j=0,k=0; i<num_attrs; i++) //attributes[0] represents CPK, attr[1] represents cred hash
        {
            if (!revealed[l][i]) //not revealed
            {
                if ((l+1) % 2)
                {
                    element_init_G1(te->resa[j], pairing);
                    element_pow_zn(te->resa[j], g1, rhoa[l][i]);
                }
		else
                {
                    element_init_G2(te->resa[j], pairing);
                    element_pow_zn(te->resa[j], g2, rhoa[l][i]);
                }
                element_pow_zn(temp5, ic->ca->attributes[i], tok->c);
                element_mul(te->resa[j], te->resa[j], temp5);
       	        //element_printf("resa[%d][%d] = %B\n", l, j, te->resa[j]);
	        te->revealed[i] = 0;
       	        j++;
	    }
	    else //revealed
            {
                element_init_same_as(te->attributes[k],ic->ca->attributes[i]);
                element_set(te->attributes[k],ic->ca->attributes[i]);
    	        k++;
    	        te->revealed[i] = 1;
	    }
        }
    }

    printf("Done!\n");
}
/*
void verify_attribute_token(token_t *tk)
{
    printf("\t5. Testing if everything is fine...");

    int i, j, k, l;
    element_t **comt;
    element_t temp1, temp2, temp5;
    element_t temp3, temp4;
    element_t ct;
    element_t eg1g2;
    element_t one;
    token_element_t *tok;
    element_t prevrescpk;

    element_init_Zr(temp1, pairing);
    element_init_GT(temp2, pairing);
    element_init_GT(temp3, pairing);
    element_init_GT(temp4, pairing);
    element_init_G1(temp5, pairing);
    element_init_Zr(one, pairing);    
    element_init_GT(eg1g2, pairing);

    element_set1(one);
    pairing_apply(eg1g2, g1, g2, pairing);    

    comt = (element_t **)malloc(tk->levels * sizeof(element_t *));

    for(l=0; l<tk->levels; l++) 
    {
        tok = &tk->te[l];

	if (l != 0)
	{
            element_init_same_as(prevrescpk ,tk->te[l-1].rescpk);
            element_set(prevrescpk, tk->te[l-1].rescpk);
	}

        comt[l]  = (element_t *)malloc((N+3) * sizeof(element_t));
        for(i=0; i<N+3; i++) //for s, cpk, credential hash and n attributes
        {
            element_init_GT(comt[l][i], pairing);
        }

        if ((l+1) % 2)
        {
            //comt[0] = t(ress,r1) (e(y1[0],g2) * (e(g1,root_public_key))^(-c)
            pairing_apply(comt[l][0], tok->ress, tok->r1, pairing);
	    if(l != 0)
	    {
                //e(g1^(-1), rescpk[i-1])
		element_neg(temp1, one);
		pairing_apply(temp3, g1, prevrescpk, pairing);
		element_pow_zn(temp3, temp3, temp1);
		element_mul(comt[l][0], comt[l][0], temp3);
	    }

            pairing_apply(temp3, Y1[0], g2, pairing);
	    if(l == 0)
            {
                pairing_apply(temp4, g1, root_public_key, pairing);
                element_mul(temp3, temp3, temp4);
	    }
            element_neg(temp1, tk->c);
            element_pow_zn(temp3, temp3, temp1); 
            element_mul(comt[l][0], comt[l][0], temp3);
            element_printf("comt[%d][0] = %B\n", l, comt[l][0]);

            //comt[1] = e(rest[0],r1) * e(g1,g2)^(-rescsk) * (e(y1[0],root_public_key))^(-c)
            pairing_apply(comt[l][1], tok->rest[0], tok->r1, pairing);
            if(l == (tk->levels - 1))
            {
                element_neg(temp1, tok->rescsk);
                element_pow_zn(temp3, eg1g2, temp1);
                element_mul(comt[l][1], comt[l][1], temp3);
	    }
	    else
	    {
                //e(rescpk[i],g2^(-1))
                element_neg(temp1, one);
                pairing_apply(temp3, tok->rescpk, g2, pairing);
                element_pow_zn(temp3, temp3, temp1);
                element_mul(comt[l][1], comt[l][1], temp3);
	    }

            if(l == 0)
            {
                pairing_apply(temp3, Y1[0], root_public_key, pairing);
                element_neg(temp1, tk->c);
                element_pow_zn(temp3, temp3, temp1);
	        element_mul(comt[l][1], comt[l][1], temp3);
	    }
	    else
	    {
                //e(Y1[0],rescpk[l-1]) 
                pairing_apply(temp3, Y1[0], prevrescpk, pairing);
                element_neg(temp1, one);
                element_pow_zn(temp3, temp3, temp1);
                element_mul(comt[l][1], comt[l][1], temp3);
	    }

            element_printf("comt[%d][1] = %B\n", l, comt[l][1]);

           // compute comt[l][2]
            pairing_apply(comt[l][2], tok->rest[1], tok->r1, pairing);
	    if (l != 0)
	    {
                pairing_apply(temp3, Y1[1], prevrescpk, pairing);
                element_neg(temp1, one);
                element_pow_zn(temp3, temp3, temp1);
                element_mul(comt[l][2], comt[l][2], temp3);
	    }

	    pairing_apply(temp3, tok->credhash, g2, pairing);
            if(l == 0)
            {
                pairing_apply(temp4, Y1[1], root_public_key, pairing);
                element_mul(temp3, temp3, temp4);
            }
            element_neg(temp1, tk->c);
            element_pow_zn(temp3, temp3, temp1);

            element_mul(comt[l][2], comt[l][2], temp3);
            element_printf("comt[%d][2] = %B\n", l, comt[l][2]);
   
            for(i=0,j=0,k=0; i<N; i++)
            {
                pairing_apply(comt[l][i+3], tok->rest[i+2], tok->r1, pairing);
                if(tok->revealed[i])
         	{
                    //com[i+3] = e(rest[i+1], r1) * (e(attributes[i+2],g2) * e(y1[i+2],root_public_key)) ^ (-c)
    	            pairing_apply(temp2, tok->attributes[j++],g2, pairing);
		    if (l == 0)
                    {
                        pairing_apply(temp3, Y1[i+2],root_public_key, pairing);
    	                element_mul(temp2, temp2, temp3);
                    }
	            element_neg(temp1, tk->c);
	            element_pow_zn(temp2, temp2, temp1);

	            element_mul(comt[l][i+3], comt[l][i+3], temp2);
		    if (l != 0)
		    {
                        //e(Y1[0],rescpk[l-1]) 
                        pairing_apply(temp3, Y1[i+2], prevrescpk, pairing);
			element_neg(temp1, one);
                        element_pow_zn(temp3, temp3, temp1);
	                element_mul(comt[l][i+3], comt[l][i+3], temp3);
		    }
	        }
	        else
	        {
                    //com[i+3] = e(rest[i+1], r1) * (e(resa[i],g2)^(-1)) * (e(y1[i+2],root_public_key)) ^ (-c)
                    pairing_apply(temp2, tok->resa[k++],g2, pairing);
	            element_neg(temp1, one);
    	            element_pow_zn(temp2, temp2, temp1);
                    element_mul(comt[l][i+3], comt[l][i+3], temp2);
                    if (l == 0)
                    {
                        pairing_apply(temp3, Y1[i+2],root_public_key, pairing);
                        element_neg(temp1, tk->c);
                        element_pow_zn(temp3, temp3, temp1);
                        element_mul(comt[l][i+3], comt[l][i+3], temp3);
		    }
		    else
		    {
                        //e(Y1[0],rescpk[l-1])
                        pairing_apply(temp3, Y1[i+2], prevrescpk, pairing);
			element_neg(temp1, one);
                        element_pow_zn(temp3, temp3, temp1);
                        element_mul(comt[l][i+3], comt[l][i+3], temp3);
		    }
	        }
	        element_printf("comt[%d][%d] = %B\n", l, i+3,comt[l][i+3]);
            }
        }
	else
        {
            //comt[0] = t(r1,ress) (e(y1[0],g2) * (e(g1,root_public_key))^(-c)
            pairing_apply(comt[l][0], tok->r1, tok->ress, pairing);

            //e(rescpk[i-1], g2^(-1))
            element_neg(temp1, one);
            pairing_apply(temp3, prevrescpk, g2, pairing);
            element_pow_zn(temp3, temp3, temp1);
            element_mul(comt[l][0], comt[l][0], temp3);

            pairing_apply(temp3, g1, Y2[0], pairing);
            element_neg(temp1, tk->c);
            element_pow_zn(temp3, temp3, temp1); 
            element_mul(comt[l][0], comt[l][0], temp3);
            element_printf("comt[%d][0] = %B\n", l, comt[l][0]);

            //comt[1] = e(rest[0],r1) * e(g1,g2)^(-rescsk) * (e(y1[0],root_public_key))^(-c)
            pairing_apply(comt[l][1], tok->r1, tok->rest[0], pairing);

            //e(rescpk[l-1],Y2[0]) 
            pairing_apply(temp3, prevrescpk, Y2[0], pairing);
	    element_neg(temp1, one);
	    element_pow_zn(temp3, temp3, temp1);
            element_mul(comt[l][1], comt[l][1], temp3);

	    if(l == (tk->levels -1))
            {
                element_neg(temp1, tok->rescsk);
                element_pow_zn(temp3, eg1g2, temp1);
                element_mul(comt[l][1], comt[l][1], temp3);
	    }
	    else
	    {
                //e(g1, rescpk[i]i)^(-1))
                element_neg(temp1, one);
                pairing_apply(temp3, g1, tok->rescpk, pairing);
                element_pow_zn(temp3, temp3, temp1);
                element_mul(comt[l][1], comt[l][1], temp3);
	    }

            element_printf("comt[%d][1] = %B\n", l, comt[l][1]);

	    pairing_apply(comt[l][2], tok->r1, tok->rest[1], pairing);

	    pairing_apply(temp3, prevrescpk, Y2[1], pairing);
            element_neg(temp1, one);
            element_pow_zn(temp3, temp3, temp1);
            element_mul(comt[l][2], comt[l][2], temp3);

            pairing_apply(temp2, g1, tok->credhash, pairing);
            element_neg(temp1, tk->c);
            element_pow_zn(temp2, temp2, temp1);

            element_mul(comt[l][2], comt[l][2], temp2);
            element_printf("comt[%d][2] = %B\n", l, comt[l][2]);
   
            for(i=0,j=0,k=0; i<N; i++)
            {
                pairing_apply(comt[l][i+3], tok->r1, tok->rest[i+2], pairing);
                pairing_apply(temp3, prevrescpk, Y2[i+2], pairing);
		element_neg(temp1, one);
                element_pow_zn(temp3, temp3, temp1);
    	        element_mul(comt[l][i+3], comt[l][i+3], temp3);

                if(tok->revealed[i])
         	{
                    //com[i+3] = e(rest[i+1], r1) * (e(attributes[i+1],g2) * e(y1[i+1],root_public_key)) ^ (-c)
    	            pairing_apply(temp2, g1, tok->attributes[j++], pairing);
	            element_neg(temp1, tk->c);
	            element_pow_zn(temp2, temp2, temp1);

	            element_mul(comt[l][i+3], comt[l][i+3], temp2);

	        }
	        else
	        {
                    //com[i+3] = e(rest[i+1], r1) * (e(resa[i],g2)^(-1)) * (e(y1[i+1],root_public_key)) ^ (-c)
                    pairing_apply(temp2, g1, tok->resa[k++], pairing);
	            element_neg(temp1, one);
    	            element_pow_zn(temp2, temp2, temp1);
                    element_mul(comt[l][i+3], comt[l][i+3], temp2);
	        }
	        element_printf("comt[%d][%d] = %B\n", l, i+3,comt[l][i+3]);
            }
        }
    }

    printf("\t3. Compute c\n");
    char buffer[150] = {0};
    int size = 100;
    char hash[50] = {0};

    //c = Hash(com[i] for i=0 to n+2)
    element_init_Zr(ct, pairing);

    for (l=0; l< tk->levels; l++)
    {
        for(i=0; i<N+3; i++)
        {
            element_snprintf(buffer,size,"%B",comt[l][i]);
            strcat(buffer, hash);
            SHA1(hash, buffer);
	    //printf("Buffer = %s, Hash = %s\n", buffer, hash);
        }
    }
    element_from_hash(ct, hash, strlen(hash));

    if (element_cmp(tk->c, ct))
    {
        printf("c values comparison Failed!\n\n");
	element_printf("c = %B\nct = %B\n", tk->c, ct); 
	return;
    }

    printf("Hurray!\n");
}
*/

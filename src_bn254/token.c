#include <string.h>
#include <sys/types.h>       
#include <netdb.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include "dac.h"

void token_send(token_t *tok, int sock, struct sockaddr_in *servaddr, char *sid, FILE *fp)
{
    int i, j, k, l;
    token_element_t *te;

    //send number of levels
    send_data(1, &tok->levels, sock, servaddr, sid, fp);

    // send c
    send_element(tok->c, 0, sock, servaddr, sid, fp);

    for(l=0; l<tok->levels; l++)
    {
        te = &tok->te[l];

	//send r1
	send_element(te->r1, 1, sock, servaddr, sid, fp);

	//send ress
	send_element(te->ress, 1, sock, servaddr, sid, fp);

	if(l == tok->levels - 1)
	{
            //send rescsk
            send_element(te->rescsk, 0, sock, servaddr, sid, fp); 
	}
	{
            //send rescpk
            send_element(te->rescpk, 1, sock, servaddr, sid, fp); 
	}

	//send num_attrs
	send_data(1, &te->num_attrs, sock, servaddr, sid, fp);

	for(i=0; i < te->num_attrs; i++)
	{
            //send rest
            send_element(te->rest[i], 1, sock, servaddr, sid, fp);            
	}

	//send revealed
	send_data(te->num_attrs - 1, te->revealed, sock, servaddr, sid, fp);

        for(i=0,j=0,k=0; i < te->num_attrs - 1; i++)
        {
	    if(te->revealed[i])
	    {

	    }
	    else
            {
                //send resa
                send_element(te->resa[k++], 1, sock, servaddr, sid, fp);
	    }

        }
    }
    //send revocation time;
    unsigned char time_len = strlen(tok->revocation_time);
    send_data(1,&time_len, sock, servaddr, sid, fp); 
    send_data(time_len, tok->revocation_time, sock, servaddr, sid, fp);

    te = &tok->revocation;
    //send r1
    send_element(te->r1, 1, sock, servaddr, sid, fp);

    //send ress
    send_element(te->ress, 1, sock, servaddr, sid, fp);

    for(i=0; i < 2; i++)
    {
        //send rest
        send_element(te->rest[i], 1, sock, servaddr, sid, fp);
    }

}

void token_receive(token_t *tok, int sock)
{
    int i, j, k, l;
    token_element_t *te;

    //reveive number of levels
    receive_data(1, &tok->levels, sock);
    //printf("Levels = %d\n", tok->levels);

    // receive c
    element_init_Zr(tok->c, pairing);
    receive_element(tok->c, 0, sock);
    //element_printf("tok->c = %B\n", tok->c);

    tok->te = (token_element_t *)malloc(tok->levels * sizeof(token_element_t));

    for(l=0; l<tok->levels; l++)
    {
        te = &tok->te[l];
        if((l+1) % 2)
        {
            element_init_G2(te->r1, pairing);
            element_init_G1(te->ress, pairing);
            element_init_G1(te->rescpk, pairing);            
	}
	else
        {
            element_init_G1(te->r1, pairing);
            element_init_G2(te->ress, pairing);
            element_init_G2(te->rescpk, pairing);
	}

	//receive r1
	receive_element(te->r1, 1, sock);
	//receive ress
	receive_element(te->ress, 1, sock);

	if(l == tok->levels - 1)
	{
            //receive rescsk
	    element_init_Zr(te->rescsk, pairing);
            receive_element(te->rescsk, 0, sock);
	}
	{
            //receive rescpk
            receive_element(te->rescpk, 1, sock);
	}

	//receive num_attrs
	receive_data(1, &te->num_attrs, sock);

	te->rest = (element_t *)malloc(te->num_attrs * sizeof(element_t));
	for(i=0; i < te->num_attrs; i++)
	{
            if ((l+1) % 2)
                element_init_G1(te->rest[i], pairing);
            else
                element_init_G2(te->rest[i], pairing);
            //receive rest
            receive_element(te->rest[i], 1, sock);
	}

	//receive revealed
	te->revealed = (char *) malloc(te->num_attrs - 1);
	receive_data(te->num_attrs - 1, te->revealed, sock);

        int num_revealed = 0;
        for(i=0; i<te->num_attrs-1; i++) //attributes[0] represents CPK
        {
            if(te->revealed[i])
                num_revealed++;
        }

	//printf("Num revealed %d, Num hidden %d\n", num_revealed, (te->num_attrs - num_revealed - 2));

        te->resa = (element_t *) malloc((te->num_attrs - num_revealed - 1) * sizeof(element_t));
                                         //1 attribute have (cpk) already been accounted for
        for(i=0,j=0,k=0; i < te->num_attrs - 1; i++)
        {
	    if(te->revealed[i])
	    {
	    }
	    else
            {
                if ((l+1) % 2)
                    element_init_G1(te->resa[k], pairing);
		else
                    element_init_G2(te->resa[k], pairing);

    		    //receive resa
                receive_element(te->resa[k++], 1, sock);
	    }
        }
    }

    //receive revocation data
    
    unsigned char time_len;
    receive_data(1, &time_len, sock);
    tok->revocation_time = (char *)malloc(time_len);
    receive_data(time_len, tok->revocation_time, sock); 

    te = &tok->revocation;
    element_init_G2(te->r1, pairing);
    element_init_G1(te->ress, pairing);
    //receive r1
    receive_element(te->r1, 1, sock);
    //receive ress
    receive_element(te->ress, 1, sock);

    te->rest = (element_t *)malloc(2 * sizeof(element_t));
    for(i=0; i < 2; i++)
    {
        element_init_G1(te->rest[i], pairing);
        //receive rest
        receive_element(te->rest[i], 1, sock);
    }
}

void token_free(token_t *tok)
{
    int l, i, j, k;
    token_element_t *te;

    element_clear(tok->c);

    for(l=0; l<tok->levels; l++)
    {
        te = &tok->te[l];
	element_clear(te->r1);
	element_clear(te->ress);
	element_clear(te->rescpk);

        if(l == tok->levels - 1)
	{
	    element_clear(te->rescsk);
	}

	for(i=0; i < te->num_attrs; i++)
	{
	    element_clear(te->rest[i]);
	}

	free(te->rest);

	for(i=0,j=0,k=0; i < te->num_attrs - 2; i++)
        {
	    if(te->revealed[i])
	    {
	    }
	    else
	    {
		element_clear(te->resa[k++]);
	    }
	}
	free(te->revealed);
	free(te->resa);
    }
    free(tok->te);
    //free revocation stuff
    free(tok->revocation_time);
    te = &tok->revocation;
    element_clear(te->r1);
    element_clear(te->ress);
    for(i=0; i < 2; i++)
    {
        element_clear(te->rest[i]);
    }
}

void read_revoked_G1T_G2T(element_t g1t, element_t g2t)
{
    FILE *fp = NULL;

    element_init_G1(g1t, pairing);
    element_init_G2(g2t, pairing);

    fp = fopen(REVOKED_FILE, "r");
    if (fp == NULL)
    {
        printf("Error opening %s\n", REVOKED_FILE);
        return;
    }
    read_element_from_file(fp, "G1T", g1t, 0);
    read_element_from_file(fp, "G2T", g2t, 0);

    fclose(fp);
}

void generate_attribute_token(token_t *tok, credential_t *ci, char **revealed, credential_t *revc, char *rev_time)
{
    int i, j, k, l;
    element_t *r1, *rhosig, *s1, **t1;
    element_t one_by_r;
    element_t *rhos, **rhot, **rhoa, *rhocpk, *rhoh, rhocsk;
    element_t **com;
    credential_element_t *ic;
    int num_attrs;
    element_t G1T, G2T;

    token_element_t *te;
    tok->te = (token_element_t *)malloc(ci->levels * sizeof(token_element_t));

    //printf("Generating Attribute token\n");

    //printf("\t1. Generate Randomized signature...");

    //Randomize Signature

    rhosig  = (element_t *)malloc(ci->levels * sizeof(element_t));
    r1      = (element_t *)malloc(ci->levels * sizeof(element_t));
    s1      = (element_t *)malloc(ci->levels * sizeof(element_t));
    t1      = (element_t **)malloc(ci->levels * sizeof(element_t *));
    com     = (element_t **)malloc(ci->levels * sizeof(element_t *));
    rhos    = (element_t *)malloc(ci->levels * sizeof(element_t));
    rhocpk  = (element_t *)malloc(ci->levels * sizeof(element_t));
    rhoh    = (element_t *)malloc(ci->levels * sizeof(element_t));
    rhot    = (element_t **)malloc(ci->levels * sizeof(element_t *));
    rhoa    = (element_t **)malloc(ci->levels * sizeof(element_t *));

    for(i=0; i<ci->levels; i++)
    { 
        //num_attrs includes cpk + credhash + all attributes
	num_attrs = ci->cred[i]->ca->num_of_attributes;
        t1[i]   = (element_t *)malloc(num_attrs * sizeof(element_t));
        rhot[i] = (element_t *)malloc(num_attrs * sizeof(element_t));
        rhoa[i] = (element_t *)malloc((num_attrs - 1)   * sizeof(element_t));
        com[i]  = (element_t *)malloc((num_attrs + 2) * sizeof(element_t)); //num_attrs + com_s + com_revocation
    }

    element_init_Zr(one_by_r, pairing);

    //randomize the signature
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
        element_invert(one_by_r, rhosig[l]);

        element_pow_zn(r1[l], ic->R, rhosig[l]);

        element_pow_zn(s1[l], ic->S, one_by_r);

        for(i=0; i<num_attrs; i++)
        {
            //element_printf("level - %d, ic->T[%d] = %B\n", l, i, ic->T[i]);
            element_pow_zn(t1[l][i], ic->T[i], one_by_r);
            //element_printf("t1[%d][%d] = %B\n", l, i, t1[l][i]);
        }
    }

    // randomize the revocation signature. Currently revocation is only for the level 1 (user/device)
    // there are only two attributes during revocation. One is CPK (not revealed) other is timestapm (revealed)
    element_t rev_r1, rev_rhosig, rev_s1, rev_t1[2];

    element_init_Zr(rev_rhosig, pairing);
    element_init_G2(rev_r1, pairing);
    element_init_G1(rev_s1, pairing);

    element_init_G1(rev_t1[0], pairing); //CPK
    element_init_G1(rev_t1[1], pairing); //timestamp

    //randomize the revocation signature
    element_random(rev_rhosig);
    element_invert(one_by_r, rev_rhosig);

    element_pow_zn(rev_r1, revc->cred[0]->R, rev_rhosig);

    element_pow_zn(rev_s1, revc->cred[0]->S, one_by_r);

    for(i=0; i<2; i++)
    {
        //element_printf("level - %d, ic->T[%d] = %B\n", l, i, ic->T[i]);
        element_pow_zn(rev_t1[i], revc->cred[0]->T[i], one_by_r);
        //element_printf("t1[%d][%d] = %B\n", l, i, t1[l][i]);
    }

    //printf("Done!\n");

    //printf("\t2. Compute com-values...");

    element_t eg1R;
    element_t eg1g2;
    element_t ey1g2;
    element_t temp1, temp2, temp5;
    element_t negrhocsk;
    element_t negrhocpk;
    element_t negrhoh;
    element_t negrhoa;

    element_init_Zr(temp1, pairing);
    element_init_GT(eg1R, pairing);
    element_init_GT(temp2, pairing);
    element_init_GT(eg1g2, pairing);
    element_init_GT(ey1g2, pairing);
    element_init_Zr(negrhocsk, pairing);
    element_init_Zr(negrhocpk, pairing);
    element_init_Zr(negrhoh, pairing);
    element_init_Zr(negrhoa, pairing);

    element_init_Zr(rhocsk, pairing);
    element_random(rhocsk);

    pairing_apply(eg1g2, g1, g2, pairing);

    for (l=0; l< ci->levels; l++)
    {

        ic = ci->cred[l];
        te = &tok->te[l];
	num_attrs = ic->ca->num_of_attributes;

        element_init_Zr(rhos[l], pairing);
        element_random(rhos[l]);

        element_init_Zr(rhocpk[l], pairing);
        element_random(rhocpk[l]);

        element_init_Zr(rhoh[l], pairing);
        element_random(rhoh[l]);

        for(i=0; i<num_attrs; i++)
        {
            element_init_Zr(rhot[l][i], pairing);
	    element_random(rhot[l][i]);
        }
	// total attrs - 1 (one for CPK)
        for(i=0; i<num_attrs - 1; i++)
        {
            element_init_Zr(rhoa[l][i], pairing);
	    element_random(rhoa[l][i]);
        }    

        for(i=0; i<num_attrs + 2; i++) //for s, cpk, credential hash revocation and n attributes
                                       // num_attrs includes cpk 
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
        //element_printf("com[%d][0] = %B\n", l, com[l][0]);

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

        //element_printf("com[%d][1] = %B\n", l, com[l][1]);

	//com[l][2] for revocation

        //element_printf("com[%d][2] = %B\n", l, com[l][2]);

        for(i=0; i< num_attrs - 1; i++)
        {
            //com[i+3] = e(g1,r) ^ (rhosig * rhot[i+1])
            element_mul(temp1, rhosig[l], rhot[l][i+1]);
	    element_pow_zn(com[l][i+3], eg1R, temp1);
            if (revealed[l][i+1]) //attribute revealed
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
                    pairing_apply(ey1g2, Y1[i+1], g2, pairing);
		else
                    pairing_apply(ey1g2, g1, Y2[i+1], pairing);

		element_neg(negrhocpk, rhocpk[l-1]);
		element_pow_zn(temp2, ey1g2, negrhocpk);
		element_mul(com[l][i+3], com[l][i+3], temp2);
	    }
	    //element_printf("com[%d][%d] = %B\n", l, i+3, com[l][i+3]);
        }
    }
    //printf("Done!\n");
    
    //compute com values for revocation signature. Remember we do this only for level-0 
    element_t rev_rhos, rev_rhot[2], rev_com[3];
    element_init_Zr(rev_rhos, pairing);
    element_random(rev_rhos);

    for(i=0; i<2; i++) //one for cpk and one for timestamp
    {
        element_init_Zr(rev_rhot[i], pairing);
        element_random(rev_rhot[i]);
    }

    for(i=0; i<3; i++) //for s, cpk and timestamp
    {
        element_init_GT(rev_com[i], pairing);
    }

    //rev_com[0]
    pairing_apply(eg1R, g1, revc->cred[0]->R, pairing);
    element_mul(temp1, rev_rhosig, rev_rhos);
    element_pow_zn(rev_com[0], eg1R, temp1);

    //rev_com[1]
    element_mul(temp1, rev_rhosig, rev_rhot[0]);
    element_pow_zn(rev_com[1], eg1R, temp1); 

    element_neg(negrhocpk, rhocpk[0]); //use rhocpk from level 0
    element_pow_zn(temp2, eg1g2, negrhocpk);
    element_mul(rev_com[1], rev_com[1], temp2);

    //rev_com[2]
    element_mul(temp1, rev_rhosig, rev_rhot[1]);
    element_pow_zn(rev_com[2], eg1R, temp1);

    //printf("\t3. Compute c...");
    char buffer[150] = {0};
    int size = 100;
    char hash[50] = {0};

    //c = Hash(com[i] for i=0 to n+2)
    element_init_Zr(tok->c, pairing);

    for (l=0; l< ci->levels; l++)
    {
        for(i=0; i<ci->cred[l]->ca->num_of_attributes+2; i++)
        {
	    //element_printf("com[%d][%d] = %B\n", l, i, com[l][i]);
            element_getstr(buffer,size,com[l][i]);
	    sprintf(buffer + size, "%s", hash);
	    SHA1(hash, buffer);
	    //printf("Buffer = %s(%ld), Hash = %s(%ld)\n", buffer, strlen(buffer), hash, strlen(hash));
        }
    }
    //add revocation com values
    for(i=0; i<3; i++) //for s, cpk and timestamp
    {
	//element_printf("rev_com[%d] = %B\n", i, rev_com[i]);
        element_getstr(buffer,size,rev_com[i]);
        sprintf(buffer + size, "%s", hash);
        SHA1(hash, buffer);
        //printf("Buffer = %s(%ld), Hash = %s(%ld)\n", buffer, strlen(buffer), hash, strlen(hash));
    }

    element_from_hash(tok->c, hash, strlen(hash));
    //element_printf("c = %B\n", tok->c);

    //printf("Done!\n");

    //printf("\t4. Compute res values...");

    tok->levels = ci->levels;

    for (l=0; l< ci->levels; l++)
    {
        ic = ci->cred[l];
	num_attrs = ic->ca->num_of_attributes;
        te = &tok->te[l];
	te->num_attrs = num_attrs;

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
	{
            //cpk[l] ^ c
            element_pow_zn(temp5, ic->ca->attributes[0], tok->c);
            element_mul(te->rescpk, te->rescpk, temp5);
            //element_printf("rescpk[%d] = %B\n", l, te->rescpk);
	}

	te->rest = (element_t *)malloc(num_attrs * sizeof(element_t));

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
        for(i=1; i<num_attrs; i++) //attributes[0] represents CPK
        {
            if(revealed[l][i])
                num_revealed++;
        }	    

        te->resa = (element_t *) malloc((num_attrs - num_revealed - 1) * sizeof(element_t)); 
	                                 //1 attribute has (cpk) already been accounted for

	te->revealed = (char *)calloc(num_attrs-1,1);

        for(i=0,j=0,k=0; i<num_attrs - 1; i++) //attributes[0] represents CPK
        {
            if (!revealed[l][i+1]) //not revealed
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
                element_pow_zn(temp5, ic->ca->attributes[i+1], tok->c);
                element_mul(te->resa[j], te->resa[j], temp5);
       	        //element_printf("resa[%d][%d] = %B\n", l, j, te->resa[j]);
	        te->revealed[i] = 0;
       	        j++;
	    }
	    else //revealed
            {
    	        te->revealed[i] = attribute_element_to_index(ic->ca->attributes[i+1], l) + 1; //add 1 to account for A0
	    }
        }
	element_clear(temp5);
    }

    //set res values for revoaction. rescpk will be same rescpk[0]
    te = &tok->revocation;
    element_init_same_as(te->r1, rev_r1);
    element_set(te->r1, rev_r1);

    element_init_G1(te->ress, pairing);
    element_init_G1(temp5, pairing);

    //ress = g1^rhos * s1^c
    element_pow_zn(te->ress, g1, rev_rhos); 
    element_pow_zn(temp5, rev_s1, tok->c);
    element_mul(te->ress, te->ress, temp5);    

    te->rest = (element_t *)malloc(2 * sizeof(element_t));
    for(i=0; i<2; i++)
    {
        element_init_G1(te->rest[i], pairing);
        element_pow_zn(te->rest[i], g1, rev_rhot[i]);
        element_pow_zn(temp5, rev_t1[i], tok->c);
        element_mul(te->rest[i], te->rest[i], temp5);
    }

    tok->revocation_time = malloc(strlen(rev_time));
    strcpy(tok->revocation_time, rev_time);

    //clear of everything used in this function
    element_clear(one_by_r);
    element_clear(G1T);
    element_clear(G2T);

    for (l=0; l< ci->levels; l++)
    {
        ic = ci->cred[l];
	num_attrs = ic->ca->num_of_attributes;

	element_clear(rhosig[l]);

	element_clear(r1[l]);
	element_clear(s1[l]);
        for(i=0; i<num_attrs; i++)
        {
            element_clear(t1[l][i]);
        }
    }

    element_clear(temp1);
    element_clear(eg1R);
    element_clear(temp2);
    element_clear(eg1g2);
    element_clear(ey1g2);
    element_clear(negrhocsk);
    element_clear(negrhocpk);
    element_clear(negrhoh);
    element_clear(negrhoa);
    element_clear(rhocsk);

    for (l=0; l< ci->levels; l++)
    {
        ic = ci->cred[l];
	num_attrs = ic->ca->num_of_attributes;

	element_clear(rhos[l]);
	element_clear(rhocpk[l]);
	element_clear(rhoh[l]);
        for(i=0; i<num_attrs; i++)
        {
	    element_clear(rhot[l][i]);
	}
        for(i=0; i<num_attrs - 1; i++)
        {
            element_clear(rhoa[l][i]);
	}
	for(i=0; i<num_attrs + 2; i++)
	{
	    element_clear(com[l][i]);
	}
    }

    for(i=0; i<ci->levels; i++)
    { 
	free(t1[i]);
	free(rhot[i]);
	free(rhoa[i]);
	free(com[i]);
    }

    free(rhosig);
    free(r1);
    free(s1);
    free(t1);
    free(com);
    free(rhos);
    free(rhocpk);
    free(rhoh);
    free(rhot);
    free(rhoa);

    //printf("Done!\n");
}

int verify_attribute_token(token_t *tk)
{
    //printf("\t5. Testing if everything is fine...");

    int i, j, k, l;
    element_t **comt;
    element_t temp1, temp2, temp5;
    element_t temp3, temp4;
    element_t ct;
    element_t eg1g2;
    token_element_t *tok;
    element_t prevrescpk;
    int num_attrs;
    element_t G1T, G2T;

    element_init_Zr(temp1, pairing);
    element_init_GT(temp2, pairing);
    element_init_GT(temp3, pairing);
    element_init_GT(temp4, pairing);
    element_init_GT(eg1g2, pairing);

    pairing_apply(eg1g2, g1, g2, pairing);    

    comt = (element_t **)malloc(tk->levels * sizeof(element_t *));

    for(l=0; l<tk->levels; l++) 
    {
        tok = &tk->te[l];
	num_attrs = tok->num_attrs;

	if (l != 0)
	{
            element_init_same_as(prevrescpk ,tk->te[l-1].rescpk);
            element_set(prevrescpk, tk->te[l-1].rescpk);
	}

        comt[l]  = (element_t *)malloc((num_attrs+2) * sizeof(element_t));
        for(i=0; i<num_attrs+2; i++) //for s, cpk and all attributes
        {
            element_init_GT(comt[l][i], pairing);
        }

        if ((l+1) % 2)
        {
            element_init_G1(temp5, pairing);
            //comt[0] = t(ress,r1) (e(y1[0],g2) * (e(g1,root_public_key))^(-c)
            pairing_apply(comt[l][0], tok->ress, tok->r1, pairing);
	    if(l != 0)
	    {
                //e(g1^(-1), rescpk[i-1])
		pairing_apply(temp3, g1, prevrescpk, pairing);
		element_invert(temp3,temp3);
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
            //element_printf("comt[%d][0] = %B\n", l, comt[l][0]);

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
                pairing_apply(temp3, tok->rescpk, g2, pairing);
		element_invert(temp3, temp3);
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
		element_invert(temp3, temp3);
                element_mul(comt[l][1], comt[l][1], temp3);
	    }

            //element_printf("comt[%d][1] = %B\n", l, comt[l][1]);

            // compute comt[l][2]
            //element_printf("comt[%d][2] = %B\n", l, comt[l][2]);

            for(i=0,j=0,k=0; i<num_attrs - 1; i++)
            {
                pairing_apply(comt[l][i+3], tok->rest[i+1], tok->r1, pairing);
                if(tok->revealed[i])
         	{
                    //com[i+3] = e(rest[i+1], r1) * (e(attributes[i+2],g2) * e(y1[i+2],root_public_key)) ^ (-c)
    	            pairing_apply(temp2, system_attributes_g1[tok->revealed[i]-1], g2, pairing);
		    if (l == 0)
                    {
                        pairing_apply(temp3, Y1[i+1],root_public_key, pairing);
    	                element_mul(temp2, temp2, temp3);
                    }
	            element_neg(temp1, tk->c);
	            element_pow_zn(temp2, temp2, temp1);

	            element_mul(comt[l][i+3], comt[l][i+3], temp2);
		    if (l != 0)
		    {
                        //e(Y1[0],rescpk[l-1]) 
                        pairing_apply(temp3, Y1[i+1], prevrescpk, pairing);
			element_invert(temp3, temp3);
	                element_mul(comt[l][i+3], comt[l][i+3], temp3);
		    }
	        }
	        else
	        {
                    //com[i+3] = e(rest[i+1], r1) * (e(resa[i],g2)^(-1)) * (e(y1[i+2],root_public_key)) ^ (-c)
                    pairing_apply(temp2, tok->resa[k++],g2, pairing);
		    element_invert(temp2, temp2);
                    element_mul(comt[l][i+3], comt[l][i+3], temp2);
                    if (l == 0)
                    {
                        pairing_apply(temp3, Y1[i+1],root_public_key, pairing);
                        element_neg(temp1, tk->c);
                        element_pow_zn(temp3, temp3, temp1);
                        element_mul(comt[l][i+3], comt[l][i+3], temp3);
		    }
		    else
		    {
                        //e(Y1[0],rescpk[l-1])
                        pairing_apply(temp3, Y1[i+1], prevrescpk, pairing);
			element_invert(temp3, temp3);
                        element_mul(comt[l][i+3], comt[l][i+3], temp3);
		    }
	        }
	        //element_printf("comt[%d][%d] = %B\n", l, i+3,comt[l][i+3]);
            }
        }
	else
        {
            element_init_G2(temp5, pairing);
            //comt[0] = t(r1,ress) (e(y1[0],g2) * (e(g1,root_public_key))^(-c)
            pairing_apply(comt[l][0], tok->r1, tok->ress, pairing);

            //e(rescpk[i-1], g2^(-1))
            pairing_apply(temp3, prevrescpk, g2, pairing);
	    element_invert(temp3, temp3);
            element_mul(comt[l][0], comt[l][0], temp3);

            pairing_apply(temp3, g1, Y2[0], pairing);
            element_neg(temp1, tk->c);
            element_pow_zn(temp3, temp3, temp1); 
            element_mul(comt[l][0], comt[l][0], temp3);
            //element_printf("comt[%d][0] = %B\n", l, comt[l][0]);

            //comt[1] = e(rest[0],r1) * e(g1,g2)^(-rescsk) * (e(y1[0],root_public_key))^(-c)
            pairing_apply(comt[l][1], tok->r1, tok->rest[0], pairing);

            //e(rescpk[l-1],Y2[0]) 
            pairing_apply(temp3, prevrescpk, Y2[0], pairing);
	    element_invert(temp3, temp3);
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
                pairing_apply(temp3, g1, tok->rescpk, pairing);
		element_invert(temp3, temp3);
                element_mul(comt[l][1], comt[l][1], temp3);
	    }

            //element_printf("comt[%d][1] = %B\n", l, comt[l][1]);


            // compute comt[l][2]
            //element_printf("comt[%d][2] = %B\n", l, comt[l][2]);
   
            for(i=0,j=0,k=0; i<num_attrs - 1; i++)
            {
                pairing_apply(comt[l][i+3], tok->r1, tok->rest[i+1], pairing);
                pairing_apply(temp3, prevrescpk, Y2[i+1], pairing);
		element_invert(temp3, temp3);
    	        element_mul(comt[l][i+3], comt[l][i+3], temp3);

                if(tok->revealed[i])
         	{
                    //com[i+3] = e(rest[i+1], r1) * (e(attributes[i+1],g2) * e(y1[i+1],root_public_key)) ^ (-c)
    	            pairing_apply(temp2, g1,system_attributes_g2[tok->revealed[i] -1], pairing);
	            element_neg(temp1, tk->c);
	            element_pow_zn(temp2, temp2, temp1);

	            element_mul(comt[l][i+3], comt[l][i+3], temp2);

	        }
	        else
	        {
                    //com[i+3] = e(rest[i+1], r1) * (e(resa[i],g2)^(-1)) * (e(y1[i+1],root_public_key)) ^ (-c)
                    pairing_apply(temp2, g1, tok->resa[k++], pairing);
		    element_invert(temp2, temp2);
                    element_mul(comt[l][i+3], comt[l][i+3], temp2);
	        }
	        //element_printf("comt[%d][%d] = %B\n", l, i+3,comt[l][i+3]);
            }
        }
    }

    //compute com values for revocation
    element_t rev_comt[3];
    element_init_G1(temp5, pairing);

    for(i=0; i<3; i++) //for s, cpk and timestamp
    {
        element_init_GT(rev_comt[i], pairing);
    }

    tok = &tk->revocation;
    //comt[0] = t(ress,r1) (e(y1[0],g2) * (e(g1,root_public_key))^(-c)
    pairing_apply(rev_comt[0], tok->ress, tok->r1, pairing);

    pairing_apply(temp3, Y1[0], g2, pairing);
    pairing_apply(temp4, g1, root_public_key, pairing);
    element_mul(temp3, temp3, temp4);
    element_neg(temp1, tk->c);
    element_pow_zn(temp3, temp3, temp1); 
    element_mul(rev_comt[0], rev_comt[0], temp3);
    //element_printf("comt[%d][0] = %B\n", l, comt[l][0]);

    pairing_apply(rev_comt[1], tok->rest[0], tok->r1, pairing);
    //e(rescpk[i],g2^(-1))
    pairing_apply(temp3, tk->te[0].rescpk, g2, pairing); //use rescpk from level 0
    element_invert(temp3, temp3);
    element_mul(rev_comt[1], rev_comt[1], temp3);

    pairing_apply(temp3, Y1[0], root_public_key, pairing);
    element_neg(temp1, tk->c);
    element_pow_zn(temp3, temp3, temp1);
    element_mul(rev_comt[1], rev_comt[1], temp3);


    pairing_apply(rev_comt[2], tok->rest[1], tok->r1, pairing);
    //build the element from revocation time
    element_t revocation_time;
    element_init_G1(revocation_time, pairing);
    element_hash_and_map_to(revocation_time, tk->revocation_time);

    pairing_apply(temp2, revocation_time, g2, pairing);

    pairing_apply(temp3, Y1[1],root_public_key, pairing);
    element_mul(temp2, temp2, temp3);
    element_neg(temp1, tk->c);
    element_pow_zn(temp2, temp2, temp1);

    element_mul(rev_comt[2], rev_comt[2], temp2);

    //printf("\t3. Compute c\n");
    char buffer[150] = {0};
    int size = 100;
    char hash[50] = {0};

    //c = Hash(com[i] for i=0 to n+2)
    element_init_Zr(ct, pairing);

    for (l=0; l< tk->levels; l++)
    {
        for(i=0; i<tk->te[l].num_attrs + 2; i++)
        {
	    //element_printf("com[%d][%d] = %B\n", l, i, comt[l][i]);
	    element_getstr(buffer,size,comt[l][i]);
	    sprintf(buffer + size, "%s", hash);
            SHA1(hash, buffer);
	    //printf("Buffer = %s, Hash = %s\n", buffer, hash);
        }
    }
    //add revocation com values
    for(i=0; i<3; i++) //for s, cpk and timestamp
    {
	//element_printf("rev_com[%d] = %B\n", i, rev_comt[i]);
        element_getstr(buffer,size,rev_comt[i]);
        sprintf(buffer + size, "%s", hash);
        SHA1(hash, buffer);
        //printf("Buffer = %s(%ld), Hash = %s(%ld)\n", buffer, strlen(buffer), hash, strlen(hash));
    }

    element_from_hash(ct, hash, strlen(hash));

    if (element_cmp(tk->c, ct))
    {
        printf("c values comparison Failed!\n\n");
	element_printf("c = %B\nct = %B\n", tk->c, ct); 
	return FAILURE;
    }

    //clear everything used in this function
    element_clear(temp1);
    element_clear(temp2);
    element_clear(temp3);
    element_clear(temp4);
    element_clear(temp5);
    element_clear(eg1g2);

    element_clear(G1T);
    element_clear(G2T);

    for(l=0; l<tk->levels; l++) 
    {
        tok = &tk->te[l];
	num_attrs = tok->num_attrs;

	if (l != 0)
	{
            element_clear(prevrescpk);
	}

        for(i=0; i<num_attrs+2; i++) //for s, cpk, and all attributes
        {
            element_clear(comt[l][i]);
	}
	free(comt[l]);
    }
    free(comt);
    element_clear(ct);

    //printf("Hurray!\n");
    return SUCCESS;
}

#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <sys/time.h>
#include "dac.h"

#define USER_DIR HOME_DIR "/users"

void calculate_time_diff(char *prefix, struct timeval *start, struct timeval *end)
{
    double time_taken;
    time_taken = (end->tv_sec - start->tv_sec) * 1e6;
    time_taken = (time_taken + (end->tv_usec -
                              start->tv_usec)) * 1e-3;
    printf("time taken for %s = %fms\n", prefix, time_taken);
}


void dac_generate_parameters()
{
    int i;
    int ret = initialize_system_params(stdout);

    if(ret == -1)
    {
	char str[10];
        FILE *fp = fopen(PARAM_FILE, "w");

	printf("param file %s\n", PARAM_FILE);
	if (fp == NULL)
	{
            printf("errno %d, str %s\n", errno, strerror(errno));
	    return;
	}

        element_random(g1);
	write_element_to_file(fp, "g1", g1);
        element_random(g2);
	write_element_to_file(fp, "g2", g2);

        element_random(root_secret_key);
	write_element_to_file(fp, "private_key", root_secret_key);
        element_pow_zn(root_public_key, g2, root_secret_key);
	write_element_to_file(fp, "public_key", root_public_key);

        //Generate system attributes
        for(i=0; i<MAX_NUM_ATTRIBUTES; i++)
        {
            element_random(system_attributes_g1[i]);
            element_random(system_attributes_g2[i]);
            sprintf(str, "att_g1[%d]", i);
            write_element_to_file(fp, str, system_attributes_g1[i]);
            sprintf(str, "att_g2[%d]", i);
            write_element_to_file(fp, str, system_attributes_g2[i]);
        }

        //Generate y1[n] and y2[n]
        for(i=0; i<TOTAL_ATTRIBUTES; i++)
        {
            element_random(Y1[i]);
	    sprintf(str, "Y1[%d]", i);
	    write_element_to_file(fp, str, Y1[i]);
        }

        for(i=0; i<TOTAL_ATTRIBUTES; i++)
        {
            element_random(Y2[i]);
	    sprintf(str, "Y2[%d]", i);
	    write_element_to_file(fp, str, Y2[i]);
        }
	fclose(fp);
    }

    printf("Done!\n\n");
}

void write_revoked_G1T_G2T()
{
    FILE *revfp = NULL;

    if( access( REVOKED_FILE, F_OK ) == -1 )
    {
        element_t g1t, g2t, t;
        // file does not exist. Write G1T and G2T
        printf("Revoked file does not exist. Writing G1T and G2T to it\n");
        element_init_G1(g1t, pairing);
        element_init_G2(g2t, pairing);
        element_init_Zr(t, pairing);
        element_random(t);

        element_pow_zn(g1t, g1, t);
        element_pow_zn(g2t, g2, t);

        revfp = fopen(REVOKED_FILE, "w");
        if (revfp == NULL)
        {
            printf("Error opening %s\n", REVOKED_FILE);
            return;
        }
        write_element_to_file(revfp, "G1T", g1t);
        write_element_to_file(revfp, "G2T", g2t);

        element_clear(g1t);
        element_clear(g2t);
        element_clear(t);
        fclose(revfp);
    }
}

int revoke_user_credential(char *user)
{
    //read attribute[0] from user's param.txt and publish it in revoked.txt
    FILE *fp, *revfp;
    char str[100];
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    element_t dummy, r, g1t, g2t, user_public_key;

    element_init_G1(g1t, pairing);
    element_init_G2(g2t, pairing);

    fp = fopen(REVOKED_FILE, "r");
    if (fp == NULL)
    {
        printf("Error opening %s\n", REVOKED_FILE);
        return FAILURE;
    }
    read_element_from_file(fp, "G1T", g1t, 0);
    read_element_from_file(fp, "G2T", g2t, 0);

    fclose(fp);

    sprintf(str, "%s/%s/params.txt", USER_DIR, user);
    fp = fopen(str, "r");
    if (fp == NULL)
    {
        printf("Error opening params.txt for %s\n", user);
        return FAILURE;
    }

    //skip first 4 lines
    read_element_from_file(fp, "dummy", dummy, 1);
    read_element_from_file(fp, "dummy", dummy, 1);
    read_element_from_file(fp, "dummy", dummy, 1);
    read_element_from_file(fp, "dummy", dummy, 1);

    element_init_G1(user_public_key, pairing);
    read_element_from_file(fp, "public_key", user_public_key, 0);

    element_init_Zr(r, pairing);
    element_random(r);
    element_pow_zn(user_public_key, user_public_key, r);
    element_pow_zn(g2t, g2t, r);

    fclose(fp);

    //append to revoked file
    revfp = fopen(REVOKED_FILE, "a");
    if (revfp == NULL)
    {
        printf("Error opening %s\n", REVOKED_FILE);
        return FAILURE;
    }
    write_element_to_file(revfp, "CPK_r", user_public_key);
    write_element_to_file(revfp, "G2T_r", g2t);
    fclose(revfp);
}

static int issue_user_credential(char *user, char *attributes)
{
    char str[100] = {0};

    sprintf(str, "%s/%s", USER_DIR, user);
    DIR* dir = opendir(str);
    if (dir)
    {
        /* User already exists. */
	printf("%s already issued credentials\n", user);
        closedir(dir);
	return FAILURE;
    }
    else if (ENOENT == errno) 
    {
	credential_attributes *ca;
	credential_t ic;
	int a[MAX_NUM_ATTRIBUTES] = {0};
	int i = 0, j=0;
	int ret;
	struct timeval start, end;

        printf("Issuing credentials to %s with attributes %s\n", user, attributes);

        /* Directory does not exist. */
        element_t priv, pub;
	mkdir(str, 0766);

	// Generate Pub/Priv Key pair
        element_init_Zr(priv, pairing);
        element_random(priv);

        element_init_G1(pub, pairing);
        element_pow_zn(pub, g1, priv);

        char* token = strtok(attributes, ","); 
  
        while (token != NULL) 
	{
	    int attrindx = atoi(token + 1);
	    a[i++] = attrindx;
            token = strtok(NULL, ","); 
        }
	ca = set_credential_attributes(1, pub, i, a);

	memset(&ic, 0, sizeof(ic));
	gettimeofday(&start, NULL);
        ret = issue_credential(root_secret_key, root_public_key, ca, &ic); //called by issuer with its private and public key
        gettimeofday(&end, NULL);
        calculate_time_diff("issue credential", &start, &end);

        if (ret != SUCCESS)
        {
            printf("issue_credential Failed\n");
            exit(FAILURE);
        }	

	// Write everything to the file
	strcat(str, "/params.txt");
	FILE *fp = fopen(str, "w");
	fprintf(fp, "user = %s\n", user);
	fprintf(fp, "levels = %d\n",ic.levels);
	fprintf(fp, "attributes = ");
	for(i=0; a[i] != 0; i++)
            fprintf(fp, "A%d,", a[i]);
	fprintf(fp, "\n");
	write_element_to_file(fp, "private_key", priv);
	write_element_to_file(fp, "public_key", pub);

	for(i=0; i<ic.levels; i++)
	{
            credential_element_t *ce = ic.cred[i];
	    write_element_to_file(fp, "R", ce->R);
	    write_element_to_file(fp, "S", ce->S);
	    fprintf(fp, "num_attrs = %d\n",ce->ca->num_of_attributes);
	    for(j=0; j<ce->ca->num_of_attributes; j++)
	    {
		char s[10];
		sprintf(s, "T[%d]", j);
                write_element_to_file(fp, s, ce->T[j]);
		sprintf(s, "attr[%d]", j);
		write_element_to_file(fp, s, ce->ca->attributes[j]);
	    }
	}
        fclose(fp);	
	return SUCCESS;
    } 
    else 
    {
        /* opendir() failed for some other reason. */
	printf("opendir failed! %s\n", strerror(errno));
	return FAILURE;
    }

}

int main(int argc, char *argv[])
{
    int i;
    int ret = FAILURE;

    dac_generate_parameters();

    if(argc < 2)
    {
        printf("Check Usage\n");
        exit(-1);
    }

    write_revoked_G1T_G2T();

    // ./root ISSUE user1 A1,A3,A4
    if (!strcasecmp(argv[1], "ISSUE"))
    {
        ret = issue_user_credential(argv[2], argv[3]);
    }

    // ./root REVOKE user1
    if (!strcasecmp(argv[1], "REVOKE"))
    {
        ret = revoke_user_credential(argv[2]);
    }    
    printf("Exit from main\n");
    return 0;
}

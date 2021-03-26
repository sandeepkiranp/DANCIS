#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <sys/time.h>
#include <pthread.h>
#include "dac.h"
#define LISTENQ 100
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
	    element_t r;
	    element_init_Zr(r, pairing);
	    element_random(r);

            element_pow_zn(system_attributes_g1[i], g1, r);
            sprintf(str, "att_g1[%d]", i);
            write_element_to_file(fp, str, system_attributes_g1[i]);

            element_pow_zn(system_attributes_g2[i], g2, r);
            sprintf(str, "att_g2[%d]", i);
            write_element_to_file(fp, str, system_attributes_g2[i]);
        }

        //Generate y1[n] and y2[n]
        for(i=0; i<TOTAL_ATTRIBUTES; i++)
        {
	    element_t r;
	    element_init_Zr(r, pairing);
	    element_random(r);

            element_pow_zn(Y1[i], g1, r);
	    sprintf(str, "Y1[%d]", i);
	    write_element_to_file(fp, str, Y1[i]);
        }
        for(i=0; i<TOTAL_ATTRIBUTES; i++)
        {
            element_t r;
            element_init_Zr(r, pairing);
            element_random(r);

            element_pow_zn(Y2[i], g2, r);
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
	ca = set_credential_attributes(1, pub, i, a, 0, NULL);

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

void send_revocation_signature(int sockfd, char *rev_time, credential_t *ic)
{
    int j;
    credential_element_t *ce = ic->cred[0];

    unsigned char len = strlen(rev_time);

    mysend(sockfd, &len, 1, 0, "dummy", stdout);
    mysend(sockfd, rev_time, strlen(rev_time), 0, "dummy", stdout);

    send_element(ce->R, 0, sockfd, NULL, "dummy", stdout);
    send_element(ce->S, 0, sockfd, NULL, "dummy", stdout);
    for(j=0; j<ce->ca->num_of_attributes; j++)
    {
        send_element(ce->T[j], 0, sockfd, NULL, "dummy", stdout);
    }
}

void process_revocation_request(int sockfd)
{
    int len, n;
    struct sockaddr_in address, cliaddr;
    event_t evt;
    len = sizeof(cliaddr);
    messagetype mtype;
    char user[USER_LENGTH] = {0};
    int i,j;
    struct timeval start;

    gettimeofday(&start, NULL);

    double time_in_mill = (start.tv_sec) * 1000 + (start.tv_usec) / 1000 ;
    printf("Received event request at %f ms\n", time_in_mill);

    n = recv(sockfd, user, sizeof(user), 0);
    printf("Received revocation status request from %s len %d\n", user, n);

    //read user public key
    char c[200] = {0};
    char str[50] = {0};
    char luser[30] = {0};
    int levels;
    char attributes[100] = {0};
    credential_element_t *ce;
    element_t dummy;
    element_t user_public_key;
    element_t current_time;
    credential_attributes *ca;
    credential_t ic;
    char cur_time[30] = {0};
    char dum[100];

    sprintf(str, "%s/%s/params.txt", USER_DIR, user);
    printf("Reading parameters from %s\n", str);

    FILE *fp = fopen(str, "r");
    if (fp == NULL)
    {
        printf("Error opening file %s\n", strerror(errno));
        return ;
    }

    fscanf(fp,"user = %s\n", dum);
    fscanf(fp,"levels = %s\n", dum);
    fscanf(fp,"attributes = %s\n", dum);

    element_init_G1(user_public_key, pairing);

    read_element_from_file(fp, "dummy", dummy, 1);
    read_element_from_file(fp, "public_key", user_public_key, 0);
    
    sprintf(cur_time, "%ld", time(NULL));
    element_init_G1(current_time, pairing);
    element_hash_and_map_to(current_time, cur_time);

    ca = set_credential_attributes(1, user_public_key, 1, NULL, 1, current_time);
    issue_credential(root_secret_key, root_public_key, ca, &ic);

    send_revocation_signature(sockfd, cur_time, &ic);
}

void handle_request(int sockfd)
{
    int n;
    messagetype mtype;

    n = recv(sockfd, (char *)&mtype, sizeof(messagetype), 0);
    if (n == -1)
    {
        printf("recvfrom returned %d, %s\n", errno, strerror(errno));
        close(sockfd);
        return;
    }

    switch(mtype)
    {
        case REVOCATION_REQUEST:
            process_revocation_request(sockfd);
            break;
        default:
            printf("Unknown %d request\n", mtype);
    }
    close(sockfd);
}

void * socketThread(void *arg)
{
    int new_socket = *((int *)arg);

    handle_request(new_socket);
    free(arg);
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

    //write_revoked_G1T_G2T();

    // ./root ISSUE user1 A1,A3,A4
    if (!strcasecmp(argv[1], "ISSUE"))
    {
        ret = issue_user_credential(argv[2], argv[3]);
	return 0;
    }

    // ./root REVOKE user1
    if (!strcasecmp(argv[1], "REVOKE"))
    {
        ret = revoke_user_credential(argv[2]);
	return 0;
    }    

    int server_fd;
    struct sockaddr_in address;
    int opt = 1;

    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Forcefully attaching socket to the port 8080
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
                                                  &opt, sizeof(opt)))
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(get_service_port(ROOT_SVC));

    if (bind(server_fd, (struct sockaddr *)&address,
                                 sizeof(address))<0)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, LISTENQ) < 0)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    while(1)
    {
        int len, n;
        pthread_t the_thread;
        int *new_socket;
        struct sockaddr_in cliaddr;

        new_socket = (int *)malloc(sizeof(int));

        len = sizeof(cliaddr);

        if ((*new_socket = accept(server_fd,
                    (struct sockaddr *)&cliaddr, (socklen_t*)&len))<0)
        {
            perror("accept");
            exit(EXIT_FAILURE);
        }

        if( pthread_create(&the_thread, NULL, socketThread, new_socket) != 0 )
        {
            printf("Failed to create thread\n");
            perror("pthread_create");
            exit(EXIT_FAILURE);
        }

        printf("Created Thread %d for socket %d\n", (int)the_thread,*new_socket);

        pthread_detach(the_thread);
    }

    printf("Exit from main\n");
    return 0;
}

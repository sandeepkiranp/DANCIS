#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <time.h>
#include <sys/time.h>
#include "dac.h"

#define USER_DIR HOME_DIR "/users"
#define CONTROLLER_DIR HOME_DIR "/controller"
#define PARAM_FILE HOME_DIR "/root/params.txt"

element_t user_private_key;
element_t user_public_key;
char username[50];
char user_attributes[100];
int attcount = 0;
int attribute_indx_array[MAX_NUM_ATTRIBUTES];
int user_level;

credential_t ic;

void calculate_time_diff(char *prefix, struct timeval *start, struct timeval *end)
{
    double time_taken;
    time_taken = (end->tv_sec - start->tv_sec) * 1e6;
    time_taken = (time_taken + (end->tv_usec -
                              start->tv_usec)) * 1e-3;
    printf("time taken for %s = %fms\n", prefix, time_taken);
}


int read_user_params(char *user)
{
    char c[200] = {0};
    char str[50] = {0};
    char luser[30] = {0};
    int levels;
    char attributes[100] = {0};
    credential_attributes ca;
    int i = 0, j = 0;
    credential_element_t *ce;

    sprintf(str, "%s/%s/params.txt", USER_DIR, user);
    printf("Reading parameters from %s\n", str);

    FILE *fp = fopen(str, "r");
    if (fp == NULL)
    {
	printf("Error opening file %s\n", strerror(errno));
        return FAILURE;
    }

    fscanf(fp,"user = %s\n", username);
    fscanf(fp,"levels = %d\n", &ic.levels);
    fscanf(fp,"attributes = %s\n", attributes);

    memcpy(user_attributes, attributes, strlen(attributes));
    printf("user = %s, levels = %d, attributes = %s ", 
		    username, ic.levels, attributes);

    user_level = ic.levels;
    char* token = strtok(attributes, ",");

    while (token != NULL)
    {
        int attrindx = atoi(token + 1);
        attribute_indx_array[attcount++] = attrindx;
        token = strtok(NULL, ",");
    }
    printf("attribute count %d\n", attcount);

    element_init_Zr(user_private_key, pairing);

    element_init_G1(user_public_key, pairing);

    read_element_from_file(fp, "private_key", user_private_key, 0);
    read_element_from_file(fp, "public_key", user_public_key, 0);

    setup_credentials_from_file(fp, &ic);

    fclose(fp);
    return SUCCESS;
}

void initialize_credential(credential_t *src, credential_t *dst)
{
    credential_element_t *ced, *ces;
    int i, j;

    dst->levels = src->levels;
    dst->cred = (credential_element_t **) malloc(dst->levels * sizeof(credential_element_t *));
    for(i = 0; i < dst->levels; i++)
    {
        ced = dst->cred[i] = (credential_element_t *)malloc(sizeof(credential_element_t));
        ces = src->cred[i];

        element_init_same_as(ced->R, ces->R);
        element_set(ced->R, ces->R);

        element_init_same_as(ced->S, ces->S);
        element_set(ced->S, ces->S);

        ced->ca = (credential_attributes *) malloc(sizeof(credential_attributes));
        ced->ca->num_of_attributes = ces->ca->num_of_attributes;
        ced->T = (element_t *)malloc(ces->ca->num_of_attributes * sizeof(element_t));
        ced->ca->attributes = (element_t *)malloc(ces->ca->num_of_attributes * sizeof(element_t));
        for(j = 0; j < ces->ca->num_of_attributes; j++)
        {
            element_init_same_as(ced->T[j], ces->T[j]);
            element_set(ced->T[j], ces->T[j]);

            element_init_same_as(ced->ca->attributes[j], ces->ca->attributes[j]);
            element_set(ced->ca->attributes[j], ces->ca->attributes[j]);
        }
    }
}

void free_credential(credential_t *dst)
{
    credential_element_t *ced;
    int i, j;

    for(i = 0; i < dst->levels; i++)
    {
        ced = dst->cred[i];

        element_clear(ced->R);
        element_clear(ced->S);

        for(j = 0; j < ced->ca->num_of_attributes; j++)
        {
            element_clear(ced->T[j]);
            element_clear(ced->ca->attributes[j]);
        }
        free(ced->ca->attributes);
        free(ced->ca);
        free(ced->T);
        free(ced);
    }
}

int send_event_request(char *user, char *event)
{
    int sockfd; 
    struct sockaddr_in     servaddr; 
    messagetype mtype = EVENT_REQUEST;
    event_t evt = get_event_from_string(event);
    socklen_t addr_size;
    int one = 1;

    // Creating socket file descriptor 
    if ( (sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0 ) { 
        perror("socket creation failed"); 
        exit(EXIT_FAILURE); 
    } 

    //setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    //setsockopt(sockfd, SOL_TCP, TCP_NODELAY, &one, sizeof(one));
  
    memset(&servaddr, 0, sizeof(servaddr)); 
      
    // Filling server information 
    servaddr.sin_family = AF_INET; 
    servaddr.sin_port = htons(get_service_port(CONTROLLER_SVC)); 
    servaddr.sin_addr.s_addr = INADDR_ANY; 

    addr_size = sizeof(servaddr);

    if(connect(sockfd, (struct sockaddr *) &servaddr, addr_size) < 0)
    {
        perror("socket connection failed");
        return FAILURE;
    }

    int n, len; 
      
    send(sockfd, (const char *)&mtype, sizeof(messagetype), 0);

    printf("Sending %d event to controller for %s\n", evt, user);

    // send user name
    send(sockfd, user, USER_LENGTH,0);

    send(sockfd, (const char *)&evt, sizeof(event_t), 0);
}

int delegate_credential(char *duser, char *attributes)
{
    // Get duser's public key
    char str[100] = {0};
    element_t dummy;
    int i=0, j=0;
    element_t duser_public_key;
    int a[50] = {0};
    char attr[100] = {0};
    credential_attributes *ca;
    credential_t dic;
    int ret;

    //check if credentials are already delegated
    sprintf(str, "%s/%s.txt", CONTROLLER_DIR,username);
    if( access( str, F_OK ) == 0 )
    {
        printf("Credentials already delegated to %s\n", duser);
    }
    else 
    {
        sprintf(str, "%s/params.txt", CONTROLLER_DIR);
        printf("Reading parameters from %s\n", str);
        FILE *fp = fopen(str, "r");

        //skip first line
        read_element_from_file(fp, "dummy", dummy, 1);
    
        element_init_G2(duser_public_key, pairing);
        read_element_from_file(fp, "public_key", duser_public_key, 0);

        fclose(fp);
	element_printf("Cont pub key %B", duser_public_key);

        i = 1;     
	a[0] = 1;  // Delegate a dummy attribute A1

        ca = set_credential_attributes(user_level + 1, duser_public_key, i, a);
	
        if (!strcasecmp(attributes, "ALL"))
        {
            memcpy(attr, user_attributes, strlen(user_attributes));
        }
        else
            memcpy(attr, attributes, strlen(attributes));

        char* token = strtok(attr, ",");

        i = 0;
        while (token != NULL)
        {
            int attrindx = atoi(token + 1);
            a[i++] = attrindx;
            token = strtok(NULL, ",");
        }
    
        memset(&dic, 0, sizeof(dic));
        //initialize dic with ic so that we can add the next level credential to dic
        initialize_credential(&ic, &dic);
        ret = issue_credential(user_private_key, user_public_key, ca, &dic); //called by issuer with its private and public key
        if (ret != SUCCESS)
        {
            printf("issue_credential Failed\n");
            exit(FAILURE);
        }

        // Write everything to the file
        sprintf(str, "%s/%s.txt", CONTROLLER_DIR, username);
        fp = fopen(str, "w");
        fprintf(fp, "delegator = %s\n", username);
        fprintf(fp, "levels = %d\n",ic.levels + 1);
        fprintf(fp, "attributes = ");
        for(i=0; a[i] != 0; i++)
            fprintf(fp, "A%d,", a[i]);
        fprintf(fp, "\n");

        // write the delegated signture details
        for(i=0; i<dic.levels; i++)
        {
            printf("Writing Level-%d Credentials\n", i+1);
            credential_element_t *ce = dic.cred[i];
            write_element_to_file(fp, "R", ce->R);
            write_element_to_file(fp, "S", ce->S);
	    fprintf(fp, "num_attrs = %d\n", ce->ca->num_of_attributes);
            for(j=0; j<ce->ca->num_of_attributes; j++)
            {
                char s[10];
                sprintf(s, "T[%d]", j);
                write_element_to_file(fp, s, ce->T[j]);
                sprintf(s, "attr[%d]", j);
                write_element_to_file(fp, s, ce->ca->attributes[j]);
            }
        }
        printf("Finished writing delegated credentials\n");
        free_credential(&dic);
    }
}

FILE *logfp;

int main(int argc, char *argv[])
{
    char user[USER_LENGTH] = {0};
    struct timeval start, end;
    initialize_system_params(stdout);
    if(read_user_params(argv[1])== FAILURE)
        exit(-1);
    read_services_location();

    //./user user1 DELEGATE user2 all|A1,A2
    if (argc > 2 && !strcmp(argv[2],"DELEGATE"))
    {
	gettimeofday(&start, NULL);
        delegate_credential(argv[3],argv[4]);
        gettimeofday(&end, NULL);
        calculate_time_diff("Delegate Credentials", &start, &end);
    }

    //./user user1 EVENT EVENT1 
    if (argc > 2 && !strcmp(argv[2],"EVENT"))
    {
	gettimeofday(&start, NULL);
        delegate_credential(CONTROLLER_SVC, "all");
        gettimeofday(&end, NULL);
        calculate_time_diff("Delegate Credentials", &start, &end);
	strcpy(user, argv[1]);
	send_event_request(user,argv[3]);
    }    

    return 0;
}


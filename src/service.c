#include "dac.h"
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#define PORT 8080

FILE *logfp;
char service_name[20];
int attributes[MAX_NUM_ATTRIBUTES] = {0};
int attr_count = 0;

typedef struct policy
{
    char *rule;
    int num_services;
    char *services[10];
}policy_t;

int num_policies;
policy_t *policies;

int load_policy(char *svc)
{
    char str[100];
    char attrs[400];
    char c[200] = {0};
    int i, j;

    sprintf(str, "%s/services/%s/policy.txt", HOME_DIR, svc);
    fprintf(logfp, "Reading policy from %s\n", str);

    FILE *fp = fopen(str, "r");
    if (fp == NULL)
    {
        fprintf(logfp, "Error opening file %s\n", strerror(errno));
        return FAILURE;
    }
    fgets(attrs, sizeof(attrs), fp);

    fprintf(logfp, "Attributes = %s\n", attrs);

    char* token = strtok(attrs, "['A");

    while (token != NULL)
    {
	if (isdigit(token[0]))
        {
            attributes[atoi(token)] = 1;
	    attr_count++;
	}

        token = strtok(NULL, "', 'A");
    }

    fgets(c, sizeof(c), fp);
    num_policies = atoi(c);

    char * line = NULL;
    size_t len = 0;
    ssize_t read;

    policies = (policy_t *)calloc(num_policies * sizeof (policy_t), 1);

    for (i = 0; i < num_policies; i++)
    {
	//read the rule
        read = getline(&line, &len, fp);
        policies[i].rule = (char *)calloc(1, read);
        memcpy(policies[i].rule, line, read -1);

	//read the services to be invoked
        read = getline(&line, &len, fp);
	line[read - 1] = 0; //trim the new line character
	j = 0;

        char* token = strtok(line, " ");

        while (token != NULL)
        {
	    policies[i].services[j] = (char *)calloc(1, strlen(token));
	    memcpy(policies[i].services[j], token, strlen(token)); 
            token = strtok(NULL, " ");
	    j++;
        }
	policies[i].num_services = j;
        //skip empty line
	getline(&line, &len, fp);
    }

    free(line);
  
    return SUCCESS;
}

int invoke_service(char *sid, char *service)
{
    int sockfd;
    struct sockaddr_in     servaddr;
    messagetype mtype = SERVICE_CHAIN_REQUEST;

    // Creating socket file descriptor
    if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&servaddr, 0, sizeof(servaddr));

    // Filling service information
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(get_service_port(service));
    char *ip = get_service_ip(service);
    if (ip == NULL)
    {
	fprintf(logfp,"Invalid service %s\n", service);
        return FAILURE;
    }
    inet_aton(ip, &servaddr.sin_addr);

    sendto(sockfd, (const char *)&mtype, sizeof(messagetype),
        0, (const struct sockaddr *) &servaddr,
            sizeof(servaddr));

    sendto(sockfd, (const char *)sid, SID_LENGTH,
        0, (const struct sockaddr *) &servaddr,
            sizeof(servaddr));
}

void evaluate_policy(char *sid, token_t *tok)
{
    int i, j = 0;
    int num_revealed = 0;
    int attributes[MAX_NUM_ATTRIBUTES] = {0};

    for(i=0; i<tok->te[1].num_attrs-2; i++) //attributes[0] represents CPK
    {
        if(tok->te[1].revealed[i])
            num_revealed++;
    }

    for (j = 0; j < num_revealed; j++)
    {
        int attr_indx = attribute_element_to_index(tok->te[1].attributes[j]);
	attributes[attr_indx] = 1;
    }

    for (i = 0; i < num_policies; i++)
    {
        if(evaluate(attributes, policies[i].rule))
	{
            for(j = 0; j < policies[i].num_services; j++)
            {
                fprintf(logfp, "Invoking service %s\n", policies[i].services[j]);
                invoke_service(sid, policies[i].services[j]);
	    }
	    break;
        }
    }
}

void calculate_time_diff(char *prefix, struct timeval *start, struct timeval *end)
{
    double time_taken;
    time_taken = (end->tv_sec - start->tv_sec) * 1e6;
    time_taken = (time_taken + (end->tv_usec -
                              start->tv_usec)) * 1e-3;
    fprintf(logfp, "time taken for %s = %fms\n", prefix, time_taken);
}

int process_service_request(int sock)
{
    token_t tok;
    char sid[SID_LENGTH];
    int len, n;
    struct sockaddr_in cliaddr;
    struct timeval start, end;

    len = sizeof(cliaddr);
    n = recvfrom(sock, sid, sizeof(sid),
                0, ( struct sockaddr *) &cliaddr,
                &len);
    if (n == -1)
    {
        fprintf(logfp, "recvfrom returned %d, %s\n", errno, strerror(errno));
        return FAILURE;
    }

    fprintf(logfp, "Received Service Request for Session %s\n", sid);

    gettimeofday(&start, NULL);
    //receive the token
    token_receive(&tok, sock);
    gettimeofday(&end, NULL);
    calculate_time_diff("receive attribute token", &start, &end);

    gettimeofday(&start, NULL);
    //verify the token
    if(verify_attribute_token(&tok) == FAILURE)
    {
        fprintf(logfp, "Attribute token verification failed!\n");
	return FAILURE;
    }
    gettimeofday(&end, NULL);
    calculate_time_diff("verify attribute token", &start, &end);

    gettimeofday(&start, NULL);

    // check for blacklist credential hash
    if(is_credential_valid(tok.te[0].credhash) == FAILURE)
    {
	fprintf(logfp, "process_service_request failed as credential is blacklisted\n");
	return FAILURE;
    }
    gettimeofday(&end, NULL);
    calculate_time_diff("credential blacklist checking", &start, &end);

    // Evaluate policy
    gettimeofday(&start, NULL);
    evaluate_policy(sid, &tok);
    gettimeofday(&end, NULL);
    calculate_time_diff("policy evaluation", &start, &end);

    token_free(&tok);
}

int process_service_chain_request(int sock)
{
    char sid[SID_LENGTH];
    int len, n;
    struct sockaddr_in cliaddr;

    len = sizeof(cliaddr);
    n = recvfrom(sock, sid, sizeof(sid),
                0, ( struct sockaddr *) &cliaddr,
                &len);
    if (n == -1)
    {
        fprintf(logfp, "recvfrom returned %d, %s\n", errno, strerror(errno));
        return FAILURE;
    }
    fprintf(logfp, "Received service chain request for session ID %s\n", sid);

    //make a request to controller for attribute token for this sid and service
    int sockfd;
    struct sockaddr_in     servaddr;
    messagetype mtype = SERVICE_CHAIN_REQUEST;

    // Creating socket file descriptor
    if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&servaddr, 0, sizeof(servaddr));

    // Filling service information
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(get_service_port(CONTROLLER_SVC));
    inet_aton(get_service_ip(CONTROLLER_SVC), &servaddr.sin_addr);

    sendto(sockfd, (const char *)&mtype, sizeof(messagetype),
        0, (const struct sockaddr *) &servaddr,
            sizeof(servaddr));

    sendto(sockfd, (const char *)service_name, strlen(service_name),
        0, (const struct sockaddr *) &servaddr,
            sizeof(servaddr));

    sendto(sockfd, (const char *)sid, SID_LENGTH,
        0, (const struct sockaddr *) &servaddr,
            sizeof(servaddr));
}

//./service <service_name> <port>
int main(int argc, char *argv[])
{
    char str[100];
    sprintf(str, "%s/services/%s/log.txt", HOME_DIR, argv[1]);

    logfp = fopen(str, "a");

    if(initialize_system_params(logfp) != SUCCESS)
	return -1;

    strcpy(service_name, argv[1]);

    load_policy(argv[1]);

    read_services_location();

    fflush(logfp);

    int server_fd, new_socket, valread; 
    struct sockaddr_in address, cliaddr; 
    int opt = 1; 
    int addrlen = sizeof(address); 
    char buffer[1024] = {0}; 
       
    // Creating socket file descriptor 
    if ((server_fd = socket(AF_INET, SOCK_DGRAM, 0)) == 0) 
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
    address.sin_port = htons( get_service_port(argv[1]) ); 
       
    // Forcefully attaching socket to the port 8080 
    if (bind(server_fd, (struct sockaddr *)&address,  
                                 sizeof(address))<0) 
    { 
        perror("bind failed"); 
        exit(EXIT_FAILURE); 
    } 

    while(1)
    {
        int len, n;
        len = sizeof(cliaddr);
        messagetype mtype;
        n = recvfrom(server_fd, (char *)&mtype, sizeof(messagetype),
                    0, ( struct sockaddr *) &cliaddr,
                    &len);
        if (n == -1)
        {
            fprintf(logfp, "recvfrom returned %d, %s\n", errno, strerror(errno));
            return 0;
        }
    
        switch(mtype)
        {
            case SERVICE_REQUEST:
                process_service_request(server_fd);
	        break;
            case SERVICE_CHAIN_REQUEST:
                process_service_chain_request(server_fd);
                break;
            default:
	        fprintf(logfp, "Unknown %d request\n", mtype);
        }
	fflush(logfp);
    }

    return 0;
}

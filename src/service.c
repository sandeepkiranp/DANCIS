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
#include <pthread.h>
#define PORT 8080
#define LISTENQ 100
#define MAX_SESSIONS 20

FILE *logfp;
char service_name[SERVICE_LENGTH];
int num_sessions = 0;
char session_list[MAX_SESSIONS][SID_LENGTH] = {0};
int attr_count = 0;

int num_policies;
policy_t *policies;
pthread_mutex_t lock;

void handle_request(int sockfd);

int invoke_service(char *sid, char *service)
{
    int sockfd;
    struct sockaddr_in     servaddr;
    messagetype mtype = SERVICE_CHAIN_REQUEST;
    socklen_t addr_size;

    mylog(logfp, "Sending service chain request to %s with SID %s\n", service, sid);

    // Creating socket file descriptor
    if ( (sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0 ) {
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
	mylog(logfp,"Invalid service %s\n", service);
        return FAILURE;
    }
    inet_aton(ip, &servaddr.sin_addr);

    addr_size = sizeof(servaddr);

    if(connect(sockfd, (struct sockaddr *) &servaddr, addr_size) < 0)
    {
        perror("socket connection failed");
        return FAILURE;
    }

    send(sockfd, (const char *)&mtype, sizeof(messagetype), 0);

    send(sockfd, (const char *)service_name, sizeof(service_name),0);

    send(sockfd, (const char *)sid, SID_LENGTH, 0);

    close(sockfd);
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
                mylog(logfp, "Invoking service %s\n", policies[i].services[j]);
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
    mylog(logfp, "time taken for %s = %fms\n", prefix, time_taken);
}

int process_constrained_service_request(int sock)
{
    token_t tok;
    char sid[SID_LENGTH];
    char dest_services[100] = {0};
    int len, n;
    struct sockaddr_in cliaddr;
    struct timeval start, end;

    len = sizeof(cliaddr);
    n = recv(sock, sid, sizeof(sid), 0);
    if (n == -1)
    {
        mylog(logfp, "recvfrom returned %d, %s\n", errno, strerror(errno));
        return FAILURE;
    }

    len = sizeof(cliaddr);
    n = recv(sock, dest_services, sizeof(dest_services), 0);
    if (n == -1)
    {
        mylog(logfp, "recvfrom returned %d, %s\n", errno, strerror(errno));
        return FAILURE;
    }

    mylog(logfp, "Received Constrained Service Request for Session %s, Destination Services %s\n", sid, dest_services);

    char* token = strtok(dest_services, ",");

    while (token != NULL)
    {
	invoke_service(sid,token);
        token = strtok(NULL, ",");
    }    
}

int process_service_request(int sock)
{
    token_t tok;
    char sid[SID_LENGTH];
    int len, n;
    struct sockaddr_in cliaddr;
    struct timeval start, end;

    len = sizeof(cliaddr);
    n = recv(sock, sid, sizeof(sid), 0);
    if (n == -1)
    {
        mylog(logfp, "recvfrom returned %d, %s\n", errno, strerror(errno));
        return FAILURE;
    }

    mylog(logfp, "Received Service Request for Session %s\n", sid);

    gettimeofday(&start, NULL);
    //receive the token
    token_receive(&tok, sock);
    gettimeofday(&end, NULL);
    calculate_time_diff("receive attribute token", &start, &end);

    gettimeofday(&start, NULL);
    //verify the token
    if(verify_attribute_token(&tok) == FAILURE)
    {
        mylog(logfp, "Attribute token verification failed!\n");
	return FAILURE;
    }
    gettimeofday(&end, NULL);
    calculate_time_diff("verify attribute token", &start, &end);

    gettimeofday(&start, NULL);

    // check for blacklist credential hash
    if(is_credential_valid(tok.te[0].credhash) == FAILURE)
    {
	mylog(logfp, "process_service_request failed as credential is blacklisted\n");
        token_free(&tok);
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
    int len, n, i;
    struct sockaddr_in cliaddr;
    char service[SERVICE_LENGTH] = {0};

    len = sizeof(cliaddr);
    n = recv(sock, service, sizeof(service), 0);
    if (n == -1)
    {
        mylog(logfp, "recvfrom returned %d, %s\n", errno, strerror(errno));
        return FAILURE;
    }

    n = recv(sock, sid, sizeof(sid), 0);
    if (n == -1)
    {
        mylog(logfp, "recvfrom returned %d, %s\n", errno, strerror(errno));
        return FAILURE;
    }
    mylog(logfp, "Received service chain request from %s for session ID %s\n", service, sid);

    pthread_mutex_lock(&lock);

    for (i = 0; i < MAX_SESSIONS; i++)
    {
	if (session_list[i] && !strcmp(session_list[i], sid))
	{
            mylog(logfp, "Session %s already encountered for this service \n", sid);
            pthread_mutex_unlock(&lock);
	    return SUCCESS;
	}
    }

    //make a request to controller for attribute token for this sid and service
    int sockfd;
    struct sockaddr_in     servaddr;
    socklen_t addr_size;
    messagetype mtype = SERVICE_CHAIN_REQUEST;

    // Creating socket file descriptor
    if ( (sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0 ) {
        perror("socket creation failed");
        pthread_mutex_unlock(&lock);
	return FAILURE;
    }

    memset(&servaddr, 0, sizeof(servaddr));

    // Filling service information
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(get_service_port(CONTROLLER_SVC));
    inet_aton(get_service_ip(CONTROLLER_SVC), &servaddr.sin_addr);

    addr_size = sizeof(servaddr);

    if(connect(sockfd, (struct sockaddr *) &servaddr, addr_size) < 0)
    {
        perror("socket connection failed");
        pthread_mutex_unlock(&lock);
	return FAILURE;
    }

    mylog(logfp, "Sending service chain request to controller for Session %s \n", sid);

    send(sockfd, (const char *)&mtype, sizeof(messagetype), 0);

    send(sockfd, (const char *)service_name, sizeof(service_name),0);

    send(sockfd, (const char *)sid, SID_LENGTH,0);

    mylog(logfp, "Adding Session %s to session list\n", sid);

    if (num_sessions == MAX_SESSIONS)
        num_sessions = 0;

    strcpy(session_list[num_sessions], sid);
    num_sessions++;

    pthread_mutex_unlock(&lock);

    handle_request(sockfd);
}

void handle_request(int sockfd)
{
    int n;
    messagetype mtype;

    n = recv(sockfd, (char *)&mtype, sizeof(messagetype), 0);
    if (n == -1)
    {
        mylog(logfp, "recvfrom returned %d, %s\n", errno, strerror(errno));
        close(sockfd);
        return;
    }

    switch(mtype)
    {
        case SERVICE_REQUEST:
            process_service_request(sockfd);
            break;
        case SERVICE_CHAIN_REQUEST:
            process_service_chain_request(sockfd);
            break;
        case CONSTRAINED_SERVICE_REQUEST:
            process_constrained_service_request(sockfd);
            break;
        default:
            mylog(logfp, "Unknown %d request\n", mtype);
    }
    close(sockfd);
}

void * socketThread(void *arg)
{
    int new_socket = *((int *)arg);

    handle_request(new_socket);
    free(arg);
}

//./service <service_name> <port>
int main(int argc, char *argv[])
{
    service_policy svcplcy;
    char str[100];

    sprintf(str, "%s/services/%s/log.txt", HOME_DIR, argv[1]);

    if (pthread_mutex_init(&lock, NULL) != 0)
    {
        printf("\n mutex init has failed\n");
        return 1;
    }

    logfp = fopen(str, "a");

    if(initialize_system_params(logfp) != SUCCESS)
	return -1;

    strcpy(service_name, argv[1]);

    load_policy(argv[1], &svcplcy);
    num_policies = svcplcy.num_policies;
    policies = svcplcy.policies;

    read_services_location();

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
    address.sin_port = htons( get_service_port(argv[1]) ); 
       
    // Forcefully attaching socket to the port 8080 
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
        // TODO : Is it something from my port and my IP? If so, continue
	if (/*!strcmp(inet_ntoa(cliaddr.sin_addr), ) && */ntohs(cliaddr.sin_port) == address.sin_port)
	{
            close(*new_socket);
            free(new_socket);
	    continue;
	}

        if( pthread_create(&the_thread, NULL, socketThread, new_socket) != 0 )
        {
            printf("Failed to create thread\n");
            perror("pthread_create");
            exit(EXIT_FAILURE);
        }

        mylog(logfp, "Created Thread %d for socket %d\n", (int)the_thread,*new_socket);

        pthread_detach(the_thread);
    }

    return 0;
}

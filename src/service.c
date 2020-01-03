#include "dac.h"
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#define PORT 8080

char service[30];
int attributes[MAX_NUM_ATTRIBUTES] = {0};
int attr_count = 0;

typedef struct policy
{
    char *rule;
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
    printf("Reading policy from %s\n", str);

    FILE *fp = fopen(str, "r");
    if (fp == NULL)
    {
        printf("Error opening file %s\n", strerror(errno));
        return FAILURE;
    }
    fgets(attrs, sizeof(attrs), fp);

    printf("Attributes = %s\n", attrs);

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

    policies = (policy_t *)malloc(num_policies * sizeof (policy_t));

    for (i = 0; i < num_policies; i++)
    {
	//read the rule
        read = getline(&line, &len, fp);
        policies[i].rule = (char *)calloc(1, read);
        memcpy(policies[i].rule, line, read);

	//read the services to be invoked
        read = getline(&line, &len, fp);
	j = 0;

        char* token = strtok(line, " ");

        while (token != NULL)
        {
	    policies[i].services[j] = (char *)calloc(1, strlen(token));
	    memcpy(policies[i].services[j], token, strlen(token)); 
            token = strtok(NULL, " ");
	    j++;
        }
        //skip empty line
	getline(&line, &len, fp);
    }

    free(line);
  
    return SUCCESS;
}

void process_service_request(int sock)
{
    token_t tok;

    token_receive(&tok, sock);
    verify_attribute_token(&tok);
}

//./service <service_name> <port>
int main(int argc, char *argv[])
{
    if(initialize_system_params() != SUCCESS)
	return -1;

    load_policy(argv[1]);

    int server_fd, new_socket, valread; 
    struct sockaddr_in address, cliaddr; 
    int opt = 1; 
    int addrlen = sizeof(address); 
    char buffer[1024] = {0}; 
    char *hello = "Hello from server"; 
       
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
    address.sin_port = htons( atoi(argv[2]) ); 
       
    // Forcefully attaching socket to the port 8080 
    if (bind(server_fd, (struct sockaddr *)&address,  
                                 sizeof(address))<0) 
    { 
        perror("bind failed"); 
        exit(EXIT_FAILURE); 
    } 

    int len, n;
    len = sizeof(cliaddr);
    messagetype mtype;
    n = recvfrom(server_fd, (char *)&mtype, sizeof(messagetype),
                0, ( struct sockaddr *) &cliaddr,
                &len);
    if (n == -1)
    {
        printf("recvfrom returned %d, %s\n", errno, strerror(errno));
        return 0;
    }

    switch(mtype)
    {
        case SERVICE_REQUEST:
	    printf("Received Service Request\n");
	    process_service_request(server_fd);
	    break;
	default:
	    printf("Unknown %d request\n", mtype);
    }

    return 0;
}

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <time.h>
#include <sys/time.h>
#include "dac.h"

#define USER_DIR HOME_DIR "/users"
#define CONTROLLER_DIR HOME_DIR "/controller"
#define SERVICES_DIR HOME_DIR "/services"
#define PARAM_FILE HOME_DIR "/root/params.txt"

element_t user_private_key;
element_t user_public_key;
char username[50];
char user_attributes[100];
int attcount = 0;
int attribute_indx_array[50];
int user_level;
int dusers_count = 0;

typedef struct delegted_credential
{
    char delegator[30];
    int num_dattrs;
    int  dattrs[MAX_NUM_ATTRIBUTES];
    credential_t dic;
}delegated_credential_t;

delegated_credential_t *dc;

int num_events;

typedef struct events
{
    event_t evt;
    char *services[10];
}evt_svc_map;

evt_svc_map *esmap;

int num_services = 0;

typedef struct service_attributes
{
    char service[30];
    int num_attrs;
    int attributes[MAX_NUM_ATTRIBUTES];
}service_attributes;

service_attributes *svc_attrs;

typedef struct session
{
    char user[30];
    char sid[SID_LENGTH];
}session_t;

int num_sessions = 0;
int MAX_SESSIONS = 0;
session_t *sessions;

int read_event_file()
{
    char str[50] = {0};
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    int i = 0, j=0;

    sprintf(str, "%s/event.txt", CONTROLLER_DIR);
    printf("\nReading events from %s\n", str);

    FILE *fp = fopen(str, "r");
    if (fp == NULL)
    {
        printf("Error opening file %s\n", strerror(errno));
        return FAILURE;
    }

    fscanf(fp, "%d\n",&num_events);
    esmap = (evt_svc_map *) calloc(num_events , sizeof(evt_svc_map));

    while ((read = getline(&line, &len, fp)) != -1) 
    {
	line[read - 1] = 0; //trim the new line character
        j = 0;

        //first token is the event
        char* token = strtok(line, " ");
        esmap[i].evt = get_event_from_string(token);

        token = strtok(NULL, " ");
        while (token != NULL)
        {
            esmap[i].services[j] = (char *)calloc(1, strlen(token));
            memcpy(esmap[i].services[j], token, strlen(token));
	    token = strtok(NULL, " ");
            j++;
        }
	i++;
    }
    fclose(fp);

   free(line);
}

int read_params()
{
    char str[50] = {0};
    char luser[30] = {0};
    int levels;
    char attributes[100] = {0};
    
    element_init_Zr(user_private_key, pairing);
    element_init_G2(user_public_key, pairing);

    sprintf(str, "%s/params.txt", CONTROLLER_DIR);
    printf("Reading parameters from %s\n", str);

    if( access( str, F_OK ) != 0 )
    {
        element_random(user_private_key);
	element_pow_zn(user_public_key, g2, user_private_key);

        FILE *fp = fopen(str, "w");
        if (fp == NULL)
        {
            printf("Error opening file %s\n", strerror(errno));
            return FAILURE;
        }

        write_element_to_file(fp, "private_key", user_private_key);
        write_element_to_file(fp, "public_key", user_public_key);
        fclose(fp);
        return SUCCESS;	
    }

    FILE *fp = fopen(str, "r");
    if (fp == NULL)
    {
        printf("Error opening file %s\n", strerror(errno));
        return FAILURE;
    }


    read_element_from_file(fp, "private_key", user_private_key, 0);
    read_element_from_file(fp, "public_key", user_public_key, 0);

    element_printf("Priv Key = %B, Pub Key = %B\n", user_private_key, user_public_key);

    fclose(fp);
    return SUCCESS;
}

int load_delegated_credentials(char *user)
{
    char c[200] = {0};
    char str[50] = {0};
    char luser[30] = {0};
    int levels;
    char attributes[100] = {0};
    credential_attributes ca;
    int i = 0, j = 0;
    credential_element_t *ce;
    char cmd[100];
    char dusers[100][30];
    char name[30] = {0};
    FILE *fp;
    int old_dusers_count = dusers_count;

    memset(dusers, 0, sizeof(dusers));
    //If user is NULL, load all delegated credentials in the directory
    //else load only that user's delegated credentials

    if (user == NULL)
    {
        sprintf(cmd, "ls %s | grep -v -e params -e event | sed -e 's/\\.txt$//'", CONTROLLER_DIR);
	fp = popen(cmd, "r");
        while (fgets(name, sizeof(name), fp) != NULL)
	{
	    name[strlen(name) - 1] = 0;
            strcpy(dusers[dusers_count++], name);
	    memset(name, 0, sizeof(name));
        }
	pclose(fp);
    }
    else
    {
	//check if the we already have the delegated credential for this delegator
	for (i = 0; i < dusers_count; i++)
	{
            if(!strcmp(dc[i].delegator, user))
	    {
	        printf("Delegated credentials from %s are already loaded\n", user);
		return SUCCESS;
	    }
	}

        strcpy(dusers[old_dusers_count],user);
	dusers_count++;
    }

    dc = (delegated_credential_t *)realloc(dc, dusers_count * (sizeof(delegated_credential_t)));

    for(i = old_dusers_count; i<dusers_count; i++)
    {
	printf("\nLoading Delegated Credentials for %s\n", dusers[i]);
	memset(&dc[i], 0, sizeof(dc[i]));
        sprintf(str, "%s/%s.txt", CONTROLLER_DIR, dusers[i]);
        printf("Reading parameters from %s\n", str);

        fp = fopen(str, "r");
        if (fp == NULL)
        {
            printf("Error opening file %s\n", strerror(errno));
            return FAILURE;
        }

        fscanf(fp,"delegator = %s\n", dc[i].delegator);
        fscanf(fp,"levels = %d\n", &levels);
        fscanf(fp,"attributes = %s\n", attributes);

        printf("duser = %s, levels = %d, attributes = %s\n",
                        dc[i].delegator, levels, attributes);

        char* token = strtok(attributes, ",");

        while (token != NULL)
        {
            int attrindx = atoi(token + 1);
            dc[i].dattrs[dc[i].num_dattrs++] = attrindx;
            token = strtok(NULL, ",");
        }

	dc[i].dic.levels = levels;
	credential_set_private_key(user_private_key, &dc[i].dic);
        setup_credentials_from_file(fp,dc[i].num_dattrs,&dc[i].dic);
    }
    printf("Finished loading Delegated credentials for all users\n");

}

void send_token(token_t *tok, char *service, char *session_id)
{
    int sockfd;
    struct sockaddr_in     servaddr;
    messagetype mtype = SERVICE_REQUEST;

    // Creating socket file descriptor
    if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&servaddr, 0, sizeof(servaddr));

    // Filling service information
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(get_service_port(service));
    inet_aton(get_service_ip(service), &servaddr.sin_addr);

    sendto(sockfd, (const char *)&mtype, sizeof(messagetype),
        0, (const struct sockaddr *) &servaddr,
            sizeof(servaddr));

    sendto(sockfd, (const char *)session_id, SID_LENGTH,
        0, (const struct sockaddr *) &servaddr,
            sizeof(servaddr));

    token_send(tok, sockfd, &servaddr);
}

unsigned long get_time()
{
        struct timeval tv;
        gettimeofday(&tv, NULL);
        unsigned long ret = tv.tv_usec;
        ret /= 1000;
        ret += (tv.tv_sec * 1000);
        return ret;
}

static char *rand_string(char *str, size_t size)
{
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890+-*%$#@!";
    srand(get_time());
    if (size) {
        --size;
        for (size_t n = 0; n < size; n++) {
            int key = rand() % (int) (sizeof charset - 1);
            str[n] = charset[key];
        }
        str[size] = '\0';
    }
}

void generate_credential_token(char *session_id, char *user, char *service)
{
    int i = 0,j = 0;
    credential_t *c = NULL;

    if (session_id == NULL)
    {
	if (num_sessions == MAX_SESSIONS)
	{
	    MAX_SESSIONS += 100;
	    sessions = (session_t *) realloc(sessions, MAX_SESSIONS * sizeof(session_t));
        }
	// Generate random session_id
	rand_string(sessions[num_sessions].sid, sizeof(sessions[num_sessions].sid)); 
        strcpy(sessions[num_sessions].user, user);
	session_id = sessions[num_sessions].sid;
        num_sessions++;
    }
    else
    {
        //Get user from session cache for this session_id
	for(i = 0; i < num_sessions; i++)
	{
	    if(!strcmp(sessions[num_sessions].sid, session_id))
	        user = sessions[num_sessions].user;
	}
    }

    for(i = 0; i < dusers_count; i++)
    {
        if(!strcmp(dc[i].delegator, user))
        {
            c = &dc[i].dic;
        }
    }

    if (NULL == c)
    {
	printf("Delegated Credentials not found for %s\n", user);
	return;
    }

    for(i = 0; i < num_services; i++)
    {
	if(!strcmp(svc_attrs[i].service, service))
	{
	    printf("Generating Token for %s for %s\n", user, service);
	    char *revealed[2]; //two levels.
	    revealed[0] = (char *)calloc(c->cred[0]->ca->num_of_attributes, 1);
	    revealed[1] = (char *)calloc(c->cred[1]->ca->num_of_attributes, 1);

	    //Reveal credhash at level 0. do not reveal any other attributes at level 0
	    revealed[0][1] = 1;


            // attribute 0 is pub key1. Dont reveal
            // attribute 1 is cred hash. reveal it
	    revealed[1][0] = 0;
            revealed[1][1] = 1;
	    for (j = 2; j < c->cred[1]->ca->num_of_attributes; j++)
	    {
                int attr_indx = attribute_element_to_index(c->cred[1]->ca->attributes[j]); 
		if(svc_attrs[i].attributes[attr_indx])
		    revealed[1][j] = 1;
	    }

	    token_t tok;
            generate_attribute_token(&tok, c, revealed);    
	    //verify_attribute_token(&tok);
	    send_token(&tok, service, session_id);
	}
    }
}

int process_event_request(int sock)
{
    int len, n;
    struct sockaddr_in address, cliaddr;
    event_t evt;
    len = sizeof(cliaddr);
    messagetype mtype;
    char user[20];
    int i,j;

    n = recvfrom(sock, user, sizeof(user),
                0, ( struct sockaddr *) &cliaddr,
                &len);    

    n = recvfrom(sock, (char *)&evt, sizeof(event_t),
                0, ( struct sockaddr *) &cliaddr,
                &len);
    printf("Received %d event from %s\n", evt, user);

    //load the delegated credentials for this user
    load_delegated_credentials(user);

    for(i = 0; i < num_events; i++)
    {
        if(esmap[i].evt == evt)
	{
	    for(j = 0; esmap[i].services[j] != NULL; j++)
	    {
                generate_credential_token(NULL, user, esmap[i].services[j]);
	    }
	}
    }	
}

int read_policy_attributes_from_services()
{
    //for each of the services, read what all attributes
    //it needs
    struct dirent *de;
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    char str[100];

    DIR *dr = opendir(SERVICES_DIR);

    if (dr == NULL)  // opendir returns NULL if couldn't open directory
    {
        printf("Could not open current directory" );
        return 0;
    }

    //allocate for 20 services initially
    svc_attrs = (service_attributes *)calloc(20 * sizeof(service_attributes), 1);

    while ((de = readdir(dr)) != NULL)
    {
	char name[20];

        if(de->d_name[0] == '.')
	    continue;

	if (num_services > 19)
            svc_attrs = (service_attributes *)realloc(svc_attrs, (num_services + 10) * sizeof(service_attributes));

	strcpy(name, de->d_name);
        sprintf(str, "%s/services/%s/policy.txt", HOME_DIR, name);
        printf("Reading policy from %s\n", str);

	memset(svc_attrs[num_services].service, 0, sizeof(svc_attrs[num_services].service));
	memcpy(svc_attrs[num_services].service, name, strlen(name));

        FILE *fp = fopen(str, "r");
        if (fp == NULL)
        {
            printf("Error opening file %s\n", strerror(errno));
            return FAILURE;
        }

	read = getline(&line, &len, fp);

        printf("Attributes = %s\n", line);

        char* token = strtok(line, "['A");

        while (token != NULL)
        {
            if (isdigit(token[0]))
            {
                svc_attrs[num_services].attributes[atoi(token)] = 1;
                svc_attrs[num_services].num_attrs++;
            }

            token = strtok(NULL, "', 'A");
        }
	num_services++;
	fclose(fp);
    }

    closedir(dr);
}

int main(int argc, char *argv[])
{
    initialize_system_params();
    read_params();
    read_event_file();
    read_services_location();
    read_policy_attributes_from_services();

    load_delegated_credentials(NULL);

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
/*
    // Forcefully attaching socket to the port 8080
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
                                                  &opt, sizeof(opt)))
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
*/
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons( CONTROLLER_PORT );

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
            printf("recvfrom returned %d, %s\n", errno, strerror(errno));
            return 0;
        }

        switch(mtype)
        {
            case EVENT_REQUEST:
                printf("Received Event Request\n");
                process_event_request(server_fd);
                break;
            default:
                printf("Unknown %d request\n", mtype);
        }
    }
}

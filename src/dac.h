#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pbc/pbc.h>

#define SUCCESS 0
#define FAILURE 1
#define N 3

#define HOME_DIR "/home/users/sandeep/dac/dac"
//#define HOME_DIR "/root/dac"
#define MAX_NUM_ATTRIBUTES 50
#define TOTAL_ATTRIBUTES (MAX_NUM_ATTRIBUTES + 2) //cpk(i-1) + credential hash + MAX_NUM_ATTRIBUTES attributes

#define CONTROLLER_SVC "controller"

#define SID_LENGTH 10
#define SERVICE_LENGTH 15
#define USER_LENGTH 10

typedef struct attributes
{
    element_t *attributes;     //attributes[0] represents the public key
                               //attribute[1] represents the hashed credential
    int num_of_attributes;
}credential_attributes;

typedef struct credential_element
{
    element_t R;
    element_t S;
    element_t *T; //CPK + credential hash + n attributes
    credential_attributes *ca;
}credential_element_t;

typedef struct credential
{
    int levels;
    credential_element_t **cred; 
    element_t secret_key;
}credential_t;

typedef struct token_element
{
    element_t r1;
    element_t ress;
    element_t rescpk;
    element_t rescsk;
    element_t rev_g1t_r;
    element_t rev_cpk_r;
    char num_attrs; //cpk + all attributes
    element_t *rest;
    char *revealed;
    element_t *attributes;
    element_t *resa;
}token_element_t;

typedef struct token
{
    char levels;
    token_element_t *te;
    element_t c;
}token_t;

typedef enum messagetype
{
    SERVICE_REQUEST = 1,
    SERVICE_RESPONSE,
    EVENT_REQUEST,
    EVENT_RESPONSE,
    SERVICE_CHAIN_REQUEST,
    SERVICE_CHAIN_RESPONSE,
    CONSTRAINED_SERVICE_REQUEST
}messagetype;

typedef enum eventtype
{
    EVENT1 = 1,
    EVENT2,
    EVENT3,
    EVENT4
}event_t;

typedef enum servicemode
{
    CONSTRINED = 1,
    UNCONSTRAINED
}servicemode;

extern element_t g1, g2;
extern element_t system_attributes_g1[MAX_NUM_ATTRIBUTES];
extern element_t system_attributes_g2[MAX_NUM_ATTRIBUTES];
extern element_t Y1[TOTAL_ATTRIBUTES], Y2[TOTAL_ATTRIBUTES];
extern pairing_t pairing;
extern element_t root_public_key;
extern element_t root_secret_key;

typedef struct policy
{
    char *rule;
    int num_services;
    char *services[10];
}policy_t;

typedef struct service_policy
{
    char service[20];
    int num_policies;
    policy_t *policies;
}service_policy;

extern int load_policy(char *svc, service_policy *svcplcy);

extern void read_element_from_file(FILE *fp, char *param, element_t e, int skipline);

extern void write_element_to_file(FILE *fp, char *param, element_t e);

extern char *base64_encode(const unsigned char *data,
                    size_t input_length,
                    size_t *output_length) ;
extern unsigned char *base64_decode(const char *data,
                             size_t input_length,
                             size_t *output_length);

extern int evaluate(int *attributes, char * tokens);

extern int attribute_element_to_index(element_t e, int level);

extern event_t get_event_from_string(char *evt);

extern int read_services_location();

extern char *get_service_ip(char *service);

extern short int get_service_port(char *service);

extern servicemode get_service_mode(char *service);

extern void dac_generate_parameters();

extern int initialize_system_params(FILE *fp);

extern void setup_credentials_from_file(FILE *fp, credential_t *c);

extern credential_attributes *set_credential_attributes(int level, element_t pub, int num_attr, int *attr);

extern int issue_credential(element_t secret_key, element_t public_key, credential_attributes *ca, credential_t *ic);

extern void generate_user_keys(int level, element_t priv, element_t pub);

extern void get_root_secret_key(element_t x);

extern void get_root_public_key(element_t x);

extern void credential_set_private_key(element_t secret_key, credential_t *ic);

extern void generate_attribute_token(token_t *tok, credential_t *ic, char **revealed, element_t T, element_t T1);

extern int verify_attribute_token(token_t *tok);

extern int is_credential_valid(element_t credhash);

extern void token_send(token_t *tok, int sock, struct sockaddr_in *servaddr, char *sid, FILE *fp);

extern  void token_receive(token_t *tok, int sock);

extern void token_free(token_t *tok);

extern void groth_generate_signature_1(element_t secret_key, credential_attributes *ca, credential_element_t *ic);

extern int groth_verify_signature_1(element_t public_key, credential_attributes *ca, credential_element_t *ic);

extern void groth_generate_signature_2(element_t secret_key, credential_attributes *ca, credential_element_t *ic);

extern int groth_verify_signature_2(element_t public_key, credential_attributes *ca, credential_element_t *ic);

extern void SHA1(char *hash, unsigned char * str1);

extern void mylog(FILE *logfp, char *fmt, ...);
extern void mysend(int sockfd, const char *msg, int length, int flags, char *sid, FILE *logfp);

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <mcl/bn_c384_256.h>

#define SUCCESS 0
#define FAILURE 1
#define N 3

#define HOME_DIR "/home/users/sandeep/dac/dac"
#define PARAM_FILE HOME_DIR "/root/params.txt"
#define SERVICES_FILE HOME_DIR "/root/services.txt"
#define REVOKED_FILE HOME_DIR "/root/revoked.txt"

//#define HOME_DIR "/root/dac"
#define MAX_NUM_ATTRIBUTES 50
#define TOTAL_ATTRIBUTES (MAX_NUM_ATTRIBUTES + 1) //cpk(i-1) + MAX_NUM_ATTRIBUTES attributes

#define CONTROLLER_SVC "controller"

#define SID_LENGTH 10
#define SERVICE_LENGTH 15
#define USER_LENGTH 10

#define element_init_G1(x,y) huremi_element_init_G1(x)
#define element_init_G2(x,y) huremi_element_init_G2(x)
#define element_init_GT(x,y) huremi_element_init_GT(x)
#define element_init_Zr(x,y) huremi_element_init_Zr(x)
#define pairing_apply(w,x,y,z) huremi_pairing_apply(w,x,y)

typedef enum element
{
    ELEMENT_FR = 1,
    ELEMENT_G1,
    ELEMENT_G2,
    ELEMENT_GT
}element_type;

typedef struct element_s
{
    element_type t;
    union 
    {
        mclBnG1 g1;
	mclBnG2 g2;
	mclBnGT gt;
	mclBnFr fr;
    }e;
}element_s;
typedef struct element_s element_t[1];

typedef struct attributes
{
    element_t *attributes;     //attributes[0] represents the public key
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

extern void generate_attribute_token(token_t *tok, credential_t *ic, char **revealed);

extern int verify_attribute_token(token_t *tok);

extern int is_credential_valid(element_t user_cpk_r, element_t user_g2t_r);

extern void read_revoked_G1T_G2T(element_t g1t, element_t g2t);

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

extern char *rand_string(char *str, size_t size);

extern void huremi_element_init_G1(element_t e);
extern void huremi_element_init_G2(element_t e);
extern void huremi_element_init_GT(element_t e);
extern void huremi_element_init_Zr(element_t e);
extern void huremi_pairing_apply(element_t res, element_t a, element_t b);
extern void element_random(element_t e);
extern void element_pow_zn(element_t res, element_t a, element_t b);
extern void element_clear(element_t a);
extern int element_cmp(element_t a, element_t b);
extern void element_mul(element_t res, element_t a, element_t b);
extern void element_invert(element_t res, element_t a);
extern void element_set(element_t dest, element_t src);
extern void element_init_same_as(element_t dest, element_t src);
extern void element_neg(element_t dest, element_t src);
extern int element_serialize(element_t a, char *buf, int buf_size);
extern void element_deserialize(element_t a, char *buf, int len);
extern void element_add(element_t res, element_t a, element_t b);
extern void element_getstr(char *buf, int size, element_t e);
extern void element_from_hash(element_t e, char *buf, int len);
extern void element_printf(char* format,...);

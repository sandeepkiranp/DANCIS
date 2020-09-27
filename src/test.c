#include <stdio.h>
#include <pbc/pbc.h>
char *base64_encode(const unsigned char *data,
                    size_t input_length,
                    size_t *output_length) ;
unsigned char *base64_decode(const char *data,
                             size_t input_length,
                             size_t *output_length) ;
pairing_t pairing;

void func(element_t y)
{
        element_t x;
	element_init_G1(x, pairing);
	//element_init_G1(y, pairing);
	element_init_same_as(y,x);
	element_random(x);
	element_printf("in func x = %B\n", x);
	element_set(y,x);
}

main()
{
    element_t g, h;
    element_t a, b;
    element_t temp1, temp2;
    element_t x;
    char param[4096];
    char buffer[4096] = {0};
    size_t size = 4096;
    int outlen;
    char *base64e;
    char *base64d;

    size_t count = fread(param, 1, 4096, stdin);
    if (!count) pbc_die("input error");

    pairing_init_set_buf(pairing, param, count);    

//    func(x);
//    element_printf("In main x = %B\n", x);
    element_init_G1(a, pairing);
    element_init_G1(b, pairing);

    element_init_GT(temp1, pairing);
    element_init_GT(temp2, pairing);

    element_random(a);
    element_random(b);

    pairing_apply(temp1, a, b, pairing);
    element_printf("temp1 = %B\n", temp1);

    element_set1(b);

    pairing_apply(temp1, a, b, pairing);
    element_printf("temp1 = %B\n", temp1);

    element_set1(a);
    element_random(b);

    pairing_apply(temp1, a, b, pairing);
    element_printf("temp1 = %B\n", temp1);

    element_random(a);
    element_random(b);

    pairing_apply(temp1, a, b, pairing);
    element_printf("temp1 = %B\n", temp1);
/*    
    printf("Length = %d, Compressed Length = %d\n", element_length_in_bytes(a), element_length_in_bytes_compressed(a));

    element_to_bytes_compressed(buffer, a);
    base64e = base64_encode(buffer, element_length_in_bytes_compressed(a), &outlen);
    printf("Compressed base64 element = %s\n", base64e);

    base64d = base64_decode(base64e, outlen, &outlen);
    element_from_bytes_compressed(b, base64d);

    if (!element_cmp(a, b)) {
        printf("signature verifies\n");
    } else {
        printf("signature does not verify\n");
    }
*/
/*
    element_snprintf(buffer,size,"%B",a);
    printf("A = %s, len = %d\n", buffer, size);
    printf("strlen = %d\n", strlen(buffer));
    element_snprintf(buffer,size,"%B",b);
    printf("A = %s, len = %d\n", buffer, size);
    printf("strlen = %d\n", strlen(buffer));

    pairing_apply(temp1, a, b, pairing);
    pairing_apply(temp2, a, b, pairing);

    element_printf("temp1 = %B\n", temp1);
    element_printf("temp2 = %B\n", temp2);

    if (!element_cmp(temp1, temp2)) {
        printf("signature verifies\n");
    } else {
        printf("signature does not verify\n");
    }    
*/    
}    

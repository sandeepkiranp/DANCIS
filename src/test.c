#include <stdio.h>
#include <pbc/pbc.h>

main()
{
    pairing_t pairing;
    element_t g, h;
    element_t a, b;
    element_t temp1, temp2;
    char param[4096];
    char buffer[4096] = {0};
    size_t size = 4096;

    size_t count = fread(param, 1, 4096, stdin);
    if (!count) pbc_die("input error");

    pairing_init_set_buf(pairing, param, count);    

    element_init_G1(a, pairing);
    element_init_G2(b, pairing);

    element_init_GT(temp1, pairing);
    element_init_GT(temp2, pairing);

    element_random(a);
    element_random(b);
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
}    

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
main()
{
    char str[] = "Ab96+dDROA8moCYPonPyz/TwACyKIJ76wc/6KbwbwxaCVFQMI2+ju8cm2NijXVuUbSjvcs648EbdTTiu9y6VEJWey7BOOLd+g/gDpPH95NoipdnS/CBqpin7MM6/p6/lRzJrkwWV5r3uk0ndiddrUwMnAAcMQpgS3ydTe4b2ld4=";

    int i, j, start, end, temp;
    srand(time(0));

    printf("Original %s\n", str);
    for (j=0; j < 100000; j++)
    {
        for(i = 0; i < strlen(str); i++)
        {
            start = rand() % strlen(str);
    	    end = rand() % strlen(str);
	    temp = str[start];
	    str[start] = str[end];
	    str[end] = temp;
        }
        printf("%s\n", str);
    }
}
	

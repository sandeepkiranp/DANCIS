#include <stdio.h>
#include <string.h> 
#include <sys/time.h>
int main(int argc, char *argv[])
{
        int pos, ret;
	int end, start=0, found=0, intend = 0;
        char *line = NULL;
        size_t len = 0;
        ssize_t read;
	char *instr = argv[1];
struct timeval tstop, tstart;

gettimeofday(&tstart, NULL);

        FILE *fp = fopen("b.txt", "r");
 
        /* Position the stream to the end of fyle and get the byte offset. */
        fseek(fp, 0, SEEK_END);
        end = pos = ftell(fp);
 
	while(1)
	{
	    if(start >= end)
	    {
		break;
	    }

            pos = (start + end)/2;
            //printf("start - %d, end - %d, pos - %d\n", start, end, pos);

	    if(pos)
	    {
                fseek(fp, pos -1, SEEK_SET);

	        if (fgetc(fp) == '\n')
	        {
	        }
	        else
	        {
                    while(1)
		    {
                        if(fgetc(fp) == '\n')
                            break;
		    }
	        }
	    }
	    else //first line
                fseek(fp, 0, SEEK_SET);

            read = getline(&line, &len, fp);
	    line[read - 1] = 0;
	    //printf("Line %s\n", line);
	    ret = strcmp(instr, line);
	    if (ret == 0)
	    {
		found = 1;
	        break;
	    }
	    if (ret > 0)
		start = ftell(fp);
	    else
	        end = pos;
        }
	if(found)
	    printf("Found string\n");
	else
	    printf("Cannot find string\n");

gettimeofday(&tstop, NULL);
printf("took %lu us\n", (tstop.tv_sec - tstart.tv_sec) * 1000000 + tstop.tv_usec - tstart.tv_usec);
        return 0;
}

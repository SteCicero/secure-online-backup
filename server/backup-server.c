#include <string.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/in.h>
#include "../utility.h"
#define NUM_HANDLER_THREADS 2

void* print(void* tid)
{
    int id=(int)tid;
    printf("I'm thread %d\n", id);
    pthread_exit(NULL);
}


int main (int argc, const char * argv[]) 
{
	char ip[15];
	int i;
	int thr_id[NUM_HANDLER_THREADS];
	pthread_t p_threads[NUM_HANDLER_THREADS];
	
	printf("SOBS: Secure Online Backup Server\n");
	struct sockaddr_in my_addr, cl_addr;
	int ret,sk,cn_sk;
	socklen_t len;
	
	sk=socket(PF_INET,SOCK_STREAM,0);
	memset(&my_addr,0,sizeof(my_addr));
	my_addr.sin_family=AF_INET;
	my_addr.sin_addr.s_addr=htonl(INADDR_ANY);
	my_addr.sin_port=htons(atol(argv[1]));
	
	ret=bind(sk,(struct sockaddr*)&my_addr,sizeof(my_addr));
	ret=listen(sk,10);
	
	for(i=0;i<NUM_HANDLER_THREADS;i++)				//creo i threads
	{
		thr_id[i]=i;
		pthread_create(&p_threads[i],NULL,handle_request_loop,(void*)&thr_id[i]);
	}
	
	while(1)
	{
		printf("In attesa di connessioni\n");
	
		len=sizeof(cl_addr);
		cn_sk=accept(sk,(struct sockaddr*) &cl_addr,&len);
		
		strcpy(ip,inet_ntoa(cl_addr.sin_addr));
		printf("CLIENT %s connesso sulla porta %s\n",ip,argv[1]);
		
		add_request(cn_sk,ip,&request_mutex,&got_request);
	}
	return 0;
}


#include <pthread.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/in.h>
#include "../utility.h"


int main (int argc, const char * argv[]) 
{
	printf("SOBC: Secure Online Backup Client\n");
	struct sockaddr_in srv_addr;
	int ret,sk;
	char choice;
	
	if(strlen(argv[1])>15 || strlen(argv[2])>5)		//prevenzione buffer overflow
	{
		printf("Parametri formalmente invalidi\n");
		return(1);	
	}
	
	sk=socket(PF_INET,SOCK_STREAM,0);				//Inizializzo il socket
	memset(&srv_addr,0,sizeof(srv_addr));
	srv_addr.sin_family=AF_INET;
	srv_addr.sin_port=htons((int)atol(argv[2]));
	ret=inet_pton(AF_INET,argv[1],&srv_addr.sin_addr);
	
	ret=connect(sk,(struct sockaddr*) &srv_addr,sizeof(srv_addr));
    
    if(ret==0)										//Controllo connessione
    {
    	printf("Connesso al server\n");	
    }
    else
    {
    	printf("Impossibile connettersi al server, termino\n");
    	return 1;	
    }
	char user[10];
	char pass[10];
	
	printf("Cerco di stabilire un canale sicuro con il server\n");
	
	const int n_size=4;							//dimensione nonce
	int i;
	unsigned char *na=malloc(n_size*sizeof(char));
	unsigned char *nb=malloc(n_size*sizeof(char));
	unsigned int *nai=(unsigned int*)na;
	unsigned int *nbi=(unsigned int*)nb;
	printf("Nonce del client: ");
	RAND_bytes(na,n_size);
	for(i=0;i<n_size;i++)
	{
		printbyte(na[i]);
	}
	printf("\n");
	
	char *key;
	key=malloc((EVP_DES_ECB) * sizeof(char));
	inviaChiaveSim(sk,key,na);					//invio chiave simmetrica e nonce
	
	printf("Canale sicuro stabilito con chiave simmetrica: ");
	for(i=0;i<EVP_DES_ECB;i++)
	{
		printbyte(key[i]);
	}
	printf("\n");
	
	unsigned char *data=riceviMessaggio(sk,key);
    if(((unsigned int*)data)[0]==nai[0]+1)
	{
		printf("Nonce correttamente incrementato dal server\n");	
	}
	else
	{
		printf("Nonce NON correttamente incrementato dal server\n");
		return 1;
	}
	
	memcpy(nb,data+n_size,n_size);
	printf("Nonce del server: ");
	
	for(i=0;i<n_size;i++)
	{
		printbyte(nb[i]);
	}
	printf("\n");
	
	nbi[0]++;
	
	user[0]='\0';				//inizializzo la lunghezza delle stringhe
	pass[0]='\0';
	
	while(strlen(user)<4)
	{
		printf("\nUtente: ");
    	scanf("%9s",user);						//scanf con limite contro buffer overflow
    	if(strlen(user)<4)
    	{
    		printf("Il nome utente deve essere compreso tra 4 e 9 caratteri\n");	
    	}
	}
	
	while(strlen(pass)<4)
	{
		printf("\nPassword: ");
    	scanf("%9s",pass);						//scanf con limite contro buffer overflow
    	if(strlen(pass)<4)
    	{
    		printf("La password deve essere compresa tra 4 e 9 caratteri\n");	
    	}
	}
	
	free(data);
	
	char *size_up=malloc(2*sizeof(char));
	int data_size=(2+strlen(user)+strlen(pass)+n_size)*sizeof(char);
		
	sprintf(size_up, "%i",(int)strlen(user));
	sprintf(size_up+1, "%i",(int)strlen(pass));
	
	data=malloc((2+strlen(user)+strlen(pass)+n_size)*sizeof(char));
	memcpy(data,size_up,2*sizeof(char));
	memcpy(data+(2*sizeof(char)),user,strlen(user)*sizeof(char));
	memcpy(data+((2+strlen(user))*sizeof(char)),pass,strlen(pass)*sizeof(char));
	memcpy(data+(2*sizeof(char))+((strlen(user)+strlen(pass))*sizeof(char)),nb,n_size);
	
	inviaMessaggio(sk,data,data_size,key);
	free(data);
  
  	data=riceviMessaggio(sk,key);
  	if(strncmp(data,"OK",2)==0)
  	{
  		printf("Autenticazione col server avvenuta con successo\n");
  		free(data);	
  	}
  	else
  	{
  		printf("Autenticazione col server fallita, termino\n");
  		close(sk);
  		return 1;	
  	}
  	
    for(;;)											//Menù di selezione
    {
    	printf("\nMENU' DI SELEZIONE:\n");
    	printf("1. Carica un nuovo file\n");
    	printf("2. Visualizza l'elenco dei file caricati\n");
    	printf("3. Scarica un file\n");
    	printf("4. Rimuovi un file\n");
    	printf("5. Rimuovi tutti i file\n");
    	printf("6. Esci da SOBC\n");
    	printf("Inserisci il numero corrispondente alla scelta effettuata\n");
    	printf("backup-online-client> ");
 		scanf("%1s",&choice);
 		
 		if(choice=='1')
 		{
 			int i;
 			int s=0;
 			char percorso[101];
 			struct stat info;
 			char csize[33];
			int size;
			const int buf_size=4096;
			
 			printf("Carica un nuovo file\n");
 			printf("Inserisci il percorso del file da caricare (max 100 caratteri): ");
 			scanf("%100s",percorso);
 			
 			for(i=0;i<strlen(percorso);i++)
 			{
 				if(percorso[i]=='/')
 				{
 					s=i;	
 				}	
 			}
 			
 			FILE *fp;
			fp=fopen(percorso,"r");
			if(fp==NULL)
			{
				printf("Impossibile leggere il file\n");
				continue;
			}
			
 			data_size=(strlen(percorso)-s)+2;
 			data=malloc(data_size*sizeof(char));
 			memcpy(data,"1",1);
 			if(s==0)
 			{
 				memcpy(data+1,percorso,data_size-1);
 			}
 			else
 			{
 				memcpy(data+1,percorso+s+1,data_size-1);
 			}
 			memcpy(data+data_size-1,"\0",sizeof(char));
 			inviaMessaggio(sk,data,data_size,key);		//invio nome file
 			free(data);
 			
			stat(percorso,&info);
			size=info.st_size;							//grandezza del file in byte
			sprintf(csize,"%d",size);

			data_size=sizeof(char)*33;
			data=malloc(data_size);
			memcpy(data,csize,data_size);
			inviaMessaggio(sk,data,data_size,key);		//invio grandezza del file
			free(data);
			
			data_size=sizeof(char)*buf_size;
			data=malloc(data_size);
			printf("%s %d %d %d\n",percorso,size,size/buf_size,size%buf_size);
			for(i=0;i<(size/buf_size);i++)
			{
				if(fread(data,1,buf_size,fp)<buf_size)
				{
					printf("\n Errore nella lettura del file \n");
					close(sk);
	  				return 1;	
				}
				inviaMessaggio(sk,data,data_size,key);
			}
			if((size%buf_size)>0)
			{
				if(fread(data,1,size%buf_size,fp)<(size%buf_size))
				{
					printf("\n Errore nella lettura del file \n");
					close(sk);
	  				return 1;	
				}
				inviaMessaggio(sk,data,size%buf_size,key);	
			}
			fclose(fp);
			free(data);
 			continue;
 		}
 		
 		if(choice=='2')
 		{
 			printf("Elenco file caricati\n");
 			data=malloc(sizeof(char));
 			memcpy(data,"2",1);
 			inviaMessaggio(sk,data,1,key);
 			free(data);
 			data=riceviMessaggio(sk,key);
 			int file_size=atoi(data);
 			const int buf_size=4096;
 			
 			free(data);
			for(i=0;i<(file_size/buf_size);i++)
			{
				data=riceviMessaggio(sk,key);
    			printf("%s",data);
   				free(data);	
			}
			if((file_size%buf_size)>0)
			{
				data=riceviMessaggio(sk,key);
    			printf("%s",data);
   				free(data);	
			} 			
 			continue;
 		}
 		
 		if(choice=='3')
 		{
 			char file_name[101];
 			printf("Scarica un file\n");
 			printf("Inserisci il nome del file da scaricare (max 100 caratteri): ");
 			scanf("%100s",file_name);
 			int data_size=strlen(file_name)+2;
 			data=malloc(data_size*sizeof(char));
 			memcpy(data,"3",1);
 			memcpy(data+1,file_name,data_size-1);
 			memcpy(data+data_size-1,"\0",sizeof(char));
 			inviaMessaggio(sk,data,data_size,key);
 			
 			free(data);
 			if(strncmp(riceviMessaggio(sk,key),"KO",2)==0)
 			{
 				printf("File non trovato\n");
 				continue;	
 			}

			const int buf_size=4096;
			int file_size=atoi(riceviMessaggio(sk,key));
			FILE* fp;
			fp=fopen(file_name,"w");
			
			for(i=0;i<(file_size/buf_size);i++)
			{
				data=riceviMessaggio(sk,key);
    			if(fwrite(data,1,buf_size,fp)<buf_size) 
    			{
					printf("\n Errore nella scrittura del file \n");
					close(sk);
					return;
   				}
   				free(data);	
			}
			if((file_size%buf_size)>0)
			{
				data=riceviMessaggio(sk,key);
    			if(fwrite(data,1,file_size%buf_size,fp)<(file_size%buf_size)) 
    			{
					printf("\n Errore nella scrittura del file \n");
					close(sk);
					return;
   				}
   				free(data);	
			}
			fclose(fp);
			 			
 			continue;
 		}
 		
 		if(choice=='4')
 		{
 			char file_name[101];
 			printf("Rimuovi un file\n");
 			printf("Inserisci il nome del file da rimuovere (max 100 caratteri): ");
 			scanf("%100s",file_name);
 			data=malloc(sizeof(char)*(strlen(file_name)+3));
 			
 			memcpy(data,"4",1);
 			memcpy(data+1,file_name,strlen(file_name)+1);
 			inviaMessaggio(sk,data,strlen(file_name)+3,key);
 			
 			if(strncmp(riceviMessaggio(sk,key),"OK",2)==0)
 			{
 				printf("File rimosso\n");	
 			}
 			else
 			{
 				printf("File non trovato\n");	
 			}
 			
 			continue;
 		}
 		
 		if(choice=='5')
 		{
 			data=malloc(sizeof(char));
 			memcpy(data,"5",1);
 			inviaMessaggio(sk,data,1,key);
 			free(data);
 			if(strncmp(riceviMessaggio(sk,key),"OK",2)==0)
 			{
 				printf("Tutti file caricati sono stati rimossi\n");	
 			}
 			else
 			{
 				printf("Si è verificato un errore durante la rimozione dei file\n");	
 			}
 			continue; 		
 		}
 		
 		if(choice=='6')
 		{
 			data=malloc(sizeof(char));
 			memcpy(data,"6",1);
 			inviaMessaggio(sk,data,1,key); 			
 			printf("Termino\n");
 			close(sk);
 			return 0;
 		}
 		else
 		{
    		printf("Valore inserito non valido\n");
 		}
    }
}


#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#define EVP_DES_ECB EVP_CIPHER_key_length(EVP_des_ecb())
#define EVP_DES_CBC EVP_CIPHER_key_length(EVP_des_cbc())



//INIZIO SEZIONE FUNZIONI PER LA CIFRATURA

void printbyte(char b) 
{
  	char c;

  	c = b;
  	c = c >> 4;
  	c = c & 15;
  	printf("%X", c);
  	c = b;
  	c = c & 15;
  	printf("%X:", c);
}

void select_random_key(char *k, int b) 
{
  	int i;
  	RAND_bytes(k, b);
  	/*for (i = 0; i < b - 1; i++)
    	printbyte(k[i]);
  	printbyte(k[b-1]);
  	printf("\n");*/
}

int create_enc_context(EVP_CIPHER_CTX *ctx, int* block_size,char *key)
{
	int key_size;

	EVP_CIPHER_CTX_init(ctx);

	EVP_EncryptInit(ctx, EVP_des_ecb(),NULL, NULL);

	key_size = EVP_CIPHER_CTX_key_length(ctx);

	int i;
	printf("Chiave di sessione per cifratura: ");
	for(i=0;i<key_size;i++)
	{
		printbyte(key[i]);
	}
	printf("\n");

	EVP_CIPHER_CTX_set_key_length(ctx, key_size);
	EVP_EncryptInit(ctx, NULL, (unsigned char*) key, NULL);

	*block_size=EVP_CIPHER_CTX_block_size(ctx);

	//free(key);
	return 0;
}

int m_encrypt(EVP_CIPHER_CTX *ctx, const char* buffer, const int size, char* enc_buffer, int* ct_size)
{
	int nc,nctot,i,ct_ptr,msg_ptr,n;
	n=10;
	nc=0;
	nctot=0;
	ct_ptr=0;
	msg_ptr=0;

	EVP_EncryptUpdate(ctx, enc_buffer, &nc, buffer, size);
	ct_ptr += nc;
	nctot += nc;

	EVP_EncryptFinal(ctx, &enc_buffer[ct_ptr], &nc);
	nctot += nc;

	*ct_size=nctot;

	return 0;
}

int create_dec_context(EVP_CIPHER_CTX *ctx, int* block_size, char *key)
{
	int key_size;

	EVP_CIPHER_CTX_init(ctx);

	EVP_EncryptInit(ctx, EVP_des_ecb(),NULL, NULL);

	key_size = EVP_CIPHER_CTX_key_length(ctx);
	
	int i;
	printf("Chiave di sessione per decifratura: ");
	for(i=0;i<key_size;i++)
	{
		printbyte(key[i]);
	}
	printf("\n");

	EVP_CIPHER_CTX_set_key_length(ctx, key_size);
	EVP_DecryptInit(ctx, NULL, (unsigned char*) key, NULL);

	*block_size=EVP_CIPHER_CTX_block_size(ctx);

	return 0;
}

int decrypt(EVP_CIPHER_CTX *ctx, char* buffer,char* dec_buffer,int dec_buffer_size,int* ct_size)
{
	int nd,ndtot,i,ct_ptr,msg_ptr,n;
	n=10;
	nd=0;
	ndtot=0;
	ct_ptr=0;
	msg_ptr=0;

	EVP_DecryptUpdate(ctx,buffer,&nd,dec_buffer,dec_buffer_size);
	ct_ptr += nd;
	ndtot += nd;
	
	EVP_DecryptFinal(ctx, &buffer[ct_ptr],&nd);
	ndtot += nd;
	
	*ct_size=ndtot;

	return 0;
}

int inviaChiaveSim(int sk,char *des_key,unsigned char *na)
{
	FILE *fp;
	char *des_key_crypt;								//chiave des criptata
	struct stat info;
	int ret,srsa;										//srsa dimensione chiave des criptata con rsa
	unsigned char *des_key_nonce;
	fp=fopen("pub.pem","r");
	
	RSA *rsa = RSA_new();								//allocazione del contesto	
	rsa = PEM_read_RSAPublicKey(fp,&rsa,NULL,NULL);		//lettura della chiave pubblica
	fclose(fp);

	int key_size = EVP_DES_ECB;
	select_random_key(des_key, key_size);
	
	//inserisco nonce in coda alla chiave des
	des_key_nonce=malloc((EVP_DES_ECB + strlen(na))*sizeof(char));		
	memcpy(des_key_nonce,des_key,EVP_DES_ECB);
	memcpy(des_key_nonce+EVP_DES_ECB,na,strlen(na));
		
	des_key_crypt=malloc(RSA_size(rsa)*sizeof(char));
	
	//cifratura con chiave pubblica
	RSA_public_encrypt(EVP_DES_ECB+strlen(na),des_key_nonce,des_key_crypt,rsa,RSA_PKCS1_PADDING);	
	srsa=RSA_size(rsa);
	ret=send(sk,&srsa,sizeof(int),0);
	ret=send(sk,des_key_crypt,srsa,0);
	
	return 0;
}

int riceviChiaveSim(int sk,char *des_key,unsigned char *na)
{
	int srsa;						//dimensione dati criptati con rsa
	int sdes;						//dimensione dati in chiaro
	char *des_key_crypt;
	char *des_key_temp;
	int i;
	FILE *fp;
	recv(sk,&srsa,sizeof(int),MSG_WAITALL);			//ricezione dimensione chiave des criptata
	des_key_crypt=malloc(srsa * sizeof(char));
	recv(sk,des_key_crypt,srsa,MSG_WAITALL);		//ricezione chiave des criptata

	RSA *rsa=RSA_new();								//allocazione del contesto
	OpenSSL_add_all_algorithms();
	
	fp=fopen("priv.pem","r");
	rsa=PEM_read_RSAPrivateKey(fp,&rsa,NULL,"password");	//lettura chiave privata
	des_key_temp=malloc(srsa * sizeof(char));

	sdes=RSA_private_decrypt(srsa,des_key_crypt,des_key_temp,rsa,RSA_PKCS1_PADDING);	//decifratura chiave des con rsa
	memcpy(des_key,des_key_temp,sdes-4);
	
	memcpy(na,des_key_temp+sdes-4,4);

	RSA_free(rsa);						//deallocazione del contesto
	fclose(fp);
	return 0;
}



//FINE SEZIONE FUNZIONI PER LA CRITTOGRAFIA

char* riceviMessaggio(int sk,char* key)				//ottiene un messaggio cifrato, lo decifra e lo restituisce
{
	int ret;
    int size;			// dimensione del buffer per il testo in chiaro
    char* buffer;		// buffer per il testo in chiaro
    unsigned char* dec_buffer;	// buffer per il testo cifrato ricevuto
    int dec_buffer_size;	// dimensione del buffer per il testo cifrato ricevuto
    int block_size;		// dimensione del blocco
    int ct_size; 		// dimensione del testo in chiaro
	
    EVP_CIPHER_CTX *ctx; 	// contesto
 
    /* Ricezione della dimensione del messaggio */
    ret = recv(sk, &dec_buffer_size, sizeof(dec_buffer_size), MSG_WAITALL);
    if(ret != sizeof(dec_buffer_size)) {
      printf("\n Errore nel ricevere la dimensione del file\n");
      return "1";
    }
 
    /* Allocazione della memoria */
    dec_buffer = malloc(dec_buffer_size * sizeof(char));
    if(dec_buffer == NULL){
      printf("\n Errore nell'allocazione di memoria\n");
      return "1";
    }

    /* Ricezione del messaggio */
    ret = recv(sk, dec_buffer, dec_buffer_size, MSG_WAITALL);
    if(ret != dec_buffer_size) {
      printf("\n Errore nel ricevere il file\n");
      return "1";
    }
       
    /* allocazione del contesto */
    ctx = malloc(sizeof(EVP_CIPHER_CTX));
       
    if (create_dec_context(ctx, &block_size,key)) 
    {
		printf("Errore creazione contesto\n");
		return "1";
    }
	
    /* allocazione del buffer per il testo cifrato */
    size = dec_buffer_size + block_size;
   
    buffer = malloc(size * sizeof (char));
    if (buffer == NULL) 
    {
		printf("Errore allocazione buffer\n");
		return "1";
    }

    /* decifratura */
    decrypt(ctx, buffer, dec_buffer, dec_buffer_size, &ct_size);
   
    /* deallocazione contesto */
    EVP_CIPHER_CTX_cleanup(ctx);
    free(ctx);

    free(dec_buffer);
	
    return buffer;
}

int inviaMessaggio(int sk,unsigned char msg[],int size,char* key)		//prende il dato, lo cifra e lo invia
{
	int ret, i; 			
	unsigned char* enc_buffer;	// buffer per il testo cifrato
	int enc_buffer_size;		// dimensione del buffer per il testo cifrato
	int block_size;			// dimensione del blocco
	EVP_CIPHER_CTX *ctx; 		// contesto
	int ct_size;			// dimensione del testo cifrato
	
	/* allocazione del contesto */
	ctx = malloc(sizeof(EVP_CIPHER_CTX));
	
	if (create_enc_context(ctx, &block_size,key)) {
	    printf("Errore creazione contesto\n");
	    return 1;
	}
	
	/* allocazione del buffer per ciphertext */
	enc_buffer_size = size + block_size;
	
	enc_buffer = malloc(enc_buffer_size * sizeof (char));
	if (enc_buffer == NULL) {
	  printf("Errore allocazione buffer\n");
	  return 1;
	}
	
	/* cifratura del file */
	m_encrypt(ctx, msg, size, enc_buffer, &ct_size);
	
	/* deallocazione contesto */
	EVP_CIPHER_CTX_cleanup(ctx);
	free(ctx);
	
	/* Invio della dimesione del file */
	ret = send(sk, &ct_size, sizeof(ct_size), 0);
	  if(ret != sizeof(ct_size)){
	  printf("\n Errore nella trasmissione della dimensione del file\n ");
	  return 1;
	}

	/* Invio del file */
	ret = send(sk, enc_buffer, ct_size, 0);
	if(ret < ct_size){
	  printf("\n Errore nella trasmissione del file \n");
	  return 1;
	}
	
	//free(buffer);
	free(enc_buffer);
    
	return 0;
}

int account_check(char user[],char pass[])
{
	FILE* file;			// puntatore al file degli account
	char *buff1=malloc(11*sizeof(char));
	char *buff2=malloc(11*sizeof(char));
	
	file = fopen("accounts","r");
	if(file == NULL) 
	{
	  printf("\nErrore durante l'apertura del file\n");
	  return 1;
	}
	while(!feof(file))
    {
        fgets(buff1,10,file);
        buff1[strlen(buff1)-1]='\0';
        if(strcmp(buff1,user)==0)
        {
        	fgets(buff2,11,file);
        	buff2[strlen(buff2)-1]='\0';
        	if(strcmp(buff2,pass)==0)
        	{
        		fclose(file);
        		free(buff1);
        		free(buff2);
        		return 0;
        	}
        }
    }
    fclose(file);
    free(buff1);
    free(buff2);
	return 1;	
}

int file_checkrm(char *user,char *file_name)
{
	char *buff1=malloc(101*sizeof(char));
	char cmd[30];
	strcpy(cmd,"ls ");
	strcat(cmd,user);
	strcat(cmd," > ls");
	strcat(cmd,user);
	system(cmd);
	
	FILE *fp;
	fp = fopen(cmd+6+strlen(user),"r");
	if(fp == NULL) 
	{
	  printf("\nErrore durante l'apertura del file\n");
	  return 1;
	}
	
	while(!feof(fp))
    {
        fgets(buff1,101,fp);
        if(strncmp(buff1,file_name,strlen(file_name))==0)
        {
        	strcpy(cmd,"rm ");
        	strcpy(cmd+3,user);
        	strcpy(cmd+3+strlen(user),"/");
        	strcpy(cmd+4+strlen(user),file_name);
        	printf("Comando: %s\n",cmd);
        	system(cmd);
        	fclose(fp);
        	free(buff1);
        	return 0;
        }
    }
    fclose(fp);
    return 1;
}




//INIZIO SEZIONE DATI E METODI PER THREAD



//semaforo globale inizializzato
pthread_mutex_t request_mutex=PTHREAD_MUTEX_INITIALIZER;


//variabile condition globale
pthread_cond_t got_request=PTHREAD_COND_INITIALIZER;

int num_requests=0; //numero delle richieste pendenti

struct request		//struttura di una richiesta
{
	int socket;
	char ip[15];
	struct request* next;
};

struct request* list_requests=NULL;			//prima richiesta
struct request* last_request=NULL;			//ultima richiesta

void add_request(int request_num,char ip[],pthread_mutex_t* p_mutex,pthread_cond_t* p_cond_var)
{
	int rc;
	struct request* a_request;
	a_request=(struct request*)malloc(sizeof(struct request));
	if(!a_request)
	{
		printf("Errore\n");
		exit(1);	
	}
	a_request->socket=request_num;
	strcpy(a_request->ip,ip);
	a_request->next=NULL;
	
	//blocco il semaforo per assicurarmi accesso atomico alla lista
	rc=pthread_mutex_lock(p_mutex);
	
	if(num_requests==0)
	{
		list_requests=a_request;
		last_request=a_request;
	}
	else
	{
		last_request->next=a_request;
		last_request=a_request;
	}
	num_requests++;
	
	//sblocco il semaforo
	rc=pthread_mutex_unlock(p_mutex);
	
	//invio segnale alla variabile condition - c'è una nuova richiesta da gestire
	rc=pthread_cond_signal(p_cond_var);
}

struct request* get_request(pthread_mutex_t* p_mutex)
{
	int rc;
	struct request* a_request;
	
	rc=pthread_mutex_lock(p_mutex);
	
	if(num_requests>0)
	{
		a_request=list_requests;
		list_requests=a_request->next;
		if(list_requests==NULL)
		{
			last_request=NULL;
		}
		num_requests--;
	}
	else
	{
		a_request=NULL;
	}
	
	rc=pthread_mutex_unlock(p_mutex);
	return a_request;
}

void handle_request(struct request* a_request,int thread_id)
{	
	if(a_request)
	{
		printf("Thread %d sta gestendo la richiesta del client %s\n",thread_id,a_request->ip);
	}
	
	printf("Thread %d cerca di stabilire un canale sicuro con il client\n",thread_id);
	const int n_size=4;							//dimensione nonce
	unsigned char *na=malloc(n_size*sizeof(char));
	unsigned char *nb=malloc(n_size*sizeof(char));	
	char *key;
	int i;
	key=malloc((EVP_DES_ECB) * sizeof(char));
	riceviChiaveSim(a_request->socket,key,na);
	RAND_bytes(nb,n_size);
			
	printf("Nonce del client: ");
	for(i=0;i<n_size;i++)
	{
		printbyte(na[i]);
	}
		
	printf("\nNonce del server: ");
	for(i=0;i<n_size;i++)
	{
		printbyte(nb[i]);
	}
	
	printf("\nCanale sicuro stabilito con chiave simmetrica: ");
	for(i=0;i<EVP_DES_ECB;i++)
	{
		printbyte(key[i]);
	}
	printf("\n Invio nonce di risposta\n");
		
	unsigned int *nai=(unsigned int*)na;
	unsigned int *nbi=(unsigned int*)nb;
	nai[0]++;
	unsigned char* data=malloc(n_size*2*sizeof(char));
	if(data==NULL)
	{
		printf("\nErrore nell'allocazione di memoria\n");
		return;
	}
	memcpy(data,na,n_size);
	memcpy(data+n_size,nb,n_size);
		
	inviaMessaggio(a_request->socket,data,n_size*2,key);		//invio nonce_client+1 e nonce_server
	free(data);
	data=riceviMessaggio(a_request->socket,key);				//ricevo dimensione user e pass
																//user e pass e nonce_server+1
	int u_size,p_size;
	u_size=(int)(data[0]-'0');
	p_size=(int)(data[1]-'0');
	char user[u_size+1];
	char pass[p_size+1];
		
	memcpy(user,data+2,u_size);
	memcpy(pass,data+2+u_size,p_size);
	user[u_size]='\0';
	pass[p_size]='\0';
	printf("%s %s %d %d\n",user,pass,u_size,p_size);
		
	if(((unsigned int*)(data+2+u_size+p_size))[0]==nbi[0]+1)
	{
		printf("Nonce correttamente incrementato dal client\n");	
	}
	else
	{
		printf("Nonce NON correttamente incrementato dal client\n");
		return;
	}
		
	if(account_check(user,pass)==0)
	{
		char smkdir[20];
		strcpy(smkdir,"mkdir ");
		printf("Utente e password del client corretti\n");
		inviaMessaggio(a_request->socket,"OK",2,key);
		printf("%s\n",user);
		system(strcat(smkdir,user));
		printf("%s\n",smkdir);
		free(data);	
	}
	else
	{
		printf("Credenziali del client errate, chiudo la connessione.\n");
		inviaMessaggio(a_request->socket,"KO",2,key);
		close(a_request->socket);
		return;	
	}
	
	while(1)
	{	
		data=riceviMessaggio(a_request->socket,key);
		
		if(data[0]=='1')
		{
			int file_size;
			char file_name[strlen(data+1)];
			memcpy(file_name,data+1,sizeof(char)*(strlen(data+1)+1));
			const int buf_size=4096;
			char percorso[110];
			strncpy(percorso,user,u_size);
			percorso[u_size]='/';
			percorso[u_size+1]='\0';
			strcat(percorso,file_name);
			
			FILE* fp;
			fp=fopen(percorso,"w");			
			free(data);
			data=riceviMessaggio(a_request->socket,key);
			file_size=atoi(data);
			
			free(data);
			for(i=0;i<(file_size/buf_size);i++)
			{
				data=riceviMessaggio(a_request->socket,key);
    			if(fwrite(data,1,buf_size,fp)<buf_size) 
    			{
					printf("\n Errore nella scrittura del file \n");
					close(a_request->socket);
					return;
   				}
   				free(data);	
			}
			if((file_size%buf_size)>0)
			{
				data=riceviMessaggio(a_request->socket,key);
    			if(fwrite(data,1,file_size%buf_size,fp)<(file_size%buf_size)) 
    			{
					printf("\n Errore nella scrittura del file \n");
					close(a_request->socket);
					return;
   				}
   				free(data);	
			}
			fclose(fp);
			continue;	
		}
		
		if(data[0]=='2')
		{
			free(data);
			
			char cmd[30];
			strcpy(cmd,"ls ");
			strcat(cmd,user);
			strcat(cmd," > ls");
			strcat(cmd,user);
			printf("%s\n",cmd);
			system(cmd);
			
			FILE *fp;
			char csize[33];
			int size;
			const int buf_size=4096;
			struct stat info;
			int data_size,i;
			
			stat(cmd+6+u_size,&info);
			size=info.st_size;							//grandezza del file in byte
			sprintf(csize,"%d",size);

			fp=fopen(cmd+6+u_size,"r");
			if(fp==NULL)
			{
				printf("Impossibile leggere il file\n");
				continue;
			}
			
			data_size=sizeof(char)*33;
			data=malloc(data_size);
			memcpy(data,csize,data_size);
			inviaMessaggio(a_request->socket,data,data_size,key);
			free(data);
			data_size=sizeof(char)*buf_size;
			data=malloc(data_size);
			
			for(i=0;i<(size/buf_size);i++)
			{
				if(fread(data,1,buf_size,fp)<buf_size)
				{
					printf("\n Errore nella lettura del file \n");
					close(a_request->socket);
	  				return;	
				}
				inviaMessaggio(a_request->socket,data,data_size,key);
			}
			
			if((size%buf_size)>0)
			{
				if(fread(data,1,size%buf_size,fp)<(size%buf_size))
				{
					printf("\n Errore nella lettura del file \n");
					close(a_request->socket);
	  				return;	
				}
				inviaMessaggio(a_request->socket,data,size%buf_size,key);	
			}
			free(data);
			fclose(fp);
			continue;
		}
		
		if(data[0]=='3')
		{
			const int buf_size=4096;
			int data_size;
			char percorso[111];
			strcpy(percorso,user);
			strcat(percorso,"/");
			strcat(percorso,data+1);
			free(data);
			FILE* fp;
			fp=fopen(percorso,"r");
			
			if(fp==NULL)
			{
				printf("Impossibile leggere il file\n");
				inviaMessaggio(a_request->socket,"KO",2,key);
				continue;
			}
			inviaMessaggio(a_request->socket,"OK",2,key);			
			
			struct stat info;
 			char csize[33];
			int size;
			stat(percorso,&info);
			size=info.st_size;							//grandezza del file in byte
			sprintf(csize,"%d",size);
			
			data_size=sizeof(char)*33;
			data=malloc(data_size);
			memcpy(data,csize,data_size);
			inviaMessaggio(a_request->socket,data,data_size,key);		//invio grandezza del file
			free(data);
			
			data_size=sizeof(char)*buf_size;
			data=malloc(data_size);
			
			for(i=0;i<(size/buf_size);i++)
			{
				if(fread(data,1,buf_size,fp)<buf_size)
				{
					printf("\n Errore nella lettura del file \n");
					close(a_request->socket);
	  				return;	
				}
				inviaMessaggio(a_request->socket,data,data_size,key);
			}
			if((size%buf_size)>0)
			{
				if(fread(data,1,size%buf_size,fp)<(size%buf_size))
				{
					printf("\n Errore nella lettura del file \n");
					close(a_request->socket);
	  				return;	
				}
				inviaMessaggio(a_request->socket,data,size%buf_size,key);	
			}
			fclose(fp);
						
			continue;	
		}
		
		if(data[0]=='4')
		{
			if(file_checkrm(user,data+1)==1)
			{
				printf("File %s non trovato\n",data+1);
				inviaMessaggio(a_request->socket,"KO",2,key);
				free(data);
				continue;			
			}	
			printf("File %s rimosso\n",data+1);
			inviaMessaggio(a_request->socket,"OK",2,key);
			free(data);
			continue;	
		}
		
		if(data[0]=='5')
		{
			free(data);
			char cmd[30];
			strcpy(cmd,"rm -r ");
			strcat(cmd,user);
			system(cmd);
			//printf("%s\n",cmd);
			strcpy(cmd,"mkdir ");
			strcat(cmd,user);
			system(cmd);
			inviaMessaggio(a_request->socket,"OK",2,key);
			//printf("%s\n",cmd);		
			continue;	
		}
		
		if(data[0]=='6')
		{
			printf("Il client ha chiuso la connessione\n");
			close(a_request->socket);
			return;	
		}
	}
}

void* handle_request_loop(void* data)
{
	int rc;
	struct request* a_request;
	int thread_id=*((int*)data);
	
	printf("Starting thread %d\n",thread_id);
	
	while(1)
	{
		rc=pthread_mutex_lock(&request_mutex);
		if(num_requests>0)
		{
			rc=pthread_mutex_unlock(&request_mutex);
			a_request=get_request(&request_mutex);
			if(a_request)
			{
				rc=pthread_mutex_unlock(&request_mutex);
				handle_request(a_request,thread_id);
				free(a_request);
			}
		}
		else
		{
			rc=pthread_cond_wait(&got_request, &request_mutex);
			rc=pthread_mutex_unlock(&request_mutex);
		}
	}
}


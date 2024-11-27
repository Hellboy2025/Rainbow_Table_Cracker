#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <openssl/sha.h>
#include "uthash.h"

#define MAX_LINE_LENGTH 41
#define MAX_HASH_LENGTH (21)

char *wordlist_filename;
char *filename2;
int num_threads;
char* GLOBAL_BUFFER;
int NUMBER_OF_NEWLINES;

typedef struct {
    char hash[MAX_HASH_LENGTH];
    char password[MAX_LINE_LENGTH];
    UT_hash_handle hh;
} PasswordEntry;

PasswordEntry *thread_dictionaries[10] = {NULL};

void add_entry(int thread_id, const char *hash, const char *password) {
    PasswordEntry *entry = (PasswordEntry *)malloc(sizeof(PasswordEntry));
    memcpy(entry->hash, hash, MAX_HASH_LENGTH);
    strcpy(entry->password, password);
    //printf("password: %s\n", password);
    HASH_ADD(hh, thread_dictionaries[thread_id], hash, MAX_HASH_LENGTH, entry);
}



char *convertStringToHash(char *input){
    //input is a 40 character hex string (0..9 or a..f)
    char *hash = malloc(20*sizeof(char));
    int i,a,b;

    for (i = 0; i < 40; i+=2){
        a = (input[i]>='a') ? input[i]-'W' : input[i]-'0';
        b = (input[i+1]>='a') ? input[i+1]-'W' : input[i+1]-'0';
        hash[i/2] = a * 16 + b;
    }
    return hash;
}
struct thread_params {
    long thread_id;
    int start_index;
    int chunk_size;
};

void* process_file(void *arg) {
    struct thread_params* param = (struct thread_params*)arg;
    
    for (int i = 0; i < param->chunk_size ; i++) {    
        char line[MAX_LINE_LENGTH];
        int i = 0;
        while (GLOBAL_BUFFER[param->start_index] != '\n' && GLOBAL_BUFFER[param->start_index ] != '\0') {
            line[i] = GLOBAL_BUFFER[param->start_index];
            param->start_index++;
            i++;
        }
        line[i] = '\0';
        unsigned char* hash_buffer = (unsigned char *) calloc(sizeof(line),sizeof(char));
        SHA1((const unsigned char *)line ,strlen(line),hash_buffer);
        add_entry(param->thread_id, (const char *)hash_buffer, line);
        param->start_index++; //skip over newline
    }
    pthread_exit(NULL);
}

const char* is_hash_present(int thread_id, char *hash_to_find) {
    PasswordEntry *entry;
    HASH_FIND(hh, thread_dictionaries[thread_id], hash_to_find, MAX_HASH_LENGTH, entry);// this allows me to check each dictionary form each thread based on the thread id that I passed in. 
    return entry ? entry->password : NULL;  
}

int main(int argc, char *argv[]){
    if (argc != 4) {
        printf("Usage: %s <hash_file> <wordlist> <num_threads>\n", argv[0]);
        return 1;
    }
    int num_threads;

    num_threads = strtol(argv[3], NULL, 10);
    wordlist_filename = argv[2];
    filename2= argv[1];
    if (num_threads < 1){
        printf("ERROR: enter a positive number of threads\n");
        return -1;
    }
    FILE* file = fopen(wordlist_filename, "r");

    if (file == NULL) {
        printf("Error opening file\n");
        pthread_exit(NULL);
    }
    fseek(file, 0L, SEEK_END);
    int sz = ftell(file);


    GLOBAL_BUFFER = malloc(sz + 1);
    fseek(file,0L,SEEK_SET);
    fread(GLOBAL_BUFFER, sz, 1, file);
    fclose(file);

    int number_of_newlines = 0;
    char* tmp = GLOBAL_BUFFER;
    while (*tmp != '\0') {
        if (*tmp == '\n') {
            number_of_newlines++;
        }
        tmp++;
    }

    NUMBER_OF_NEWLINES = number_of_newlines;
    int chunk_size = number_of_newlines / num_threads;
    pthread_t *thread_array;

    thread_array = malloc(num_threads* sizeof(pthread_t));

    if (!thread_array) printf("ERROR: malloc failed");
    
    long i;
    int index = 0;
    
    for (i = 0; i < num_threads; i++) {
        struct thread_params* params = malloc(sizeof(struct thread_params));
        params->thread_id = i;
        if (i!=0){ //This is to make sure the subsequent math works properly because the first thread needs to start at index 0;
        
            if (NUMBER_OF_NEWLINES >= chunk_size) {
                params->chunk_size = chunk_size;
                NUMBER_OF_NEWLINES -= chunk_size;
            } else {
                params->chunk_size = NUMBER_OF_NEWLINES;
                NUMBER_OF_NEWLINES = 0;
            }
            
            //move index chunk_size number of newlines forward
            int newline_count = 0;
            while (newline_count < chunk_size) {
                if (GLOBAL_BUFFER[index] == '\n') {
                    newline_count++;
                }
                index++;
            }
            
            params->start_index = index;
           
        }
        else{
            params->start_index=0;
            params->chunk_size=chunk_size;
        }
        
        if (params->chunk_size > 0 && pthread_create(&thread_array[i], NULL, process_file, (void*)params) != 0) {
            perror("Thread creation failed");
            return 1;
        }
    }
    for (int i = 0; i < num_threads; ++i) {
        if (pthread_join(thread_array[i], NULL) != 0) {
            printf("Error joining thread");
            return EXIT_FAILURE;
        }
    }
    
    file= fopen(filename2, "r");
    if  (file == NULL){
        printf("File can't be found \n");
        return -1;
    }

    
    char lines[82]; // Including userID, :, and hash
    
    
    while (fgets(lines, sizeof(lines),file) != NULL){ // Opening the Craking file single threaded
        char *User=NULL;
        char *Hash=NULL;
        const char Target[2]= ":";
        char *split_location;       
        split_location= strtok(lines,Target);
        if (split_location != NULL){
            User = split_location;
        }
        
        split_location=strtok(NULL,Target); 
        if (split_location != NULL){
            Hash = split_location;
        }
        

        char *Converted_Hash = convertStringToHash((char*)Hash);
        int i;
        const char *s;
         
         if (strlen(Hash)!=41){
                printf("Error given Hash has the wrong length\n");
            }
        for(i=0; i<=num_threads ; i++){ //iterating through the dictionary created by each thread and testing the hash against all of them since only one dictionary should have the solution since each dictionary is built with a section of passwords.lst

            s =is_hash_present(i,Converted_Hash);
            if (s){
                printf("%s:%s \n",User, s);
                break;
            }
            
        }
        if (i==num_threads+1){ // i++ will increment it before testing and exiting the for loop so if i > numthreads then you never found the solution because when it is found you break out of the foor loop
            printf("%s:[not found] \n", User);
        }
    }   


    return EXIT_SUCCESS;
}

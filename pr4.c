
#include <stdio.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <string.h> 
#include "uthash.h"

struct my_struct {
    unsigned hash[21];            /* we'll use this field as the key */
    unsigned password[41];
    UT_hash_handle hh; /* makes this structure hashable */
};

struct my_struct *users = NULL;

void add_user( unsigned char *hash_id,  unsigned char *known_password) {
    struct my_struct *s = NULL;
    s= (struct my_struct *)calloc(1,sizeof *s);
    strncpy(s -> hash, hash_id, 20);
    strncpy(s -> password, known_password, 40);
    HASH_ADD_STR(users, hash, s );
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

int main(int argc, char* argv[]){
    
    if (argc != 3) {// This is the first check to make sure that the user provides the right amount of arguments 
        printf("Usage: ./pr4 [pwhashes] [dictionary] \n");
        return 1;
    }
    
    char *all_pass_file= argv[2];
    char *crack_pass_file= argv[1];


    FILE *ptr;
    
    //Common Passwords
    ptr= fopen(all_pass_file, "r");
    if  (ptr == NULL){
        printf("File can't be found \n");
        return -1;
    }

    unsigned char line[41]; // Including userID, :, and hash
    while (fgets(line, 41,ptr)){
        //printf("%s \n",line);
        line[strlen(line)-1]= (char)'\0';
        unsigned char *Crack= (unsigned char *) calloc(21,sizeof(char));
        SHA1(line,strlen(line),Crack); // This is the hash for each of the passwords provided.
        add_user(Crack, line);
        free(Crack);
    }
    fclose(ptr);

    //Passwords to Crack
    ptr= fopen(crack_pass_file, "r");
    if  (ptr == NULL){
        printf("File can't be found \n");
        return -1;
    }

    
    char lines[82]; // Including userID, :, and hash
    struct my_struct *s = NULL;
    char *User;
    unsigned char *Hash;
    while (fgets(lines, sizeof(lines),ptr) != NULL){
        const char Target[2]= ":";
        char *split_location;       // This section finds the colon in the line of the file so we can split between the user and the hash
        split_location= strtok(lines,Target); // Source of knowledge : https://www.tutorialspoint.com/c_standard_library/c_function_strtok.htm
        
        if (split_location != NULL){
            User = split_location;
        }
        
        split_location=strtok(NULL,Target); // Finding the pointer of the Hash

        if (split_location != NULL){
            Hash = split_location;
        }
        

      
        unsigned char *Converted_Hash = convertStringToHash(Hash);
        
        
        HASH_FIND_STR(users, Converted_Hash, s); // Cadet Kim '23 Helped me implment the Hash Find function because i was having issues formating it. 

        if (strlen(Hash)!=41){
            printf("Error given Hash has the wrong length\n");
        }
        else if (s){
            printf("%s:%s \n",User, (char*)s-> password);
        }
        else{
            printf("%s:[not found]\n", User);
        }
    }

    
    
    fclose(ptr);
    
    
    return 0;


    
    
}
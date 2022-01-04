#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>
#include <iostream>
#include <fstream>
using namespace std;

int encrypt(unsigned char *key, unsigned char *iv, unsigned char *plaintxt, unsigned char *ciphertxt, int plaintxt_len){
    //Will be used in the following if statements
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertxt_len;
    
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())){
        cout << "Error with context initialization!" << endl;
        exit(0);
    }
    
    /*set up cipher context ctx for encryption with aes-128-cbc*/
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)){
        cout << "Error with context setup!" << endl;
        exit(0);
    }
       
    /*Perform actual encryption*/
    if(1 != EVP_EncryptUpdate(ctx, ciphertxt, &len, plaintxt, plaintxt_len)){
        cout << "Error with actual encryption!" << endl;
        exit(0);
    }
    ciphertxt_len = len;
    
    /*Finalize encryption*/
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertxt + len, &len)){
        cout << "Error with encryption finalization!" << endl;
        exit(0);
    }
    ciphertxt_len = ciphertxt_len + len;

    /*Free up ctx after finishing encryption. It's kinda like a destructor*/
    EVP_CIPHER_CTX_free(ctx);
    return ciphertxt_len;
}

int main (void){
    //Since we are using aes-128-cbc, we need a key, iv, and plaintext
    unsigned char *key;
    unsigned char iv[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    unsigned char *plaintxt = (unsigned char *)"This is a top secret.";
    int plaintxt_len = strlen ((char *)plaintxt);
   
    //Will be used to compare the two ciphertexts in order to find the key
    unsigned char ciphertxt[128];
    int ciphertxt_len;
    unsigned char *expected_ciphertxt = (unsigned char *)"\x8d\x20\xe5\x05\x6a\x8d\x24\xd0\x46\x2c\xe7\x4e\x49\x04\xc1\xb5\x13\xe1\x0d\x1d\xf4\xa2\xef\x2a\xd4\x54\x0f\xae\x1c\xa0\xaa\xf9";
   
    //Will loop through words.txt and perform encryption for each word until key found
    fstream newfile;
    newfile.open("words.txt",ios::in); 
    string word;
    while(getline(newfile, word)){ 
    	//calculate and append the number of space characters needed word if word is less
        //than 16 bytes
        int num_of_spaces = 0;
    	if (word.length() < 16){
    		num_of_spaces = 16 - word.length();
    		for(int i = 1; i <= num_of_spaces; i++){
    			word += ' ';
    		}
    	}
        
        //word will now be used as a key for encryption
        key = (unsigned char *) word.c_str();
        
        //perform encryption using the current key
    	ciphertxt_len = encrypt (key, iv, plaintxt, ciphertxt, plaintxt_len);
    	
        //Compare the original ciphertext with the newly produced ciphertext
        if(memcmp (ciphertxt, expected_ciphertxt, ciphertxt_len) == 0){
    		cout << "I found the key" << endl;
    		cout << "The key is: " << word << endl;
            break;
    	}
    }
    newfile.close(); 
    
    return 0;
}


/**
 * @file aesTest.c
 * @authors MubRab
 * @brief This program runs the AES function as a standalone function
 * @version 0.1
 * @date 2020-05-07
 * 
 * @copyright Copyright (c)
 * 
 */
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include "aes.h"

int main()
{
    printf("Choose: Decryption (d) or Encryption (e): ");
    char flag = getchar();
    getchar();
    if (tolower(flag) != 'e' && tolower(flag) != 'd') {
        printf("Invalid character entered!\n");
        return -1;
    }
    printf("Enter message: ");
    //stores the message to encrypted/decrypted
    unsigned char *message = malloc(100);
    gets(message, 100, stdin);
    printf("Enter cipher key: ");
    //stores the cipher key to be used for encryption/decryption
    unsigned char *key = malloc(33);
    gets(key, 33, stdin);
    printf("Enter AES key size (128, 192 or 256): ");
    //stores the key length
    char type[3];
    gets(type, 3, stdin);
    int keyLength = atoi(type);
    if (keyLength != 128 && keyLength != 192 && keyLength != 256) {
        printf("Wrong key size!");
        return -1;
    }
    
    if (tolower(flag) == 'e')
        encryption(message, key, keyLength/8);
    else
        decryption(message, key, keyLength/8);

    return 1;

}
/**
 * @brief Runs the AES encryption function
 * 
 * @param message Plain text to be encrypted
 * @param key Cipher key used for AES encryption
 * @param key Length The length of the key
 */
void encryption(unsigned char *message, unsigned char *key, int keyLength)
{
    int messageLength = strlen(message);
    int cipherLength = 16*ceil(messageLength/16.0f);
    unsigned char *finalCipherText[cipherLength];
    // finalCipherText[cipherLength-1] = '\0';

    for (int iter = 0; iter <= messageLength/16; ++iter) {
        unsigned char inputMessage[17] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, '\0'};
        int index = 0;
        for (int i = iter*16; i < messageLength && i < (16*(iter+1)); ++i) {
            //the input plain text is put into an array which processes it 128-bits at a time
            inputMessage[index++] = message[i];
        }
        inputMessage[index] = '\0';
        unsigned char outputAES[16];
        encrypt(inputMessage, 16, key, keyLength, outputAES);
        index = 0;
        for (int i = iter*16; i < (16*(iter+1)); ++i) {
            //The output from the AES is inserted into the final cipher text array
            finalCipherText[i] = outputAES[index];
            outputAES[index++] = 0;
        }
    }
    printf("\nCipher key used for expansion:\n");
    for (int i = 0; i < strlen(key); ++i)
        printf("%02X\t", key[i]);
    printf("\nFinal CBC Cipher Text:\n");
    for (int i = 0; i < cipherLength; ++i) {
        printf("%02X\t", finalCipherText[i]);
        if (i == 15)
            printf("\n");
    }
    printf("\n");

}

/**
 * @brief Runs the AES decryption function
 * 
 * @param message Cipher text to be encrypted
 * @param key Cipher key used for AES encryption
 * @param key Length The length of the key
 */
void decryption(unsigned char *message, unsigned char *key, int keyLength)
{
    int messageLength = strlen(message);
    int cipherLength = 16*ceil(messageLength/16.0f);
    unsigned char *finalPlainText[cipherLength];
    // finalCipherText[cipherLength-1] = '\0';

    for (int iter = 0; iter <= messageLength/16; ++iter) {
        unsigned char inputMessage[17] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, '\0'};
        int index = 0;
        for (int i = iter*16; i < messageLength && i < (16*(iter+1)); ++i) {
            //the input plain text is put into an array which processes it 128-bits at a time
            inputMessage[index++] = message[i];
        }

        unsigned char outputAES[16];
        decrypt(inputMessage, 16, key, keyLength, outputAES);
        index = 0;
        for (int i = iter*16; i < (16*(iter+1)); ++i) {
            //The output from the AES is inserted into the final plain text array
            finalPlainText[i] = outputAES[index];
            outputAES[index++] = 0;
        }
    }

    printf("\nCipher key used for expansion:\n");
    for (int i = 0; i < strlen(key); ++i)
        printf("%02X\t", key[i]);
    printf("\nFinal CBC Plain Text:\n");
    for (int i = 0; i < cipherLength; ++i) {
        printf("%02X\t", finalPlainText[i]);
        if (i == 15)
            printf("\n");
    }
    printf("\n");
}
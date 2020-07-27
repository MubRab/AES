/**
 * @file aes.c
 * @authors MubRab
 * @brief Implementation of AES algorithm
 * @version 0.1
 * @date 2020-04-05
 * 
 * @copyright Copyright (c)
 * 
 */

#include "aes.h"
#include <stdio.h>
#include <string.h>
#include <math.h>

//Look up table for the S Box table
const unsigned char sBox[256] = {
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 
  };

//Look up table for the inverse S Box table
const unsigned char inverseSBox[256] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d 
  };

//https://cryptography.fandom.com/wiki/Rijndael_key_schedule
unsigned char Rcon[255] = {
0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 
0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 
0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 
0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 
0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 
0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 
0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 
0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 
0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 
0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 
0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 
0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 
0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 
0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 
0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 
0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb
};

/**
 * @brief Holds the state values during the encryption/decryption process
 * 
 */
unsigned char state[4][4];
/**
 * @brief Holds the round keys for each round
 * 
 */
unsigned char roundKey[4][4];

//=============================================================================================================================
void encrypt(unsigned char* inputMessage, int inputLength, unsigned char* cipherKey, int keyLength, unsigned char* cipherText)
{
    printf("====================AES Encryption===================\n");
    unsigned char key[keyLength];
    for (int i = 0; i < keyLength; ++i)
        key[i] = 0;
    for (int i = 0; i < strlen(cipherKey); ++i)
        key[i] = cipherKey[i];

    unsigned char input[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    
    //Copies the plaintext input array into an input array, to ensure padding occurs.
    for (int i = 0; i < 16; ++i) {
        input[i] = inputMessage[i];
    }
    printf("Input with padding:\n");
    for (int i = 0; i < 16; ++i)
        printf("%02X ", input[i]);
    
    //copies the input array into the state matrix for processing
    copyToStateMatrix(input);
    printf("\nState Matrix:\n");
    printStateMatrix();
    int N_k = determineKeyLength(keyLength);
    printf("Key length of Cipher Key: %d\n", N_k);
    int N_r = determineNumRounds(N_k);
    printf("Number of rounds: %d\n", N_r);

    //Holds the expanded keys
    unsigned char cipherWords[4][4*(N_r+1)];
    //performs the key expansion
    keyExpansion(key, N_k, N_r, &cipherWords);
    //constructs the round key for the specific round (in this case it is round 0)
    constructRoundKey(4*(N_r+1), cipherWords, 0);
    printf("Round Key:\n");
    printRoundKey();
    //XORs the round key and state matrix
    addRoundKey();
    printf("State Matrix after Round Key (XOR):\n");
    printStateMatrix();

    for (int i = 0; i < N_r-1; ++i) {
        printf("===============Round %d==============\n", i+1);
        //performs the substitute bytes operation
        substituteBytes(0);
        printf("After Substite Bytes:\n");
        printStateMatrix();
        //performs the shift rows operation
        shiftRows(0);
        printf("After Shift Rows:\n");
        printStateMatrix();
        //performs the mix columns operation
        mixColumns(0);
        printf("After Mix Columns:\n");
        printStateMatrix();
        constructRoundKey(4*(N_r+1), cipherWords, i+1);
        printf("Round Key for round %d\n", i+1);
        printRoundKey();
        addRoundKey(key, keyLength);
        printf("State Matrix after Round Key (XOR):\n");
        printStateMatrix();
    }

    printf("===============Round %d==============\n", N_r);
    substituteBytes(0);
    printf("After Substite Bytes:\n");
    printStateMatrix();
    shiftRows(0);
    printf("After Shift Rows:\n");
    printStateMatrix();
    constructRoundKey(4*(N_r+1), cipherWords, N_r);
    printf("Round Key for round %d\n", N_r);
    printRoundKey();
    addRoundKey();
    printf("Final State Matrix\n");
    printStateMatrix();
    printf("Printing Expanded Keys:\n");
    printExpandedKey(N_r, &cipherWords); 
    printf("AES Ciphertext:\n");
    for (int columns = 0; columns < 4; ++columns) {
        //copies encrypted text into the cipherText array 
        cipherText[4*columns + 0] = state[0][columns];
        cipherText[4*columns + 1] = state[1][columns];
        cipherText[4*columns + 2] = state[2][columns];
        cipherText[4*columns + 3] = state[3][columns];
        printf("%02X\t%02X\t%02X\t%02X\t", cipherText[4*columns + 0], cipherText[4*columns + 1], cipherText[4*columns + 2], cipherText[4*columns + 3]);
    }
    printf("\n==================End of AES Encryption=================\n");

}

void decrypt(unsigned  char* inputMessage, int inputLength, unsigned char* cipherKey, int keyLength, unsigned char* plainText)
{
    printf("====================AES Decryption===================\n");
    unsigned char key[keyLength];
    for (int i = 0; i < keyLength; ++i)
        key[i] = 0;
    for (int i = 0; i < strlen(cipherKey); ++i)
        key[i] = cipherKey[i];

    unsigned char input[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    for (int i = 0; i < strlen(inputMessage) && i < 16; ++i)
        input[i] = inputMessage[i];
    printf("Input with padding:\n");
    for (int i = 0; i < 16; ++i)
        printf("%02X ", input[i]);
    
    copyToStateMatrix(input);
    printf("\nState Matrix:\n");
    printStateMatrix();
    int N_k = determineKeyLength(keyLength);
    printf("Key length of Cipher Key: %d\n", N_k);
    int N_r = determineNumRounds(N_k);
    printf("Number of rounds: %d\n", N_r);

    unsigned char cipherWords[4][4*(N_r+1)];
    keyExpansion(key, N_k, N_r, &cipherWords);
    constructRoundKey(4*(N_r+1), cipherWords, N_r);
    printf("Round Key:\n");
    printRoundKey();
    addRoundKey();
    printf("State Matrix after Round Key (XOR):\n");
    printStateMatrix();
    int k = 1;
    for (int i = N_r-1; i > 0; --i) {
        printf("===============Round %d==============\n", k);
        shiftRows(1);
        printf("After Shift Rows:\n");
        printStateMatrix();
        substituteBytes(1);
        printf("After Substite Bytes:\n");
        printStateMatrix();
        constructRoundKey(4*(N_r+1), cipherWords, i);
        printf("Round Key for round %d\n", k++);
        printRoundKey();
        addRoundKey(key, keyLength);
        printf("State Matrix after Round Key (XOR):\n");
        printStateMatrix();
        mixColumns(1);
        printf("After Mix Columns:\n");
        printStateMatrix();
    }

    printf("===============Round %d==============\n", N_r);
    shiftRows(1);
    printf("After Shift Rows:\n");
    printStateMatrix();
    substituteBytes(1);
    printf("After Substite Bytes:\n");
    printStateMatrix();
    constructRoundKey(4*(N_r+1), cipherWords, 0);
    printf("Round Key for round %d\n", N_r);
    printRoundKey();
    addRoundKey();
    printf("Final State Matrix\n");
    printStateMatrix();
    printf("Printing Expanded Keys:\n");
    printExpandedKey(N_r, &cipherWords); 
    printf("AES Plaintext:\n");
    for (int columns = 0; columns < 4; ++columns) {
        plainText[4*columns + 0] = state[0][columns];
        plainText[4*columns + 1] = state[1][columns];
        plainText[4*columns + 2] = state[2][columns];
        plainText[4*columns + 3] = state[3][columns];
        printf("%02X\t%02X\t%02X\t%02X\t", plainText[4*columns + 0], plainText[4*columns + 1], plainText[4*columns + 2], plainText[4*columns + 3]);
    }
    printf("\n==================End of AES Decryption=================\n");

    
}

//=============================================================================================================================
void (keyExpansion)(unsigned char *cipherKey, int N_k, int N_r, unsigned char words[4][4*(N_r+1)])
{

    //copying the original cipher key into the key expansion matrix
    for (int i = 0; i < N_k; ++i) {
        words[0][i] = cipherKey[4*i];
        words[1][i] = cipherKey[4*i+1];
        words[2][i] = cipherKey[4*i+2];
        words[3][i] = cipherKey[4*i+3];
    }//endfor


    //generating the rest of the words
    for (int i = N_k; i < 4*(N_r+1); ++i) {
        unsigned char tempVal[4];
        for (int k = 0; k < 4; k++) 
            tempVal[k] = words[k][i-1];
        
        if (i % N_k == 0) {
            //rotate the keys
            int temp = tempVal[0];
            tempVal[0] = tempVal[1];
            tempVal[1] = tempVal[2];
            tempVal[2] = tempVal[3];
            tempVal[3] = temp;
            //substitution operation
            for (int k = 0; k < 4; k++)
                tempVal[k] = sBox[tempVal[k]];

            tempVal[0] ^= Rcon[i/N_k];  
        } else if (N_k == 8 && i % N_k == 4) {
            for (int k = 0; k < 4; k++)
                tempVal[k] = sBox[tempVal[k]];
        }

        for (int k = 0; k < 4; k++)
            words[k][i] = words[k][i-N_k] ^ tempVal[k];

    }//endfor
    return words;

}

void addRoundKey()
{
    for (int rows = 0; rows < 4; ++rows)
        for (int cols = 0; cols < 4; ++cols) 
            state[rows][cols] = state[rows][cols] ^ roundKey[rows][cols];
}

void constructRoundKey(int col, unsigned char words[4][col], int round)
{
    for (int rows = 0; rows < 4; ++rows){
        int columns = 0;
        for (int cols = round*4; cols < (4*round) + 4; ++cols) {
            roundKey[rows][columns] = words[rows][cols];
            ++columns;
        }
    }
}

void substituteBytes(int isInverse)
{
	if (isInverse == 0)
	{
		//for encryption
        for (int rows = 0; rows < 4; ++rows)
            for (int cols = 0; cols < 4; ++cols)
                state[rows][cols] = sBox[state[rows][cols]];
	} else {
		//for decryption
        for (int rows = 0; rows < 4; ++rows)
            for (int cols = 0; cols < 4; ++cols)
                state[rows][cols] = inverseSBox[state[rows][cols]];
	}
}
void shiftRows(int isInverse)
{
	if (isInverse == 0)
	{
		//for encryption
        //for row 1:
        unsigned char temp;
        temp = state[1][0];
        state[1][0] = state[1][1];
        state[1][1] = state[1][2];
        state[1][2] = state[1][3];
        state[1][3] = temp;
        //for row 2:
        temp = state[2][0];
        state[2][0] = state[2][2];
        state[2][2] = temp;
        temp = state[2][1];
        state[2][1] = state[2][3];
        state[2][3] = temp;
        //for row 3:
        temp = state[3][0];
        state[3][0] = state[3][3];
        state[3][3] = state[3][2];
        state[3][2] = state[3][1];
        state[3][1] = temp;
	} else {
		//for decryption
        unsigned char temp;
        temp = state[1][0];
        state[1][0] = state[1][3];
        state[1][3] = state[1][2];
        state[1][2] = state[1][1];
        state[1][1] = temp;
        //for row 2:
        temp = state[2][0];
        state[2][0] = state[2][2];
        state[2][2] = temp;
        temp = state[2][1];
        state[2][1] = state[2][3];
        state[2][3] = temp;
        //for row 3:
        temp = state[3][0];
        state[3][0] = state[3][1];
        state[3][1] = state[3][2];
        state[3][2] = state[3][3];
        state[3][3] = temp;
        
	}
}
void mixColumns(int isInverse) //https://en.wikipedia.org/wiki/Rijndael_MixColumns#Implementation_example
{
	if (isInverse == 0)
	{
		//for encryption
        for (int columns = 0; columns < 4; ++columns) {
            unsigned char stateColumnCopy[4];
            for (int rows = 0; rows < 4; ++rows) stateColumnCopy[rows] = state[rows][columns];
            unsigned char tempOperations[4];
            for (int i = 0; i < 4; ++i) {
                unsigned char tempVal;
                tempVal = (unsigned char)((signed char) stateColumnCopy[i] >> 7);
                tempOperations[i] = (stateColumnCopy[i] << 1) ^ 0x1b & tempVal;
            }

            state[0][columns] = tempOperations[0] ^ stateColumnCopy[3] ^ stateColumnCopy[2] ^ tempOperations[1] ^ stateColumnCopy[1];
            state[1][columns] = tempOperations[1] ^ stateColumnCopy[0] ^ stateColumnCopy[3] ^ tempOperations[2] ^ stateColumnCopy[2];
            state[2][columns] = tempOperations[2] ^ stateColumnCopy[1] ^ stateColumnCopy[0] ^ tempOperations[3] ^ stateColumnCopy[3];
            state[3][columns] = tempOperations[3] ^ stateColumnCopy[2] ^ stateColumnCopy[1] ^ tempOperations[0] ^ stateColumnCopy[0];
        }
	} else {
		//for decryption
        for (int columns = 0; columns < 4; ++columns) {
            unsigned char stateColumnCopy[4];
            for (int rows = 0; rows < 4; ++rows) stateColumnCopy[rows] = state[rows][columns];

            state[0][columns] = mul(stateColumnCopy[0], 0xe) ^ mul(stateColumnCopy[1], 0xb) ^ mul(stateColumnCopy[2], 0xd) ^ mul(stateColumnCopy[3], 0x9);
            state[1][columns] = mul(stateColumnCopy[0], 0x9) ^ mul(stateColumnCopy[1], 0xe) ^ mul(stateColumnCopy[2], 0xb) ^ mul(stateColumnCopy[3], 0xd);
            state[2][columns] = mul(stateColumnCopy[0], 0xd) ^ mul(stateColumnCopy[1], 0x9) ^ mul(stateColumnCopy[2], 0xe) ^ mul(stateColumnCopy[3], 0xb);
            state[3][columns] = mul(stateColumnCopy[0], 0xb) ^ mul(stateColumnCopy[1], 0xd) ^ mul(stateColumnCopy[2], 0x9) ^ mul(stateColumnCopy[3], 0xe);
        }

	}
}

//=============================================================================================================================
int determineKeyLength(int keyLength)
{
	return keyLength/4;
}

int determineNumRounds(int Nk)
{
	if (Nk == 4)
		return 10;
	else if (Nk == 6)
		return 12;
	else
		return 14;
  
}

void copyToStateMatrix(const unsigned char* input)
{
    for (int rows = 0; rows < 4; ++rows)
        for (int cols = 0; cols < 4; ++cols)
            state[rows][cols] = input[cols * 4 + rows];
}

void printStateMatrix()
{
    for (int rows = 0; rows < 4; ++rows) {
        for (int cols = 0; cols < 4; ++cols) {
            printf("%02X", state[rows][cols]);
            printf("\t");
        }
        printf("\n");
    }
}

void printRoundKey()
{
    for (int rows = 0; rows < 4; ++rows) {
        for (int cols = 0; cols < 4; ++cols) {
            printf("%02X", roundKey[rows][cols]);
            printf("\t");
        }
        printf("\n");
    }
}

void printExpandedKey(int N_r, unsigned char words[4][4*(N_r+1)])
{
    for (int columns = 0; columns < 4*(N_r+1); ++columns){
        for (int rows = 0; rows < 4; ++rows)
            printf("%02X\t", words[rows][columns]);
        
        printf("\n");
    }
}

unsigned char mul(unsigned char a, unsigned char b) 
{
    unsigned char operations[5];
    operations[0] = a;
    for (int i = 1; i < 5; ++i) operations[i] = operations[i-1] << 1 ^ (((operations[i-1] >> 7) & 1) * 0x1b);
    
    unsigned char val1 = (b & 1) * operations[0];
    unsigned char val2 = (b >> 1 & 1) * operations[1];
    unsigned char val3 = (b >> 2 & 1) * operations[2];
    unsigned char val4 = (b >> 3 & 1) * operations[3];
    unsigned char val5 = (b >> 4 & 1) * operations[4];

    return val1 ^ val2 ^ val3 ^ val4 ^ val5;    
}   
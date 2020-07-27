/**
 * @file aes.h
 * @authors MubRab
 * @brief Header File containing the AES algorithm function headers
 * @version 0.1
 * @date 2020-04-05
 * 
 * @copyright Copyright (c)
 * 
 */

#ifndef AES_H
#define AES_H

//variable declarations
extern const unsigned char sBox[256];
extern const unsigned char inverseSBox[256];
extern unsigned char state[4][4];
extern unsigned char roundKey[4][4];

/**
 * @brief The encryption function encrypts the received plain text message into cipher text
 * 
 * @param inputMessage The plain text string
 * @param inputLength Length of the plain text string (use strlen)
 * @param cipherKey The key for the encryption process
 * @param keyLength The length of the key. Should be either 16, 24 or 32 
 * @param cipherText The final encrypted text will stored in this array. Should be of size 16 bytes
 */
void encrypt(unsigned char* inputMessage, int inputLength, unsigned char* cipherKey, int keyLength, unsigned char* cipherText);

/**
 * @brief The decryption function decrypts the received cipher text into plain text.
 * 
 * @param inputMessage The cipher text.
 * @param inputLength Length of the cipher text (use strlen).
 * @param cipherKey The key used for the encryption process.
 * @param keyLength The length of the key. Should be either 16, 24 or 32.
 * @param plainText The final plain text message will be stored in this array. Should be of size 16 bytes.
 */
void decrypt(unsigned  char* inputMessage, int inputLength, unsigned char* cipherKey, int keyLength, unsigned char* plainText);
/**
 * @brief This function expands the original cipher key received.
 * 
 * @param cipherKey The original cipherKey
 * @param N_k
 * @param N_r
 * @param words The array which will contain the expanded keys for future use.
 */
void (keyExpansion)(unsigned char *cipherKey, int N_k, int N_r, unsigned char words[4][4*(N_r+1)]);
/**
 * @brief Helper function to perform the XOR operation of the state array and round key array
 */
void addRoundKey();
/**
 * @brief Constructs the round key from they expanded keys
 * 
 * @param col The number of columns the expanded key has. This depends on the length of the cipher key received.
 * @param words The array containing the expanded keys
 * @param round Which round the process is currently busy with.
 */
void constructRoundKey(int col, unsigned char words[4][col], int round);
/**
 * @brief Performs the substitute bytes operation on the state matrix
 * 
 * @param isInverse Flag to determine if encryption (0) or decryption (1) is used
 */
void substituteBytes(int isInverse);
/**
 * @brief Performs the shift rows operation on the state matrix
 * 
 * @param isInverse Flag to determine if encryption (0) or decryption (1) is used
 */
void shiftRows(int isInverse);
/**
 * @brief Performs the mix column operation on the state matrix
 * 
 * @param isInverse Flag to determine if encryption (0) or decryption (1) is used
 */
void mixColumns(int isInverse);
/**
 * @brief Determines N_k
 * 
 * @param keyLength The key length of the received key (16, 24 or 32)
 * @return int Returns N_k
 */
int determineKeyLength(int keyLength);
/**
 * @brief Determines the number of rounds to perform based on the length of the key.
 * 
 * @param Nk 
 * @return int Returns the number of rounds
 */
int determineNumRounds(int Nk);
/**
 * @brief Copies the input text/message into the state matrix.
 * 
 * @param input The input plain/cipher text.
 */
void copyToStateMatrix(const unsigned char *input);
/**
 * @brief Prints the state matrix
 * 
 */
void printStateMatrix();
/**
 * @brief Prints the current round key
 * 
 */
void printRoundKey();
/**
 * @brief Prints the expanded key
 * 
 * @param N_r Number of rounds
 * @param words Array containing the expanded keys.
 */
void printExpandedKey(int N_r, unsigned char words[4][4*(N_r+1)]);
/**
 * @brief Helper function for inverse Rijndael Mix columns operation
 *  
 */
unsigned char mul(unsigned char a, unsigned char b);

#endif
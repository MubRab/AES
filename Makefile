TARGET=aesTest
aes:
	gcc -o $(TARGET) aesTest.c aes.c -lm

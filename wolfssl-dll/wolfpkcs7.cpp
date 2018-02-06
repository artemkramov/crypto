#include <conio.h>
#include <stdio.h>
#include "wolfpkcs7.h"

byte* readBinaryFile(char* filePath, long* outputFileSize)
{
	FILE* filePtr = fopen(filePath, "rb");  // Open the file in binary mode
	fseek(filePtr, 0, SEEK_END);          // Jump to the end of the file
	long fileLength = ftell(filePtr);             // Get the current byte offset in the file
	rewind(filePtr);                      // Jump back to the beginning of the file

	byte* buffer = (byte *)malloc((fileLength + 1) * sizeof(char)); // Enough memory for file + \0
	fread(buffer, fileLength, 1, filePtr); // Read in the entire file
	fclose(filePtr); // Close the file

	*outputFileSize = fileLength;

	return buffer;
}

void generatePKCS7(byte* content, byte* contentSize)
{
	PKCS7 pkcs7;
	byte* bufferCert;
	byte* bufferKey; 
	byte pkcs7Buff[FOURK_BUF];
	long bufferCertSize = 0, bufferKeySize = 0;
	RNG rng;

	wc_InitRng(&rng);

	bufferCert = readBinaryFile("E:/DATA(G)/web_ecr_ro/AMEF/PEM_3fbe28a52b55d1f4cb3e963dde434228/3fbe28a52b55d1f4cb3e963dde434228.der", &bufferCertSize);
	//bufferKey = readBinaryFile("E:/DATA(G)/web_ecr_ro/AMEF/PEM_3fbe28a52b55d1f4cb3e963dde434228/pemkeytoder.der", &bufferKeySize);
	
	// Set dummy data
	bufferKey = (byte*)malloc(1 * sizeof(byte));
	bufferKeySize = 1;

	wc_PKCS7_InitWithCert(&pkcs7, bufferCert, bufferCertSize);
}
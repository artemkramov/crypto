/*
Copyright (c) 2011, Gerhard H. Schalk (www.smartcard-magic.net)
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the 
documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT 
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT 
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON 
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE 
USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.*/
#include <winscard.h>
#include <stdio.h>
#include <conio.h>
#include <string.h>
#include <string>
#include <stdlib.h>
#include "pcsc.h"
#include "util.h"

using namespace std;

#define RcvLenMax 300l                       // Max. APDU Buffer length.

SCARDCONTEXT		m_hContext;				 // Resource manager handle 
SCARDHANDLE			m_hCard;				 // Card Handle
CHAR				m_szSelectedReader[256];  // Selected card reader name.
DWORD				m_dwActiveProtocol;      // Active protocol (T=0, T=1 or undefined).

void LogOperation(char* operation)
{
	printf("Current operation is %s \n", operation);
}

/**
* Analyze APDU response to understand if request was successfull
* Fetch data from the response
*/
PCSCResponse FormatResponseFromCard(LONG sCardResponse, BYTE data[], int dataLength)
{
	PCSCResponse response;
	char* error;
	int isResponseSuccess = PCSC_RESPONSE_SUCCESS;
	response.sCardResponseCode = PCSC_RESPONSE_CODE_SUCCESS;

	// Check if request was passed to SD card 
	if (sCardResponse != SCARD_S_SUCCESS)
	{
		isResponseSuccess = PCSC_RESPONSE_ERROR;
		error = sCardGetErrorString(sCardResponse);
	}
	else
	{

		// Read last 2 bytes of the response and check the status
		unsigned short int responseCode = data[dataLength - 1] | (data[dataLength - 2] << 8);
		if (responseCode != PCSC_RESPONSE_CODE_SUCCESS)
		{
			isResponseSuccess = PCSC_RESPONSE_ERROR;
			response.sCardResponseCode = responseCode;
			error = PCSC_GetError(responseCode);
		}
		else
		{
			if (dataLength > 2)
			{
				// Copy response data
				int responseDataLength = sizeof(response.data) / sizeof(BYTE);
				int copyLength = responseDataLength > dataLength - 2 ? dataLength - 2 : responseDataLength;
				memcpy(response.data, data, copyLength);
			}
		}
	}
	response.isSuccess = isResponseSuccess;
	
	// Write error message
	if (isResponseSuccess == PCSC_RESPONSE_ERROR)
	{
		strcpy(response.errorString, error);
	}
	return response;
}

/*************************************************
Function:       PCSC_Connect       
Description:
     Establishes the resource manager context.
Parameter:
     sReader   If the value is NULL a list all 
               readers in the system is displayed 
               for selection. Alternative a specific
               reader name string must be provided.
     
Return:
     LONG   If the function succeeds, the function 
            If the function fails,it returns an 
            SCARD error code.
**************************************************/
LONG PCSC_Connect(LPTSTR szReader  )
{
	LONG			lRetValue;
	LPTSTR          pmszReaders = NULL;
	LPTSTR          pszReader;
	LPTSTR			pszaReaders[16];
	DWORD           cch = SCARD_AUTOALLOCATE;
	INT				iNumberOfReaders;
	INT				iSelectedReader;
    
    // The SCardEstablishContext function establishes the resource manager context 
	lRetValue = SCardEstablishContext(
                   SCARD_SCOPE_USER, // Scope of the resource manager context.
                   NULL,             // r.f.u
                   NULL,             // r.f.u
                   &m_hContext);	 // Returns the resource manager handle.
	PCSC_STATUS(lRetValue, "SCardEstablishContext");	

	if(szReader  != NULL)
	{
		strcpy_s(m_szSelectedReader, szReader );
		return lRetValue;
	}

	// The SCardListReaders function provides the list of readers 
	lRetValue = SCardListReaders(
                    m_hContext,             // Resource manager handle. 
                    NULL, // NULL: list all readers in the system 
                    (LPTSTR)&pmszReaders, // Returs the card readers list.
                    &cch );
	PCSC_STATUS(lRetValue, "SCardListReaders");
		
	iNumberOfReaders = 0;
	pszReader = pmszReaders;

	// Extract the reader strings form the null separated string and 
	// get the total number of readers.
	while ( *pszReader != '\0' )
	{
		printf("\n      Reader [%2d] %s", iNumberOfReaders, pszReader);
		pszaReaders[ iNumberOfReaders ] = (LPTSTR)pszReader;
		pszReader = pszReader + strlen(pszReader) + 1;
		iNumberOfReaders++;
	}
	
	if( iNumberOfReaders > 1)
	{
		// There are several readers connected.
		printf("\n      Please select a reader (0..n): ");
		fflush(stdin);
		
		iSelectedReader = _getch() - '0';
		printf("%d\n",iSelectedReader);
		strcpy_s(m_szSelectedReader, pszaReaders[iSelectedReader]);
	}
	else
	{
		// There is only one reader connected.
		strcpy_s(m_szSelectedReader, pszaReaders[0]);	
	}

	// Releases memory that has been returned from the resource manager 
    // using the SCARD_AUTOALLOCATE length designator.
	lRetValue = SCardFreeMemory( m_hContext, pmszReaders );
	PCSC_ERROR(lRetValue, "SCardFreeMemory");
	return lRetValue;

}

LONG PCSC_ActivateCard(void)
{

	LONG			lRetValue;
    
    //Establishes a connection to a smart card contained by a specific reader.
	lRetValue = SCardConnect( 
                    m_hContext, // Resource manager handle.
					m_szSelectedReader,     // Reader name.
					SCARD_SHARE_EXCLUSIVE,  // Share Mode.
					SCARD_PROTOCOL_Tx, //Preferred protocols (T=0 or T=1).
					&m_hCard,               // Returns the card handle.
					&m_dwActiveProtocol);   // Active protocol.
	PCSC_STATUS(lRetValue,"SCardConnect");	

	switch(m_dwActiveProtocol)
	{
		case SCARD_PROTOCOL_T0:
			printf(": Card Activated via  T=0 protocol\n");
			break;

		case SCARD_PROTOCOL_T1:
			printf(": Card Activated via  T=1 protocol\n");
			break;

		case SCARD_PROTOCOL_UNDEFINED:
			printf(": ERROR: Active protocol unnegotiated or unknown\n");
			lRetValue = -1;
			break;	
	}
	return lRetValue;
}

/**
* Clear all data on the card
*/
PCSCResponse PCSC_ClearAll()
{
	BYTE baResponseApdu[2];	
	DWORD lResponseApduLen = 0;
	BYTE baCmdApduGetData[] = { 0x80, 0x46, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	LogOperation("CLEAR ALL");
	LONG sCardResponse = PCSC_Exchange(baCmdApduGetData, (DWORD) sizeof(baCmdApduGetData), baResponseApdu, &lResponseApduLen);
	return FormatResponseFromCard(sCardResponse, baResponseApdu, lResponseApduLen);
}

/**
* Select command to turn on special commands on the card
*/
PCSCResponse PCSC_Select()
{
	BYTE baResponseApdu[300];	
	DWORD lResponseApduLen = 0;
    BYTE baCmdApduGetData[] = { 0x00, 0xA4, 0x04, 0x00, 0x08, 0xFA, 0x41, 0x56, 0x54, 0x52, 0x53, 0x41, 0x44};
	LogOperation("SELECT");
	LONG sCardResponse = PCSC_Exchange(baCmdApduGetData, (DWORD) sizeof(baCmdApduGetData), baResponseApdu, &lResponseApduLen);
	PCSCResponse response = FormatResponseFromCard(sCardResponse, baResponseApdu, lResponseApduLen);
	return response;
}

/**
* Activate card
*/
PCSCResponse PCSC_Activate()
{
	BYTE baResponseApdu[2];	
	DWORD lResponseApduLen = 0;
    BYTE baCmdApduGetData[] = { 0x80, 0x48, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	LogOperation("ACTIVATE");
	LONG sCardResponse = PCSC_Exchange(baCmdApduGetData, (DWORD) sizeof(baCmdApduGetData), baResponseApdu, &lResponseApduLen);
	return FormatResponseFromCard(sCardResponse, baResponseApdu, lResponseApduLen);
}

/**
* Get serial number of the card
*/
PCSCResponse PCSC_GetSerial()
{
	BYTE baResponseApdu[10];	
	DWORD lResponseApduLen = 0;
    BYTE baCmdApduGetData[] = { 0x80, 0xF6, 0x00, 0x00, 0x08};
	LogOperation("GET SERIAL");
	LONG sCardResponse = PCSC_Exchange(baCmdApduGetData, (DWORD) sizeof(baCmdApduGetData), baResponseApdu, &lResponseApduLen);
	return FormatResponseFromCard(sCardResponse, baResponseApdu, lResponseApduLen);
}

/**
* Enter the PIN code for authorization
*/
PCSCResponse PCSC_CheckPin(BYTE pin[], int pinLength)
{
	BYTE baResponseApdu[2];	
	DWORD lResponseApduLen = 0;

	// Prepare header bytes
	BYTE headerData[] = { 0x00, 0x20, 0x00, 0x05, (BYTE)pinLength };
	int headerLength = sizeof(headerData) / sizeof(BYTE);
	int messageLength = (headerLength + pinLength) * sizeof(BYTE);
	
	// Merge header bytes and pin code into the one destination
	BYTE* baCmdApduGetData = (BYTE*)malloc(messageLength);
	memcpy(baCmdApduGetData, headerData, headerLength * sizeof(BYTE));
	memcpy(baCmdApduGetData + headerLength * sizeof(BYTE), pin, pinLength * sizeof(BYTE));
	
	LogOperation("CHECK PIN");
	LONG sCardResponse = PCSC_Exchange(baCmdApduGetData, (DWORD) messageLength, baResponseApdu, &lResponseApduLen);
	return FormatResponseFromCard(sCardResponse, baResponseApdu, lResponseApduLen);
}

/**
* Challenge method to enable input mode in card
*/
PCSCResponse PCSC_Challenge()
{
	BYTE baResponseApdu[10];	
	DWORD lResponseApduLen = 0;
    BYTE baCmdApduGetData[] = { 0x00, 0x84, 0x00, 0x00, 0x08};
	LogOperation("CHALLENGE FOR INPUT");
	LONG sCardResponse = PCSC_Exchange(baCmdApduGetData, (DWORD) sizeof(baCmdApduGetData), baResponseApdu, &lResponseApduLen);
	return FormatResponseFromCard(sCardResponse, baResponseApdu, lResponseApduLen);
}

/**
* Import array of bytes into the private key
* @data - input array of bytes
* @dataLength - array length
* @P2 - parameter which defines the type of the imported data (key or module)
*/
PCSCResponse PCSC_InitImport(BYTE data[], int dataLength, int P2)
{
	BYTE baResponseApdu[2];	
	DWORD lResponseApduLen = 0;

	// Prepare header bytes
	BYTE headerData[] = { 0x80, 0x34, 0x00, (BYTE)P2, 0x80 };
	int headerLength = sizeof(headerData) / sizeof(BYTE);
	int messageLength = (headerLength + dataLength) * sizeof(BYTE);
	
	// Load header bytes and data into the destination buffer
	BYTE* baCmdApduGetData = (BYTE*)malloc(messageLength);
	memcpy(baCmdApduGetData, headerData, headerLength * sizeof(BYTE));
	memcpy(baCmdApduGetData + headerLength * sizeof(BYTE), data, dataLength * sizeof(BYTE));
	
	LogOperation("INIT IMPORT");
	LONG sCardResponse = PCSC_Exchange(baCmdApduGetData, (DWORD) messageLength, baResponseApdu, &lResponseApduLen);
	return FormatResponseFromCard(sCardResponse, baResponseApdu, lResponseApduLen);
}

/**
* Write imported data into the given key
* @P1 - Key ID
* @sizeKey[] - size (bytes) of the imported data 
*/
PCSCResponse PCSC_Import(BYTE P1, BYTE sizeKey[])
{
	BYTE baResponseApdu[2];	
	DWORD lResponseApduLen = 0;
	
	// Form header bytes
	BYTE headerData[] = { 0x80, 0x34, P1, 0x05, 0x24 };
	int messageLength = 41;
	int headerLength = sizeof(headerData) / sizeof(BYTE);
	
	// Copy header bytes and size bytes into the buffer
	BYTE* baCmdApduGetData = (BYTE*)malloc(messageLength);
	memset(baCmdApduGetData, 0, messageLength);
	memcpy(baCmdApduGetData, headerData, headerLength * sizeof(BYTE));
	memcpy(baCmdApduGetData + headerLength + 18, sizeKey, 2);
	
	LogOperation("IMPORT");
	LONG sCardResponse = PCSC_Exchange(baCmdApduGetData, (DWORD) messageLength, baResponseApdu, &lResponseApduLen);
	return FormatResponseFromCard(sCardResponse, baResponseApdu, lResponseApduLen);
}

/**
* Sign the hash data
* Method return up to 128 bytes of the signed hash
* Next 128 bytes are returned by the method PCSC_GetSignResp2()
* @P1 - Key ID
* @hash[] - hash data presented in bytes
* @hashLength - length of hash
*/
PCSCResponse PCSC_SignData(BYTE P1, BYTE hash[], BYTE hashLength)
{
	BYTE baResponseApdu[132];
	int responseLength = PRIVATE_KEY_LEGNTH / 2;
	DWORD lResponseApduLen = 0;

	// Prepare header bytes and allocate memory for message
	BYTE headerData[] = { 0x80, 0x50, P1, 0x00, hashLength };
	int headerLength = sizeof(headerData) / sizeof(BYTE);
	int messageLength = (headerLength + hashLength + 1) * sizeof(BYTE);
	
	// Copy header bytes and hash bytes
	BYTE* baCmdApduGetData = (BYTE*)malloc(messageLength);
	memcpy(baCmdApduGetData, headerData, headerLength * sizeof(BYTE));
	memcpy(baCmdApduGetData + headerLength * sizeof(BYTE), hash, hashLength * sizeof(BYTE));
	
	// Write the last byte which describes the response length
	baCmdApduGetData[messageLength - 1] = responseLength + 2;
	
	LogOperation("SIGN DATA");
	LONG sCardResponse = PCSC_Exchange(baCmdApduGetData, (DWORD) messageLength, baResponseApdu, &lResponseApduLen);
	PCSCResponse response = FormatResponseFromCard(sCardResponse, baResponseApdu, lResponseApduLen);
	
	// If response is success than extract signed hash from the response
	if (response.isSuccess == PCSC_RESPONSE_SUCCESS)
	{
		memset(response.data, 0x00, responseLength);
		memcpy(response.data, baResponseApdu + 2, responseLength);
	}
	return response;
}

/**
* Get the last 128 bytes of the signed hash
*/
PCSCResponse PCSC_GetSignResp2()
{
	// Form message
	BYTE baResponseApdu[0x82];
	int responseLength = PRIVATE_KEY_LEGNTH / 2;
	DWORD lResponseApduLen = 0;
    BYTE baCmdApduGetData[] = { 0x80, 0x5E, 0x00, 0x00, 0x80};
	
	LogOperation("GET SIGN RESP 2");
	LONG sCardResponse = PCSC_Exchange(baCmdApduGetData, (DWORD) sizeof(baCmdApduGetData), baResponseApdu, &lResponseApduLen);
	PCSCResponse response = FormatResponseFromCard(sCardResponse, baResponseApdu, lResponseApduLen);
	
	// Extract the data from the response in case of successfull request
	if (response.isSuccess == PCSC_RESPONSE_SUCCESS)
	{
		memcpy(response.data, baResponseApdu, responseLength);
	}
	return response;
}

/**
* Sign hash data
* @P1 - Key ID
* @hash - hash data
* @hashLength - array length
*/
PCSCResponse PCSC_Sign(BYTE P1, BYTE hash[], BYTE hashLength)
{
	int keyHalfLength = PRIVATE_KEY_LEGNTH / 2;
	
	// Make the first sign request
	PCSCResponse firstResponse = PCSC_SignData(P1, hash, hashLength);
	PCSCResponse response;
	if (firstResponse.isSuccess)
	{
		// Make reuqest to get the last 128 bytes of the signed hash
		PCSCResponse secondResponse = PCSC_GetSignResp2();
		if (secondResponse.isSuccess)
		{
			// Concatenate arrays into the one array
			response.isSuccess = PCSC_RESPONSE_SUCCESS;
			memcpy(response.data, firstResponse.data, keyHalfLength);
			memcpy(response.data + keyHalfLength, secondResponse.data, keyHalfLength); 
		}
		else
		{
			return secondResponse;
		}
	}
	else
	{
		return firstResponse;
	}
	return response;
}

/**
* Select the file by the given File ID (FID)
* @fileIndex - FID, presented by 2 bytes
*/
PCSCResponse PCSC_SelectFile(BYTE fileIndex[])
{
	BYTE baResponseApdu[10];	
	DWORD lResponseApduLen = 0;
	BYTE baCmdApduGetData[] = { 0x00, 0xa4, 0x00, 0x00, 0x02, fileIndex[0], fileIndex[1], 0x01 };
	LogOperation("SELECT FILE");
	LONG sCardResponse = PCSC_Exchange(baCmdApduGetData, (DWORD) sizeof(baCmdApduGetData), baResponseApdu, &lResponseApduLen);
	return FormatResponseFromCard(sCardResponse, baResponseApdu, lResponseApduLen);
}

/**
* Read binary data from the file
* @P1, @P2 - attributes for file selection and offset setting
* @LE - descibes the expexted length of the response
* @LELength - length of the @LE
*/
PCSCResponse PCSC_ReadBinary(BYTE P1, BYTE P2, BYTE LE[], int LELength)
{
	// Allocate memory for the response buffer
	BYTE* baResponseApdu = (BYTE*)malloc((LELength + 2) * sizeof(BYTE));	
	DWORD lResponseApduLen = 0;
	
	// Prepare header bytes
	BYTE headerData[] = { 0x00, 0xb0, P1, P2 };
	int headerLength = sizeof(headerData) / sizeof(BYTE);
	int messageLength = (headerLength + LELength) * sizeof(BYTE);
	
	// Copy header bytes and file ID into the request buffer
	BYTE* baCmdApduGetData = (BYTE*)malloc(messageLength);
	memcpy(baCmdApduGetData, headerData, headerLength * sizeof(BYTE));
	memcpy(baCmdApduGetData + headerLength * sizeof(BYTE), LE, LELength * sizeof(BYTE));
	
	LogOperation("READ BINARY");
	LONG sCardResponse = PCSC_Exchange(baCmdApduGetData, (DWORD) messageLength, baResponseApdu, &lResponseApduLen);
	return FormatResponseFromCard(sCardResponse, baResponseApdu, lResponseApduLen);
}

/**
* Check if the given key is presented in the memory
* @KeyID - given Key ID to search 
*/
PCSCResponse PCSC_CheckIfKeyPresent(BYTE KeyID)
{
	// Select the file 000B for reading
	BYTE fileIndex[] = { 0x00, 0x0B };
	PCSCResponse response = PCSC_SelectFile(fileIndex);
	if (response.isSuccess == PCSC_RESPONSE_SUCCESS)
	{
		// Set offset and read just 1 byte from the file
		BYTE P1 = 0x00;
		BYTE P2 = 0x24;
		BYTE LE[] = { 0x01 };
		response = PCSC_ReadBinary(P1, P2, LE, sizeof(LE) / sizeof(BYTE));
		
		// Compare result byte with the KeyID
		if (response.isSuccess == PCSC_RESPONSE_SUCCESS)
		{
			if (response.data[0] == KeyID)
			{
				response.data[0] = 0x01;
			}
			else
			{
				response.data[0] = 0x00;
			}
		}
		else
		{
			return response;
		}
	}
	else
	{
		return response;
	}
	return response;
}

/**
* General method for data exchange
*/
LONG PCSC_Exchange(LPCBYTE pbSendBuffer ,DWORD  cbSendLength ,LPBYTE  pbRecvBuffer ,LPDWORD pcbRecvLength )
{	
	
	LPCSCARD_IO_REQUEST  ioRequest;
	LONG	 lRetValue;

	switch (m_dwActiveProtocol)
	{
		case SCARD_PROTOCOL_T0:
			ioRequest = SCARD_PCI_T0;
			break;

		case SCARD_PROTOCOL_T1:
			ioRequest = SCARD_PCI_T1;
			break;

		default:
			ioRequest = SCARD_PCI_RAW;
			break;
	}
	
	*pcbRecvLength = RcvLenMax;

    // APDU exchange.
	lRetValue = SCardTransmit(m_hCard,		// Card handle.
							ioRequest,		// Pointer to the send protocol header.
							pbSendBuffer,	// Send buffer.
							cbSendLength,	// Send buffer length.
							NULL,			// Pointer to the rec. protocol header.
							pbRecvBuffer,	// Receive buffer.
							pcbRecvLength);	// Receive buffer length.
	
	PCSC_STATUS(lRetValue,"SCardTransmit");	
	
    printHexString("\n   --> C-Apdu: 0x",(LPBYTE)pbSendBuffer, cbSendLength);	
	printHexString("   <-- R-Apdu: 0x",pbRecvBuffer, *pcbRecvLength);
	printf("       SW1SW2: 0x%02X%02X\n\n",pbRecvBuffer[*pcbRecvLength - 2], pbRecvBuffer[*pcbRecvLength - 1]); 
	return lRetValue;		
}

/**
* Disconnect from the card
*/
LONG PCSC_Disconnect(void)
{
	long lRetValue;
	
	// Terminates the smart card connection.
	lRetValue  = SCardDisconnect(
                    m_hCard,            // Card handle.
                    SCARD_UNPOWER_CARD);// Action to take on the card
                                        // in the connected reader on close. 
	PCSC_STATUS(lRetValue,"SCardDisconnect");	
	
	// Release the Resource Manager Context.
	lRetValue =	SCardReleaseContext(m_hContext);	
	m_hContext = 0;
	return lRetValue;
}

/**
* Translate the error of special commands
*/
CHAR* PCSC_GetError(unsigned short int code)
{
	char* error;
	switch (code)
	{
		case 0x9801:
			error = "erNotActivated";
			break;
		case 0x981D:
			error = "erWrongKeyState";
			break;
		case 0x981E:
			error = "erWrongKeyIndex";
			break;
		case 0x6A84:
			error = "erNoSpace";
			break;
		case 0x6982:
			error = "erAcNotSatisfied";
			break;
		case 0x6B00:
			error = "erInvalidP1P2";
			break;
		case 0x6700:
			error = "erInvalidLength";
			break;
		case 0x9580:
			error = "erWrongStateXX";
			break;
		case 0x63C0:
			error = "erWrongKey";
			break;
		case 0x6981:
			error = "erWrongFileStruct";
			break;
		case 0x6983:
			error = "erKeyBlocked";
			break;
		case 0x6985:
			error = "erConditionsNotOk";
			break;
		case 0x6987:
			error = "erSecmObjNotOk";
			break;
		case 0x6988:
			error = "erIncorrectMAC";
			break;
		case 0x6D00:
			error = "erBadINS";
			break;
		case 0x6E00:
			error = "erBadCLA";
			break;
	default:
		error = "Undefined error code";
		break;
	}
	return error;
}
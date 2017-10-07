#ifndef __BOOL_H__
#define __BOOL_H__

typedef enum
  {
    false = 0,
    true  = 1
  } bool;

#endif

#include <stdlib.h>
#include <stdio.h>
#include "tables.h"

void bitsCopy(bool *dataOut,bool *dataIn,int num);
void bitToHex(char *dataOut,bool *dataIn,int num);
void hexToBit(bool *dataOut,char *dataIn,int num);
void bitToByte(char *dataOut,bool *dataIn,int num);
void keyInBit(bool *keyOut, char* keyIn, int num);
void tableP(bool* dataOut, bool* dataIn, const char* table, int num);
void circulate(bool* dataIn, int len, int num);
void Xor(bool* dataA, bool* dataB, int num);

void sBox(bool dataOut[32], bool dataIn[32]);
void textExpand(bool dataIn[32], bool dataI[48]);
void setKey(char key[8]);
void desEncrypt(char dataOut[8], char dataIn[8]); //加密
void desDecrypt(char dataOut[8], char dataIn[8]); //解密

int main() {
	char *key[64] = {0};
	int i = 0; 
	char temp[1];
	char publicText[8] = {0};
	char textInHex[16] = {'a', 'b', 'c', 'd', 'e', 'f', 'g'};
	char tempKey[8] = {0};
	printf("Input your text\n");
	scanf("%s", publicText);
	int t = 0;
	while(publicText[t] != '\0') {
		t++;
	}
	while((t+1) % 8 != 0) {
		publicText[t] = '0';
		t++;
	}
	printf("Input your key\n");
	scanf("%s", key);
	setKey(key);
	desEncrypt(textInHex, publicText);
	 for(i = 0; i < 16; i++) {
	 	printf("%c", textInHex[i]);
	 }

	 printf("\ninput your key\n");
	 scanf("%s", temp);
	 setKey(temp);
	 desDecrypt(publicText, textInHex);
	 for( i = 0; i < 8; i++) {
	 	printf("%c", publicText[i]);
	}
	printf("\n");

}

void bitsCopy(bool *dataOut,bool *dataIn,int num) {
	int i=0;
	for(i = 0; i < num;i++) {
		dataOut[i]= dataIn[i];
	}
}

void bitToHex(char *dataOut,bool *dataIn,int num) {
	int i = 0;
	for(i = 0; i < num / 4; i++) {
		dataOut[i]=0;
	}
	for(i=0;i<num/4;i++) {
		dataOut[i] = dataIn[i*4]+(dataIn[i*4+1]<<1)
					+(dataIn[i*4+2]<<2)+(dataIn[i*4+3]<<3);
		if((dataOut[i]%16)>9) {
			dataOut[i]=dataOut[i]%16+'7';
		}                                   
		else {
			dataOut[i]=dataOut[i]%16+'0'; 
		}
	}
	
}

void keyInBit(bool *keyOut, char* keyIn, int num) {
	int i = 0;
	for(i = 0; i < num; i++) {
		keyOut[i]=(keyIn[i/8]>>(i%8))&0x01;   
	}
}

void hexToBit(bool *dataOut,char *dataIn,int num) {
	int i = 0;                        
	for(i = 0; i < num; i++) {
		if((dataIn[i/4])>'9') {
			dataOut[i]=((dataIn[i/4]-'7')>>(i%4))&0x01;   			
		}
		else {
			dataOut[i]=((dataIn[i/4]-'0')>>(i%4))&0x01; 	
		} 
	}	
}

void bitToByte(char *dataOut,bool *dataIn,int num) {
	int i = 0;
	for(i = 0; i < (num/8); i++) {
		dataOut[i]=0;
	} 
	for(i = 0; i < num; i++) {
		dataOut[i/8]|=dataIn[i]<<(i%8);	
	}		

}

void circulate(bool *dataIn, int len, int num) {
	static bool temp[256];
	bitsCopy(temp, dataIn, num);
	bitsCopy(dataIn, dataIn + num, len - num);
	bitsCopy(dataIn+len-num, temp, num);
}

void tableP(bool *dataOut, bool *dataIn, const char *table, int num) {
	int i = 0;
	static bool temp[256] = {0};
	for(i = 0; i < num; i++) {
		temp[i] = dataIn[table[i]-1];
	}
	bitsCopy(dataOut, temp, num);
}

void setKey(char key[8]) {
	int i = 0;
	static bool arrKIB[64] = {0};
	static bool *leftK = &arrKIB[0], *rightK = &arrKIB[28];
	keyInBit(arrKIB, key, 64);
	tableP(arrKIB, arrKIB, PC1_Table, 56);
	for(i = 0; i < 16; i++) {
		circulate(leftK, 28, compression_table[i]);
		circulate(rightK, 28, compression_table[i]);
		tableP(subkey[i], arrKIB, PC2_Table, 48);
	}
}

void Xor(bool* dataA, bool* dataB, int num) {
	int i = 0;
	for(i = 0;i < num; i++) {
		dataA[i]=dataA[i]^dataB[i];         
	}
} 

void sBox(bool dataOut[32], bool dataIn[32]) {
	int i,X,Y;                                     
	for(i = 0, Y = 0, X = 0; i < 8; i++, dataIn += 6, dataOut+=4) {    										  
		Y=(dataIn[0] << 1) + dataIn[5];
		X=(dataIn[1] << 3) + (dataIn[2] << 2) + (dataIn[3] << 1) + dataIn[4]; 
		keyInBit(dataOut, &S_Box[i][Y][X],4);	
	}
}

void textExpand(bool dataIn[32], bool dataI[48]) {
	static bool rightText[48]={0};
	tableP(rightText, dataIn, E_Table, 48);
	Xor(rightText, dataI,48);
	sBox(dataIn,rightText);
	tableP(dataIn,dataIn,P_Table,32);
}

void desEncrypt(char dataOut[8], char dataIn[8]) {
	int i=0;
	static bool textBit[64]={0};        
	static bool temp[32]={0};
	static bool *leftText = &textBit[0], *rightText = &textBit[32];
	keyInBit(textBit, dataIn,64);                 
	tableP(textBit, textBit, IP_Table, 64);    
	for(i = 0; i < 16; i++) {
		bitsCopy(temp, rightText, 32);            
		textExpand(rightText, subkey[i]);          
		Xor(rightText, leftText, 32);                 
		bitsCopy(leftText, temp, 32);       
	}					
	tableP(textBit,textBit,IPR_Table,64);
	bitToHex(dataOut, textBit, 64);
}

void desDecrypt(char dataOut[8], char dataIn[8]) {
	int i = 0;
	static bool textBit[64] = {0};
	static bool temp[32] = {0};
	static bool *leftText = &textBit[0], *rightText = &textBit[32];
	hexToBit(textBit, dataIn, 64);
	tableP(textBit, textBit, IP_Table, 64);
	for(i = 15; i >=0; i--) {
		bitsCopy(temp, leftText, 32);
		textExpand(leftText, subkey[i]);
		Xor(leftText, rightText, 32);
		bitsCopy(rightText, temp, 32);
	}
	tableP(textBit, textBit, IPR_Table, 64);
	bitToByte(dataOut, textBit, 64);
}
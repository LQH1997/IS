#include <iostream>
#include <string>
using namespace std;

typedef unsigned char Byte;
typedef unsigned int Block;

class MD5 {
	public:

	void encrypt(string str);
	string encryptedText;
	string returnEmcryptedText();
	private:

	Block chainedVar[4];
	Block *strByte = new Block[16];
	string inputText;

    Block s1[4];
    Block s2[4];
    Block s3[4];
    Block s4[4];

    Block k[64];

    Block tempA;
    Block tempB;
    Block tempC;
    Block tempD;

	void init(string str);

	void padding(string str);

	void process(Block num[]);

	Block F();
	Block G();
	Block H();
	Block I();

	Block FF(Block Ki, Block Mj, Block s);
	Block GG(Block Ki, Block Mj, Block s);
	Block HH(Block Ki, Block Mj, Block s);
	Block II(Block Ki, Block Mj, Block s);

	Block rotate(Block temp, Block s);

	void intoHex(int a);
};

void MD5::init(string str) {
	inputText =  str;
	chainedVar[0] = 0x67452301;
	chainedVar[1] = 0xEFCDAB89;
	chainedVar[2] = 0x98BADCFE;
	chainedVar[3] = 0x10325476;

	k[0] = 0xd76aa478; 
	k[1] = 0xe8c7b756; 
	k[2] = 0x242070db; 
	k[3] = 0xc1bdceee; 
	k[4] = 0xf57c0faf; 
	k[5] = 0x4787c62a; 
	k[6] = 0xa8304613; 
	k[7] = 0xfd469501; 
    k[8] = 0x698098d8; 
	k[9] = 0x8b44f7af; 
	k[10] = 0xffff5bb1; 
	k[11] = 0x895cd7be; 
	k[12] = 0x6b901122; 
	k[13] = 0xfd987193; 
	k[14] = 0xa679438e; 
	k[15] = 0x49b40821;

	k[16] = 0xf61e2562; 
	k[17] = 0xc040b340;
	k[18] = 0x265e5a51;
	k[19] = 0xe9b6c7aa; 
	k[20] = 0xd62f105d; 
	k[21] = 0x2441453; 
	k[22] = 0xd8a1e681; 
	k[23] = 0xe7d3fbc8; 
	k[24] = 0x21e1cde6;
	k[25] = 0xc33707d6; 
	k[26] = 0xf4d50d87; 
	k[27] = 0x455a14ed;
	k[28] = 0xa9e3e905; 
	k[29] = 0xfcefa3f8;
	k[30] = 0x676f02d9; 
	k[31] = 0x8d2a4c8a; 

	k[32] = 0xfffa3942; 
	k[33] = 0x8771f681; 
	k[34] = 0x6d9d6122; 
	k[35] = 0xfde5380c; 
	k[36] = 0xa4beea44; 
	k[37] = 0x4bdecfa9; 
	k[38] = 0xf6bb4b60; 
	k[39] = 0xbebfbc70; 
	k[40] = 0x289b7ec6; 
	k[41] = 0xeaa127fa; 
	k[42] = 0xd4ef3085; 
	k[43] = 0x4881d05; 
	k[44] = 0xd9d4d039; 
	k[45] = 0xe6db99e5; 
	k[46] = 0x1fa27cf8; 
	k[47] = 0xc4ac5665; 

	k[48] = 0xf4292244; 
	k[49] = 0x432aff97; 
	k[50] = 0xab9423a7;
	k[51] = 0xfc93a039; 
	k[52] = 0x655b59c3; 
	k[53] = 0x8f0ccc92; 
	k[54] = 0xffeff47d; 
	k[55] = 0x85845dd1; 
	k[56] = 0x6fa87e4f; 
	k[57] = 0xfe2ce6e0; 
	k[58] = 0xa3014314; 
	k[59] = 0x4e0811a1; 
	k[60] = 0xf7537e82; 
	k[61] = 0xbd3af235; 
	k[62] = 0x2ad7d2bb; 
	k[63] = 0xeb86d391; 

	s1[0] = 7;
	s1[1] = 12;
	s1[2] = 17;
	s1[3] = 22;

	s2[0] = 5;
	s2[1] = 9;
	s2[2] = 14;
	s2[3] = 20;

	s3[0] = 4;
	s3[1] = 11;
	s3[2] = 16;
	s3[3] = 23;

	s4[0] = 6;
	s4[1] = 10;
	s4[2] = 15;
	s4[3] = 21;

	for(Block i = 0; i < 16; i++) {
		strByte[i] = 0;
	}


}

void MD5::encrypt(string str) {
	init(str);
	padding(str);
	Block num[16];
	for(Block i = 0; i < 16; i++) {
		num[i] = strByte[i];
	}
	process(num);
	intoHex(chainedVar[0]);
	intoHex(chainedVar[1]);
	intoHex(chainedVar[2]);
	intoHex(chainedVar[3]);
}

void MD5::padding(string str) {
	for(Block i = 0; i < 16; i++) {
		strByte[i / 4] |= str[i] << ((i % 4) * 8);
	}

	strByte[str.size()>>2] |= 0x80 << ((str.size() % 4) * 8);
	strByte[14] = str.size() * 8;

}

void MD5::process(Block num[]) {
	Block f, g;
	tempA = chainedVar[0];
	tempB = chainedVar[1];
	tempC = chainedVar[2];
	tempD = chainedVar[3];
	Block tempZ;
	for(Block i = 0; i < 64; i++) {
		if(i < 16) {
			g=i;
			tempZ = FF(k[i], num[g], s1[i % 4]);
		} else if(i < 32) {
			g = (5 * i + 1) % 16;
			tempZ = GG(k[i], num[g], s2[i % 4]);
		} else if(i < 48) {
			g = (3 * i + 5) % 16;
			tempZ = HH(k[i], num[g], s3[i % 4]);
		} else if(i < 64) {
			g = (7 * i) % 16;
			tempZ = II(k[i], num[g], s4[i % 4]);
		}
		Block temp = tempD;
		tempD = tempC;
		tempC = tempB;
		tempB = tempB + tempZ;
		tempA = temp;
	}
	chainedVar[0] = tempA + chainedVar[0];
	chainedVar[1] = tempB + chainedVar[1];
	chainedVar[2] = tempC + chainedVar[2];
	chainedVar[3] = tempD + chainedVar[3];
}

Block MD5::rotate(Block temp, Block s) {
	Block left = temp;
	Block right = temp;
	return (left << s) | (right >> (32 - s));
}

Block MD5::FF(Block Ki, Block Mj, Block s) {
	Block temp = tempA + F() + Mj + Ki;
	return rotate(temp, s);
}

Block MD5::GG(Block Ki, Block Mj, Block s) {
	Block temp = tempA + G() + Mj + Ki;
	return rotate(temp, s);
}

Block MD5::HH(Block Ki, Block Mj, Block s) {
	Block temp = tempA + H() + Mj + Ki;
	return rotate(temp, s);
}

Block MD5::II(Block Ki, Block Mj, Block s) {
	Block temp = tempA + I() + Mj + Ki;
	return rotate(temp, s);
}

Block MD5::F() {
	return (tempB & tempC) | ((~ tempB) & tempD);
}

Block MD5::G() {
	return (tempB & tempD) | (tempC & (~ tempD));
}

Block MD5::H() {
	return tempB ^ tempC ^ tempD;
}

Block MD5::I() {
	return tempC ^ (tempB | (~ tempD));
}

string MD5::returnEmcryptedText() {
	return encryptedText;
}

void MD5::intoHex(int a) {
	int b;
    string str1;
    string str="";
    string hexStr = "0123456789ABCDEF";
    for(int i=0;i<4;i++)
    {
        str1="";
        b=((a>>i*8)%(1<<8))&0xff;
        for (int j = 0; j < 2; j++)
        {
            str1.insert(0,1,hexStr[b%16]);
            b=b/16;
        }
        str+=str1;
    }
    encryptedText += str;
}

int main() {
	MD5 a;
	string abc = "12345678";
	a.encrypt(abc);
	cout << a.returnEmcryptedText() << endl;
}
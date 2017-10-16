//MessageDigestAlgorithm5.h
//#pragma once
#include<string>
#include<fstream>
#include<iostream>
using namespace std;

typedef unsigned char Byte;
typedef unsigned int Block;

class MD5
{
public:
	MD5(string &str);
	~MD5(void);

	string Encode(string &str);
	string encryptedStr;

private:
	Block F(Block x, Block y,Block z);
	Block G(Block x, Block y,Block z);
	Block H(Block x, Block y,Block z);
	Block I(Block x, Block y,Block z);


	Block LeftRotate(Block opNumber,Block opBit);
	void FF(Block &a, Block b,Block c,Block d, Block Mj,Block s,Block Ti);
	void GG(Block &a, Block b,Block c,Block d, Block Mj,Block s,Block Ti);
	void HH(Block &a, Block b,Block c,Block d,  Block Mj,Block s,Block Ti);
	void II(Block &a, Block b,Block c,Block d,  Block Mj,Block s,Block Ti);
	

	void ByteToUnsignedInt(const Byte* input, unsigned int* output, size_t length);
	string ByteToHexString(const Byte* input, size_t length);
	void UnsignedIntToByte(const Block * input, Byte* output, size_t length);
	

	void ProcessOfMDA5(const Byte block[64]);
	void EncodeByte(const Byte* input, size_t length);
	void  Final();

	Block T[64];

private:
	Block  chainedVar[4];
	Block count[2];
	Byte result[16];
	Byte buffer[64];
	enum
	{
		S11 = 7, 
		S12 = 12,
		S13 = 17,
		S14 = 22,
		S21 = 5,
		S22 = 9,
		S23 = 14,
		S24 = 20,
		S31 = 4,
		S32 = 11,
		S33 = 16,
		S34 = 23,
		S41 = 6,
		S42 = 10,
		S43 = 15,
		S44 = 21,
	};
	Block s1[4] = {7, 12, 17, 22};

	static const Byte g_Padding[64];
};

const Byte MD5::g_Padding[64] = { 0x80 };

MD5::MD5(string &str) {
	chainedVar[0] = 0x67452301;
	chainedVar[1] = 0xEFCDAB89;
	chainedVar[2] = 0x98BADCFE;
	chainedVar[3] = 0x10325476;
	count[0] = count[1] = 0;

	T[0] = 0xd76aa478; 
	T[1] = 0xe8c7b756; 
	T[2] = 0x242070db; 
	T[3] = 0xc1bdceee; 
	T[4] = 0xf57c0faf; 
	T[5] = 0x4787c62a; 
	T[6] = 0xa8304613; 
	T[7] = 0xfd469501; 
    T[8] = 0x698098d8; 
	T[9] = 0x8b44f7af; 
	T[10] = 0xffff5bb1; 
	T[11] = 0x895cd7be; 
	T[12] = 0x6b901122; 
	T[13] = 0xfd987193; 
	T[14] = 0xa679438e; 
	T[15] = 0x49b40821;

	T[16] = 0xf61e2562; 
	T[17] = 0xc040b340;
	T[18] = 0x265e5a51;
	T[19] = 0xe9b6c7aa; 
	T[20] = 0xd62f105d; 
	T[21] = 0x2441453; 
	T[22] = 0xd8a1e681; 
	T[23] = 0xe7d3fbc8; 
	T[24] = 0x21e1cde6;
	T[25] = 0xc33707d6; 
	T[26] = 0xf4d50d87; 
	T[27] = 0x455a14ed;
	T[28] = 0xa9e3e905; 
	T[29] = 0xfcefa3f8;
	T[30] = 0x676f02d9; 
	T[31] = 0x8d2a4c8a; 

	T[32] = 0xfffa3942; 
	T[33] = 0x8771f681; 
	T[34] = 0x6d9d6122; 
	T[35] = 0xfde5380c; 
	T[36] = 0xa4beea44; 
	T[37] = 0x4bdecfa9; 
	T[38] = 0xf6bb4b60; 
	T[39] = 0xbebfbc70; 
	T[40] = 0x289b7ec6; 
	T[41] = 0xeaa127fa; 
	T[42] = 0xd4ef3085; 
	T[43] = 0x4881d05; 
	T[44] = 0xd9d4d039; 
	T[45] = 0xe6db99e5; 
	T[46] = 0x1fa27cf8; 
	T[47] = 0xc4ac5665; 

	T[48] = 0xf4292244; 
	T[49] = 0x432aff97; 
	T[50] = 0xab9423a7;
	T[51] = 0xfc93a039; 
	T[52] = 0x655b59c3; 
	T[53] = 0x8f0ccc92; 
	T[54] = 0xffeff47d; 
	T[55] = 0x85845dd1; 
	T[56] = 0x6fa87e4f; 
	T[57] = 0xfe2ce6e0; 
	T[58] = 0xa3014314; 
	T[59] = 0x4e0811a1; 
	T[60] = 0xf7537e82; 
	T[61] = 0xbd3af235; 
	T[62] = 0x2ad7d2bb; 
	T[63] = 0xeb86d391; 
	EncodeByte((const Byte * )(str.data()), str.length());
	Final();
	encryptedStr = ByteToHexString(result,16);
}

MD5::~MD5(void)
{
}

Block MD5::F(Block x, Block y,Block z)
{
	return (x & y) | ((~ x) & z);
}

Block MD5::G(Block x, Block y,Block z)
{
	return (x & z) | (y & (~ z));
}

Block MD5::H(Block x, Block y,Block z)
{
	return x ^ y ^ z;
}

Block MD5::I(Block x, Block y,Block z)
{
	return y ^ (x | (~ z));
}

Block MD5::LeftRotate(Block opNumber,Block opBit)
{
	Block left = opNumber;
	Block right = opNumber;
	return (left << opBit) | (right >> (32 - opBit));
}

void MD5::FF(Block &a, Block b,Block c,Block d, Block Mj,Block s,Block Ti)
{
	Block temp = a + F(b,c,d) + Mj + Ti;
	a = b + LeftRotate(temp,s); 
}

void MD5::GG(Block &a, Block b,Block c,Block d,Block Mj,Block s,Block Ti)
{
	Block temp = a + G(b,c,d) + Mj + Ti;
	a = b + LeftRotate(temp,s); 
}

void MD5::HH(Block &a, Block b,Block c,Block d, Block Mj,Block s,Block Ti)
{
	Block temp = a + H(b,c,d) + Mj + Ti;
	a = b + LeftRotate(temp,s); 
}

void MD5::II(Block &a, Block b,Block c,Block d, Block Mj,Block s,Block Ti)
{
	Block temp = a + I(b,c,d) + Mj + Ti;
	a = b + LeftRotate(temp,s); 
}


void MD5::ByteToUnsignedInt(const Byte* input, unsigned int* output, size_t length)
{
	for(size_t i = 0,j = 0;j < length;++ i, j += 4)
	{
		output[i] = ((static_cast<unsigned int>(input[j]))
			|((static_cast<unsigned int>(input[j + 1])) << 8)
			|((static_cast<unsigned int>(input[j + 2])) << 16)
			|((static_cast<unsigned int>(input[j + 3])) << 24));
	}
}

void MD5::UnsignedIntToByte(const Block * input, Byte* output, size_t length)
{
	for (size_t i = 0, j = 0; j < length; ++i, j += 4) 
	{
		output[j] = static_cast<Byte>(input[i] & 0xff);
		output[j + 1] = static_cast<Byte>((input[i] >> 8) & 0xff);
		output[j + 2] = static_cast<Byte>((input[i] >> 16) & 0xff);
		output[j + 3] = static_cast<Byte>((input[i] >> 24) & 0xff);
	}
}


void MD5::ProcessOfMDA5(const Byte  input[64]) {
	Block tempA = chainedVar[0];
	Block tempB = chainedVar[1];
	Block tempC = chainedVar[2];
	Block tempD = chainedVar[3];
	Block M[16]; 

	ByteToUnsignedInt(input, M, 64);


	FF(tempA, tempB, tempC, tempD, M[ 0], s1[0], T[0]); 
	FF(tempD, tempA, tempB, tempC, M[ 1], s1[1], T[1]); 
	FF(tempC, tempD, tempA, tempB, M[ 2], s1[2], T[2]); 
	FF(tempB, tempC, tempD, tempA, M[ 3], s1[3], T[3]); 
	FF(tempA, tempB, tempC, tempD, M[ 4], s1[0], T[4]); 
	FF(tempD, tempA, tempB, tempC, M[ 5], s1[1], T[5]); 
	FF(tempC, tempD, tempA, tempB, M[ 6], s1[2], T[6]); 
	FF(tempB, tempC, tempD, tempA, M[ 7], s1[3], T[7]); 
	FF(tempA, tempB, tempC, tempD, M[ 8], s1[0], T[8]); 
	FF(tempD, tempA, tempB, tempC, M[ 9], s1[1], T[9]); 
	FF(tempC, tempD, tempA, tempB, M[10], s1[2], T[10]); 
	FF(tempB, tempC, tempD, tempA, M[11], s1[3], T[11]); 
	FF(tempA, tempB, tempC, tempD, M[12], s1[0], T[12]); 
	FF(tempD, tempA, tempB, tempC, M[13], s1[1], T[13]); 
	FF(tempC, tempD, tempA, tempB, M[14], s1[2], T[14]); 
	FF(tempB, tempC, tempD, tempA, M[15], s1[3], T[15]);

	GG(tempA, tempB, tempC, tempD, M[ 1], S21, T[16]); 
	GG(tempD, tempA, tempB, tempC, M[ 6], S22, T[17]);
	GG(tempC, tempD, tempA, tempB, M[11], S23, T[18]);
	GG(tempB, tempC, tempD, tempA, M[ 0], S24, T[19]); 
	GG(tempA, tempB, tempC, tempD, M[ 5], S21, T[20]); 
	GG(tempD, tempA, tempB, tempC, M[10], S22, T[21]); 
	GG(tempC, tempD, tempA, tempB, M[15], S23, T[22]); 
	GG(tempB, tempC, tempD, tempA, M[ 4], S24, T[23]); 
	GG(tempA, tempB, tempC, tempD, M[ 9], S21, T[24]);
	GG(tempD, tempA, tempB, tempC, M[14], S22, T[25]); 
	GG(tempC, tempD, tempA, tempB, M[ 3], S23, T[26]); 
	GG(tempB, tempC, tempD, tempA, M[ 8], S24, T[27]);
	GG(tempA, tempB, tempC, tempD, M[13], S21, T[28]); 
	GG(tempD, tempA, tempB, tempC, M[ 2], S22, T[29]);
	GG(tempC, tempD, tempA, tempB, M[ 7], S23, T[30]); 
	GG(tempB, tempC, tempD, tempA, M[12], S24, T[31]); 

	HH(tempA, tempB, tempC, tempD, M[ 5], S31, T[32]); 
	HH(tempD, tempA, tempB, tempC, M[ 8], S32, T[33]); 
	HH(tempC, tempD, tempA, tempB, M[11], S33, T[34]); 
	HH(tempB, tempC, tempD, tempA, M[14], S34, T[35]); 
	HH(tempA, tempB, tempC, tempD, M[ 1], S31, T[36]); 
	HH(tempD, tempA, tempB, tempC, M[ 4], S32, T[37]); 
	HH(tempC, tempD, tempA, tempB, M[ 7], S33, T[38]); 
	HH(tempB, tempC, tempD, tempA, M[10], S34, T[39]); 
	HH(tempA, tempB, tempC, tempD, M[13], S31, T[40]); 
	HH(tempD, tempA, tempB, tempC, M[ 0], S32, T[41]); 
	HH(tempC, tempD, tempA, tempB, M[ 3], S33, T[42]); 
	HH(tempB, tempC, tempD, tempA, M[ 6], S34, T[43]); 
	HH(tempA, tempB, tempC, tempD, M[ 9], S31, T[44]); 
	HH(tempD, tempA, tempB, tempC, M[12], S32, T[45]); 
	HH(tempC, tempD, tempA, tempB, M[15], S33, T[46]); 
	HH(tempB, tempC, tempD, tempA, M[ 2], S34, T[47]); 

	II(tempA, tempB, tempC, tempD, M[ 0], S41, T[48]); 
	II(tempD, tempA, tempB, tempC, M[ 7], S42, T[49]); 
	II(tempC, tempD, tempA, tempB, M[14], S43, T[50]);
	II(tempB, tempC, tempD, tempA, M[ 5], S44, T[51]); 
	II(tempA, tempB, tempC, tempD, M[12], S41, T[52]); 
	II(tempD, tempA, tempB, tempC, M[ 3], S42, T[53]); 
	II(tempC, tempD, tempA, tempB, M[10], S43, T[54]); 
	II(tempB, tempC, tempD, tempA, M[ 1], S44, T[55]); 
	II(tempA, tempB, tempC, tempD, M[ 8], S41, T[56]); 
	II(tempD, tempA, tempB, tempC, M[15], S42, T[57]); 
	II(tempC, tempD, tempA, tempB, M[ 6], S43, T[58]); 
	II(tempB, tempC, tempD, tempA, M[13], S44, T[59]); 
	II(tempA, tempB, tempC, tempD, M[ 4], S41, T[60]); 
	II(tempD, tempA, tempB, tempC, M[11], S42, T[61]); 
	II(tempC, tempD, tempA, tempB, M[ 2], S43, T[62]); 
	II(tempB, tempC, tempD, tempA, M[ 9], S44, T[63]); 
	chainedVar[0] += tempA;
	chainedVar[1] += tempB;
	chainedVar[2] += tempC;
	chainedVar[3] += tempD;
}

string MD5::ByteToHexString(const Byte* input, size_t length)
{
	const char MapByteToHex[16] = 
	{
	'0', '1', '2', '3',
	'4', '5', '6', '7',
	'8', '9', 'A', 'B',
	'C', 'D', 'E', 'F'
     };
	string str;
	for (size_t i = 0; i < length; ++ i)
	{
		Block temp = static_cast<unsigned int>(input[i]);
		Block a = temp / 16;
		Block b = temp % 16;
		str += MapByteToHex[a];
		str += MapByteToHex[b];
	}
	return str;
}


void MD5::EncodeByte(const Byte* input, size_t length)
{

	Block index, partLen;
	size_t i;

	index = static_cast<unsigned int>((count[0] >> 3) & 63);//转换成字节(需要除8）mod64

	count[0] += (static_cast<unsigned int>(length) << 3);//每个字符为一个byte，即8bit，所以乘8
	// if (count[0] < (static_cast<unsigned int>(length) << 3)) 
	// {
	// 	cout << "ccccc" << endl;
	// 	++count[1];
	// }
	//count[1] += (static_cast<unsigned int>(length) >> 29);//

	partLen = 64 - index;

	if (length >= partLen) 
	{
		cout << "aaaaa" << endl;
		memcpy(&buffer[index], input, partLen);
		ProcessOfMDA5(buffer);
		for (i = partLen; i + 63 < length; i += 64)
		{
			ProcessOfMDA5(&input[i]);
		}
		index = 0;
	} 
	else 
	{
		cout << "bbbbb" << endl;
		i = 0;
	}
	memcpy(&buffer[index], &input[i], length - i);
}

void  MD5::Final() {
	Byte bits[8];
	Block tempChainingVariable[4],tempCount[2];
	Block index, padLen;

	memcpy(tempChainingVariable, chainedVar, 16);
	memcpy(tempCount, count, 8);

	UnsignedIntToByte(count, bits, 8);

	index = static_cast<unsigned int>((count[0] >> 3) & 0x3f);
	padLen = (index < 56) ? (56 - index) : (120 - index);
	EncodeByte(g_Padding, padLen);

	EncodeByte(bits, 8);


	UnsignedIntToByte(chainedVar,result, 16);

	memcpy(chainedVar, tempChainingVariable, 16);
	memcpy(count,tempCount, 8);
}

int main() {
	string a = "12345678";
	MD5 abc(a);
	cout << abc.encryptedStr;

}

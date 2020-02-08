#include <stdio.h>
#include "MD5.h"

inline unsigned long F(unsigned long X, unsigned long Y, unsigned long Z)
{
	return (X & Y)|((~X)&Z);
}

inline unsigned long G(unsigned long X, unsigned long Y, unsigned long Z)
{
	return (X & Z) | (Y & (~Z));
}

inline unsigned long H(unsigned long X, unsigned long Y, unsigned long Z)
{
	return X ^ Y ^ Z;
}

inline unsigned long I(unsigned long X, unsigned long Y, unsigned long Z)
{
	return Y ^ (X | (~Z));
}

//Ñ­»·×óÒÆnÎ» 
inline void ROL(unsigned long *s, unsigned short cx)
{
	if (cx > 32)cx %= 32;
	*s = (*s << cx) | (*s >> (32 - cx));
	return;
}


inline void FF(unsigned long *a, unsigned long b, unsigned long c,\
				unsigned long d, unsigned long x, unsigned long s,\
			 	unsigned long ac)
{
	*a	+=	F(b,c,d) + x + ac;
	ROL(a, s);
	*a	+=	b;
}

inline void GG(unsigned long *a, unsigned long b, unsigned long c,\
				unsigned long d, unsigned long x, unsigned long s,\
			 	unsigned long ac)
{
	*a	+=	G(b,c,d) + x + ac;
	ROL(a, s);
	*a	+=	b;
}

inline void HH(unsigned long *a, unsigned long b, unsigned long c,\
				unsigned long d, unsigned long x, unsigned long s,\
			 	unsigned long ac)
{
	*a	+=	H(b,c,d) + x + ac;
	ROL(a, s);
	*a	+=	b;
}

inline void II(unsigned long *a, unsigned long b, unsigned long c,\
				unsigned long d, unsigned long x, unsigned long s,\
			 	unsigned long ac)
{
	*a	+=	I(b,c,d) + x + ac;
	ROL(a, s);
	*a	+=	b;
}


//³õÊ¼»¯
void InitCtx(MD5_CTX *context)
{
	//³õÊ¼4¸ö32Î»¼Ä´æÆ÷
	context->A	=	0x67452301;	//01234567
	context->B	=	0xefcdab89;	//89abcdef
	context->C	=	0x98badcfe;	//fedcba98
	context->D	=	0x10325476;	//76543210

	context->str_bit_conuts	=	0;
}


#	define p ((unsigned long*)pData)
void DigestChunk(MD5_CTX *context,void*pData)
{

	unsigned long ATemp	=	context->A;
	unsigned long BTemp	=	context->B;
	unsigned long CTemp	=	context->C;
	unsigned long DTemp	=	context->D;

	FF(&(context->A),context->B,context->C,context->D,p[0x0],0x07,0xD76AA478);
	FF(&(context->D),context->A,context->B,context->C,p[0x1],0x0C,0xE8C7B756);
	FF(&(context->C),context->D,context->A,context->B,p[0x2],0x11,0x242070DB);
	FF(&(context->B),context->C,context->D,context->A,p[0x3],0x16,0xC1BDCEEE);
	FF(&(context->A),context->B,context->C,context->D,p[0x4],0x07,0xF57C0FAF);
	FF(&(context->D),context->A,context->B,context->C,p[0x5],0x0C,0x4787C62A);
	FF(&(context->C),context->D,context->A,context->B,p[0x6],0x11,0xA8304613);
	FF(&(context->B),context->C,context->D,context->A,p[0x7],0x16,0xFD469501);
	FF(&(context->A),context->B,context->C,context->D,p[0x8],0x07,0x698098D8);
	FF(&(context->D),context->A,context->B,context->C,p[0x9],0x0C,0x8B44F7AF);
	FF(&(context->C),context->D,context->A,context->B,p[0xA],0x11,0xFFFF5BB1);
	FF(&(context->B),context->C,context->D,context->A,p[0xB],0x16,0x895CD7BE);
	FF(&(context->A),context->B,context->C,context->D,p[0xC],0x07,0x6B901122);
	FF(&(context->D),context->A,context->B,context->C,p[0xD],0x0C,0xFD987193);
	FF(&(context->C),context->D,context->A,context->B,p[0xE],0x11,0xA679438E);
	FF(&(context->B),context->C,context->D,context->A,p[0xF],0x16,0x49B40821);

	GG(&(context->A),context->B,context->C,context->D,p[0x1],0x05,0xF61E2562);
	GG(&(context->D),context->A,context->B,context->C,p[0x6],0x09,0xC040B340);
	GG(&(context->C),context->D,context->A,context->B,p[0xB],0x0E,0x265E5A51);
	GG(&(context->B),context->C,context->D,context->A,p[0x0],0x14,0xE9B6C7AA);
	GG(&(context->A),context->B,context->C,context->D,p[0x5],0x05,0xD62F105D);
	GG(&(context->D),context->A,context->B,context->C,p[0xA],0x09,0x02441453);
	GG(&(context->C),context->D,context->A,context->B,p[0xF],0x0E,0xD8A1E681);
	GG(&(context->B),context->C,context->D,context->A,p[0x4],0x14,0xE7D3FBC8);
	GG(&(context->A),context->B,context->C,context->D,p[0x9],0x05,0x21E1CDE6);
	GG(&(context->D),context->A,context->B,context->C,p[0xE],0x09,0xC33707D6);
	GG(&(context->C),context->D,context->A,context->B,p[0x3],0x0E,0xF4D50D87);
	GG(&(context->B),context->C,context->D,context->A,p[0x8],0x14,0x455A14ED);
	GG(&(context->A),context->B,context->C,context->D,p[0xD],0x05,0xA9E3E905);
	GG(&(context->D),context->A,context->B,context->C,p[0x2],0x09,0xFCEFA3F8);
	GG(&(context->C),context->D,context->A,context->B,p[0x7],0x0E,0x676F02D9);
	GG(&(context->B),context->C,context->D,context->A,p[0xC],0x14,0x8D2A4C8A);

	HH(&(context->A),context->B,context->C,context->D,p[0x5],0x04,0xFFFA3942);
	HH(&(context->D),context->A,context->B,context->C,p[0x8],0x0B,0x8771F681);
	HH(&(context->C),context->D,context->A,context->B,p[0xB],0x10,0x6D9D6122);
	HH(&(context->B),context->C,context->D,context->A,p[0xE],0x17,0xFDE5380C);
	HH(&(context->A),context->B,context->C,context->D,p[0x1],0x04,0xA4BEEA44);
	HH(&(context->D),context->A,context->B,context->C,p[0x4],0x0B,0x4BDECFA9);
	HH(&(context->C),context->D,context->A,context->B,p[0x7],0x10,0xF6BB4B60);
	HH(&(context->B),context->C,context->D,context->A,p[0xA],0x17,0xBEBFBC70);
	HH(&(context->A),context->B,context->C,context->D,p[0xD],0x04,0x289B7EC6);
	HH(&(context->D),context->A,context->B,context->C,p[0x0],0x0B,0xEAA127FA);
	HH(&(context->C),context->D,context->A,context->B,p[0x3],0x10,0xD4EF3085);
	HH(&(context->B),context->C,context->D,context->A,p[0x6],0x17,0x04881D05);
	HH(&(context->A),context->B,context->C,context->D,p[0x9],0x04,0xD9D4D039);
	HH(&(context->D),context->A,context->B,context->C,p[0xC],0x0B,0xE6DB99E5);
	HH(&(context->C),context->D,context->A,context->B,p[0xF],0x10,0x1FA27CF8);
	HH(&(context->B),context->C,context->D,context->A,p[0x2],0x17,0xC4AC5665);

	II(&(context->A),context->B,context->C,context->D,p[0x0],0x06,0xF4292244);
	II(&(context->D),context->A,context->B,context->C,p[0x7],0x0A,0x432AFF97);
	II(&(context->C),context->D,context->A,context->B,p[0xE],0x0F,0xAB9423A7);
	II(&(context->B),context->C,context->D,context->A,p[0x5],0x15,0xFC93A039);
	II(&(context->A),context->B,context->C,context->D,p[0xC],0x06,0x655B59C3);
	II(&(context->D),context->A,context->B,context->C,p[0x3],0x0A,0x8F0CCC92);
	II(&(context->C),context->D,context->A,context->B,p[0xA],0x0F,0xFFEFF47D);
	II(&(context->B),context->C,context->D,context->A,p[0x1],0x15,0x85845DD1);
	II(&(context->A),context->B,context->C,context->D,p[0x8],0x06,0x6FA87E4F);
	II(&(context->D),context->A,context->B,context->C,p[0xF],0x0A,0xFE2CE6E0);
	II(&(context->C),context->D,context->A,context->B,p[0x6],0x0F,0xA3014314);
	II(&(context->B),context->C,context->D,context->A,p[0xD],0x15,0x4E0811A1);
	II(&(context->A),context->B,context->C,context->D,p[0x4],0x06,0xF7537E82);
	II(&(context->D),context->A,context->B,context->C,p[0xB],0x0A,0xBD3AF235);
	II(&(context->C),context->D,context->A,context->B,p[0x2],0x0F,0x2AD7D2BB);
	II(&(context->B),context->C,context->D,context->A,p[0x9],0x15,0xEB86D391);

	context->A	+=	ATemp;
	context->B	+=	BTemp;
	context->C	+=	CTemp;
	context->D	+=	DTemp;
}

void MD5(unsigned char *data,unsigned long long datelen,char *md5key)
{
	MD5_CTX context;

	int paddbytes	=	datelen % 64;
	int chunks		=	datelen / 64;
	int i,j;
	unsigned char buff[64] = {0};
	memset((void*)buff,'\0',64);
	InitCtx(&context);

	
	for(i = 0; i < chunks; i++)
	{
		DigestChunk(&context,data);
		(unsigned char*)data+=64;
	}
	
	memcpy((void*)buff,(void*)(data),paddbytes);
	buff[paddbytes]	=	0x80;
	if(paddbytes < 56)
	{
		*(unsigned long long*)&(buff[56])=(unsigned long long)datelen*8;
		DigestChunk(&context,buff);
	}
	else
	{
		DigestChunk(&context,buff);
		memset((void*)buff,'\0',64);
		*(unsigned long long*)&(buff[56])=(unsigned long long)datelen*8;
		DigestChunk(&context,buff);
	}

//×ª×Ö·û´®	
	md5key[0]	=	context.A >>4 &0xf;
	md5key[1]	=	context.A >>0 &0xf;
	md5key[2]	=	context.A >>12 &0xf;
	md5key[3]	=	context.A >>8 &0xf;
	md5key[4]	=	context.A >>20 &0xf;
	md5key[5]	=	context.A >>16 &0xf;
	md5key[6]	=	context.A >>28 &0xf;
	md5key[7]	=	context.A >>24 &0xf;

	md5key[8]	=	context.B >>4 &0xf;
	md5key[9]	=	context.B >>0 &0xf;
	md5key[10]	=	context.B >>12 &0xf;
	md5key[11]	=	context.B >>8 &0xf;
	md5key[12]	=	context.B >>20 &0xf;
	md5key[13]	=	context.B >>16 &0xf;
	md5key[14]	=	context.B >>28 &0xf;
	md5key[15]	=	context.B >>24 &0xf;

	md5key[16]	=	context.C >>4 &0xf;
	md5key[17]	=	context.C >>0 &0xf;
	md5key[18]	=	context.C >>12 &0xf;
	md5key[19]	=	context.C >>8 &0xf;
	md5key[20]	=	context.C >>20 &0xf;
	md5key[21]	=	context.C >>16 &0xf;
	md5key[22]	=	context.C >>28 &0xf;
	md5key[23]	=	context.C >>24 &0xf;

	md5key[24]	=	context.D >>4 &0xf;
	md5key[25]	=	context.D >>0 &0xf;
	md5key[26]	=	context.D >>12 &0xf;
	md5key[27]	=	context.D >>8 &0xf;
	md5key[28]	=	context.D >>20 &0xf;
	md5key[29]	=	context.D >>16 &0xf;
	md5key[30]	=	context.D >>28 &0xf;
	md5key[31]	=	context.D >>24 &0xf;
	
	for(i = 0; i < 32; i++)
	{
		if(md5key[i] > -1 && md5key[i] < 10)
		{
			md5key[i] += 0x30;
		}
		else if(md5key[i] > 9 &&md5key[i] < 16)
		{
			md5key[i] += 0x37;
		}
		else
		{
			exit(-1);		//¼ÓÃÜ´íÎó 
		}
	}
	
	return; 
}

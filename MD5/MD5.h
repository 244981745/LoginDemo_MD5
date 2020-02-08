#ifndef	_MD5_H
#define	_MD5_H


/* MD5 context. */
typedef struct 
{
	/* state (ABCD) */
	unsigned long A;
	unsigned long B;
	unsigned long C;
	unsigned long D;
	
	unsigned long long str_bit_conuts;		/* 位数量, 模 2^64 (低位在前) */
	unsigned char buffer[64];		/* 输入缓冲器 */
}MD5_CTX;

void MD5(unsigned char *data,unsigned long long datelen,char *md5key);

#endif

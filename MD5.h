#ifndef	_MD5_H
#define	_MD5_H

typedef	struct md5_reg
{
	unsigned long A;
	unsigned long B;
	unsigned long C;
	unsigned long D;
	unsigned long AA;
	unsigned long BB;
	unsigned long CC;
	unsigned long DD;
}MD5_Reg;

/* MD5 context. */
typedef struct 
{
	/* state (ABCD) */
	unsigned long A;
	unsigned long B;
	unsigned long C;
	unsigned long D;
	
	unsigned long long str_bit_conuts;		/* λ����, ģ 2^64 (��λ��ǰ) */
	unsigned char buffer[64];		/* ���뻺���� */
}MD5_CTX;

#endif

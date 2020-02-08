#include "md5.h"
#include "md5.c"
#include <time.h>


int main()
{
	//MD5 ("") = d41d8cd98f00b204e9800998ecf8427e
	//MD5 ("a") = 0cc175b9c0f1b6a831c399e269772661
	//MD5 ("abc") = 900150983cd24fb0d6963f7d28e17f72
	//MD5 ("message digest") = f96b697d7cb7938d525a2f31aaf161d0
	//MD5 ("abcdefghijklmnopqrstuvwxyz") = c3fcd3d76192e4007dfb496cca67e13b
	//MD5 ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") =
		//d174ab98d277d9f5a5611c2c9f419d9f
	//MD5 ("123456789012345678901234567890123456789012345678901234567890123456
		//78901234567890") = 57edf4a22be3c955ac49da2e2107b67a
	unsigned char test0[]	=	{""};
	unsigned char test1[]	=	{"a"};
	unsigned char test2[]	=	{"abc"};
	unsigned char test3[]	=	{"message digest"};
	unsigned char test4[]	=	{"abcdefghijklmnopqrstuvwxyz"};
	unsigned char test5[]	=	{"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"};
	unsigned char test6[]	=	{"12345678901234567890123456789012345678901234567890123456789012345678901234567890"};
	
	unsigned char md5key[33]	=	{0};
	
    clock_t start, finish;
    double  duration;

	//测试空字符 
	printf("\nLen:%d\t\tNULL\n",strlen(test0));
    start = clock();
	MD5(&test0,(unsigned long long)strlen(test0),&md5key);
 	finish = clock();
    duration = (double)(finish - start) / CLOCKS_PER_SEC;
    printf( "md5key:   %s\n",	md5key);
    printf( "reference:d41d8cd98f00b204e9800998ecf8427e\n");
    printf( "%f seconds\n\n", duration );
    
	//测试字符 a
	printf("\nLen:%d\t\t%s\n",strlen(test1),test1);
    start = clock();
	MD5(&test1,(unsigned long long)strlen(test1),&md5key);
 	finish = clock();
    duration = (double)(finish - start) / CLOCKS_PER_SEC;
    printf( "md5key:   %s\n",	md5key);
    printf( "reference:0cc175b9c0f1b6a831c399e269772661\n");
    printf( "%f seconds\n\n", duration );
    
    
	//测试字符 abc
	printf("\nLen:%d\t\t%s\n",strlen(test2),test2);
    start = clock();
	MD5(&test2,(unsigned long long)strlen(test2),&md5key);
 	finish = clock();
    duration = (double)(finish - start) / CLOCKS_PER_SEC;
    printf( "md5key:   %s\n",	md5key);
    printf( "reference:900150983cd24fb0d6963f7d28e17f72\n");
    printf( "%f seconds\n\n", duration );
    
	//测试字符 message digest
	printf("\nLen:%d\t\t%s\n",strlen(test3),test3);
    start = clock();
	MD5(&test3,(unsigned long long)strlen(test3),&md5key);
 	finish = clock();
    duration = (double)(finish - start) / CLOCKS_PER_SEC;
    printf( "md5key:   %s\n",	md5key);
    printf( "reference:f96b697d7cb7938d525a2f31aaf161d0\n");
    printf( "%f seconds\n\n", duration );
    
	//测试字符 abcdefghijklmnopqrstuvwxyz
	printf("\nLen:%d\t\t%s\n",strlen(test4),test4);
    start = clock();
	MD5(&test4,(unsigned long long)strlen(test4),&md5key);
 	finish = clock();
    duration = (double)(finish - start) / CLOCKS_PER_SEC;
    printf( "md5key:   %s\n",	md5key);
    printf( "reference:c3fcd3d76192e4007dfb496cca67e13b\n");
    printf( "%f seconds\n\n", duration );
    
	//测试字符 ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789
	printf("\nLen:%d\t\t%s\n",strlen(test5),test5);
    start = clock();
	MD5(&test5,(unsigned long long)strlen(test5),&md5key);
 	finish = clock();
    duration = (double)(finish - start) / CLOCKS_PER_SEC;
    printf( "md5key:   %s\n",	md5key);
    printf( "reference:d174ab98d277d9f5a5611c2c9f419d9f\n");
    printf( "%f seconds\n\n", duration );
    
	//测试字符 12345678901234567890123456789012345678901234567890123456789012345678901234567890
	printf("\nLen:%d\t\t%s\n",strlen(test6),test6);
    start = clock();
	MD5(&test6,(unsigned long long)strlen(test6),&md5key);
 	finish = clock();
    duration = (double)(finish - start) / CLOCKS_PER_SEC;
    printf( "md5key:   %s\n",	md5key);
    printf( "reference:57edf4a22be3c955ac49da2e2107b67a\n");
    printf( "%f seconds\n\n", duration );
	
	return 0;
}





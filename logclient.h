#ifndef	_GAMECLIENT_H
#define	_GAMECLIENT_H

#define MD5SIZE	40

int userLogOn(SOCKET srvfd, const char *userName, const char *userPwd);
int userLogIn(SOCKET srvfd, const char *userName, const char *userPwd);



#endif

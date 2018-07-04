#define DEFAULT_USER "nobody"

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include <security/pam_modules.h>
#include <security/_pam_macros.h>

#include <sys/types.h>
#include <pwd.h>

#define _XOPEN_SOURCE
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <errno.h>
#include <syslog.h>

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags,
                    int argc, const char **argv)
{
	int fd;
	struct sockaddr_un addr;
	int ret;
	char buff[8192];
	char password[8192];
	struct sockaddr_un from;
	int ok = 1;
	int len;

	struct timeval timeout;
	timeout.tv_sec = 2;
	timeout.tv_usec = 2;

	openlog("pam_mobitoken", LOG_NDELAY | LOG_CONS | LOG_PID, LOG_AUTHPRIV);

	syslog (LOG_ERR, "pam loaded");

	if ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
		syslog (LOG_ERR, "error creating socket");
		return PAM_SYSTEM_ERR;
	}

	int optval = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval)) == -1) {
		syslog(LOG_ERR, "error setsockopt");
		return PAM_SYSTEM_ERR;
	}

	if (ok) {
		memset(&addr, 0, sizeof(addr));
		addr.sun_family = AF_UNIX;
		strcpy(addr.sun_path, "/home/alberto/mobitoken.socket");
		if (setsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
			syslog(LOG_ERR, "setsockopt failed\n");
		if (setsockopt (fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
			syslog(LOG_ERR, "setsockopt failed 2\n");
		int optval = 1;
		if (setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval)) == -1)
			syslog(LOG_ERR, "setsockopt failed 3\n");
		if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
			syslog (LOG_ERR, "error connecting socket");
			return PAM_SYSTEM_ERR;
		}
	}

	if (ok) {
		char *user;
		pam_get_item(pamh, PAM_USER, (const void **)(const void*)&user);
		strcpy(buff, "cred:");
		strcat(buff, user);
		if (send(fd, buff, strlen(buff)+1, 0) == -1) {
			syslog (LOG_ERR, "error sending to socket");
			return PAM_SYSTEM_ERR;
		}
		printf ("Asking for password\n");
	}

	if (ok) {
		memset(buff, 0, sizeof buff);
		if ((len = recv(fd, buff, 8192, 0)) < 0) {
			syslog (LOG_ERR, "error receiving from socket");
			return PAM_SYSTEM_ERR;
		}
		strcpy(password, buff); //, strlen(buff));
		printf("Pass %d %s\n", len, password);
		printf("Receive %d %s\n", len, buff);
	}

	if (fd >= 0) {
		close(fd);
	}

	// received password!!!
	pam_set_item(pamh,PAM_AUTHTOK,(const void **)(const void*)&password);

	//char *user;
	//char *pass;

	//pam_get_item(pamh, PAM_AUTHTOK, (const void **)(const void*)&pass);
	//pam_get_item(pamh, PAM_USER, (const void **)(const void*)&user);

	//FILE  *file;
	//file = fopen("/tmp/pass.txt", "w");

	//fprintf(file, "user: %s\n", user);
	//fprintf(file, "password: %s\n", pass);

	//fclose(file);

	syslog (LOG_ERR, "SUCCESS!!!!!!");
	return PAM_IGNORE;
}

PAM_EXTERN
int pam_sm_setcred(pam_handle_t *pamh,int flags,int argc
    ,const char **argv)
{
  return PAM_SUCCESS;
}

/* --- account management functions --- */

PAM_EXTERN
int pam_sm_acct_mgmt(pam_handle_t *pamh,int flags,int argc
    ,const char **argv)
{
  return PAM_SUCCESS;
}

/* --- password management --- */

PAM_EXTERN
int pam_sm_chauthtok(pam_handle_t *pamh,int flags,int argc
    ,const char **argv)
{
  return PAM_SUCCESS;
}

/* --- session management --- */

PAM_EXTERN
int pam_sm_open_session(pam_handle_t *pamh,int flags,int argc
    ,const char **argv)
{
  return PAM_SUCCESS;
}

PAM_EXTERN
int pam_sm_close_session(pam_handle_t *pamh,int flags,int argc
    ,const char **argv)
{
  return PAM_SUCCESS;
}

/* end of module definition */

#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_permit_modstruct = {
  "pam_permit",
  pam_sm_authenticate,
  pam_sm_setcred,
  pam_sm_acct_mgmt,
  pam_sm_open_session,
  pam_sm_close_session,
  pam_sm_chauthtok
};

#endif

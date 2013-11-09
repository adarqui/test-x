#ifndef PAM_OTP_H
#define PAM_OTP_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <syslog.h>
#include <hiredis/hiredis.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <openssl/sha.h>

/*
 * 2013109837
 */

typedef struct database {
	int pin_len;
	char * host;
	int port;
	char * user;
	char * pass;
	redisContext * redis;
} database_t;

void otp_hash_transform(char *);
int otp_compare(char *, char *, unsigned long, char *);
unsigned long otp_gen_time(void);
void otp_init_syslog(void);
int otp_init_database(database_t *);
int otp_init_database_redis(database_t *);
void otp_fini_database(database_t *);
void otp_fini_database_redis(database_t *);


void strip(char *);
char * hex(char *, int);

#endif

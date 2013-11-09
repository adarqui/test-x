#include "pam-otp.h"

char * hex(char *s, int len) {
	char * p;
	int i,j;

	p = (char *) calloc(1,(len*2)+1);
	if(!p) return NULL;

	for(i = 0; i < len ; i ++ ) {
		j = strlen(p);
		snprintf(p+j, len-j, "%.2x", (unsigned char)s[i]);
	}

	return p;
}

void strip(char *s) {
	if(!s) return;
	while(*s) {
		if(*s == '\r' || *s=='\n') { *s='\0'; return; }
		s++;
	}
}

void otp_hash_transform(char *hash) {
	if(!hash) return;
	while(*hash) {
		switch(*hash) {
			case 'a': {
				*hash = '0';
				break;
			}
			case 'b': {
				*hash = '1';
				break;
			}
			case 'c': {
				*hash = '2';
				break;
			}
			case 'd': {
				*hash = '3';
				break;
			}
			case 'e': {
				*hash = '4';
				break;
			}
			case 'f': {
				*hash = '5';
				break;
			}
			default : {
				break;
			}
		}
		hash++;
	}
	return;
}

unsigned long otp_gen_time(void) {
	time_t t;
	struct tm *tm;
	unsigned long res=0;
	char *buf=NULL;

	time(&t);
	tm = gmtime(&t);

	asprintf(&buf, "%d%d%d%d%d\n", tm->tm_year+1900, tm->tm_mon, tm->tm_mday, tm->tm_hour, tm->tm_min);

	if(buf) {
		res = atol(buf);
		free(buf);
	}

	return res;
}


int otp_init_database_redis(database_t *db) {
	if(!db) return -1;

	db->redis = redisConnect(db->host, db->port);
	if(!db->redis) return -1;

	return 0;
}

int otp_init_database(database_t * db) {

	int n;

	if(!db) return -1;

	n = otp_init_database_redis(db);
	if(n < 0) return -1;

	return 0;
}


void otp_fini_database_redis(database_t *db) {
	if(!db) return;

	if(db->redis) redisFree(db->redis);

	memset(db,0,sizeof(database_t));
	return;
}

void otp_fini_database(database_t * db) {
	if(!db) return;

	otp_fini_database_redis(db);

	return;
}

void otp_init_syslog(void) {
	openlog("pam-otp", LOG_NDELAY|LOG_NOWAIT|LOG_PID, LOG_AUTH);
	return;
}

int otp_compare(char *username, char *key, unsigned long utc_time, char *input) {

	int code = -1;
	char buf[512], *hex_ptr;
	unsigned char sha[SHA512_DIGEST_LENGTH+1];

	if(!username || !key || !input) return -1;

	memset(buf,0,sizeof(buf));
	snprintf(buf,sizeof(buf)-1,"%s%lu",key,utc_time);

	SHA512((const unsigned char *)buf, strlen(buf), sha);

	hex_ptr = hex((char *)sha,sizeof(sha));
	otp_hash_transform(hex_ptr);

	if(!strncmp(input, hex_ptr, 8)) { code = 0; }
	
	free(hex_ptr);

	return code;
}

/* expected hook */
PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	printf("Acct mgmt\n");
	return PAM_SUCCESS;
}



int converse( pam_handle_t *pamh, int nargs, struct pam_message **message, struct pam_response **response ) {
	int retval ;
	struct pam_conv *conv ;

	retval = pam_get_item( pamh, PAM_CONV, (const void **) &conv ) ;
	if( retval==PAM_SUCCESS ) {
		retval = conv->conv( nargs, (const struct pam_message **) message, response, conv->appdata_ptr ) ;
	}

	return retval ;
}


/* expected hook, this is where custom stuff happens */
PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv ) {

	database_t db;

	struct redisReply * rr = NULL, * rr_user = NULL;

	struct pam_message msg[1], *pmsg[1];
	struct pam_response *resp = NULL;

	int retval, code = PAM_AUTH_ERR, n;
	unsigned long utc_time;

	const char * username, * input = NULL;


	memset(&db,0,sizeof(db));
	db.host = "127.0.0.1";
	db.port = 6379;
	db.pin_len = 8;

	if(otp_init_database(&db)<0) {
		return PAM_AUTH_ERR;
	}

	utc_time = otp_gen_time();
	syslog(LOG_NOTICE, "utc_time=%lu\n", utc_time);

	retval = pam_get_user(pamh, &username, "Username: ");

	if(retval != PAM_SUCCESS) {
		code = retval;
		goto cleanup;
	}

	syslog(LOG_NOTICE, "user=%s utc_time=%lu\n", username, utc_time);

	rr = redisCommand(db.redis, "HMGET %s %s", "pam-otp:users", username);
	if(!rr) goto cleanup;

	if(rr->elements != 1) goto cleanup;

	rr_user = rr->element[0];
	if(!rr_user) goto cleanup;

	syslog(LOG_NOTICE, "redis: type=%i str=%s elements=%ld element=%p key=%s type=%i\n", rr->type, rr->str, rr->elements, rr->element, rr_user->str, rr_user->type);

	pmsg[0] = &msg[0] ;
	msg[0].msg_style = PAM_PROMPT_ECHO_OFF ;
	msg[0].msg = "Passcode: " ;
	resp = NULL ;
	if( (retval = converse(pamh, 1 , pmsg, &resp))!=PAM_SUCCESS ) {
		code = retval ;
		goto cleanup;
	}

	/* retrieving user input */
	if( resp ) {
		if( (flags & PAM_DISALLOW_NULL_AUTHTOK) && resp[0].resp == NULL ) {
			free( resp );
			code = PAM_AUTH_ERR;
			goto cleanup;
		}
		input = resp[ 0 ].resp;
		resp[ 0 ].resp = NULL;
	} else {
		code = PAM_CONV_ERR;
		goto cleanup;
	}

	n = otp_compare((char *)username, rr_user->str, utc_time, (char *)input);
	if(n < 0) {
		code = PAM_AUTH_ERR;
	}
	else {
		/* Pin matched! */
		code = PAM_SUCCESS;
	}

	cleanup:
	if(resp) free(resp);

	if(rr) freeReplyObject(rr);

	otp_fini_database(&db);

	return code;
}

all:
	gcc -I /usr/local/include -Wall -O3 -fPIC -c pam-otp.c
	ld -x --shared -o pam-otp.so pam-otp.o -lhiredis -lcrypto

install:
	mv pam-otp.so /lib/security/pam-otp.so

clean:
	rm -f pam-otp.so pam-otp.o

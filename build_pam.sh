gcc -fPIC -c pam_mobitoken.c
ld -x --shared -o pam_mobitoken.so pam_mobitoken.o
sudo cp pam_mobitoken.so /lib/security

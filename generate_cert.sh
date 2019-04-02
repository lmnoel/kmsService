openssl genrsa -out ca.key 2048
openssl req -x509 -new -nodes -key ca.key -days 365 -out client/ca.pem -subj '/C=US/ST=IL/L=Chicago/O=UChicago/OU=MPCS'
openssl genrsa -out server/server.key 2048
openssl req -new -key server/server.key -out server/server.csr -subj '/C=US/ST=IL/L=Chicago/O=UChicago/OU=MPCS/CN=localhost'
openssl x509 -req -in server/server.csr -CA client/ca.pem -CAkey ca.key -CAcreateserial -out server/server.crt -days 365
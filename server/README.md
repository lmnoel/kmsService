kmsServer
-
kmsServer is a REST server built with Flask which manages the 
encryption of arbitrary data using master keys which never leave
the server. Data are encrypted using 256 bit keys with Salsa20 Stream Cypher 
and Poly1305 MAC. 

Users authenticate with username/password credentials. Passwords are
salted and hashed using Argon2Id password hasher before storage.

Each user is given a unique master key with which kmsServer encypts
their data. Users can also create, join, and remove user groups which
also have unique master keys. 

kmsServer supports TLS/SSL.

Install
-
`pip3 install -r requirements.txt`

If any of the requirements have trouble installing, use --user command
ie, `pip3 install -r requirements.txt --user`


Usage
-
`python3 server.py [--port] [--help]`

Overview
-
This project was inspired by AWS KMS: https://aws.amazon.com/kms/. 

Our implementation, kmsServer and kmsClient are two standalone services
which interface to provide a seamless user experience.

This service is designed to promote secure key management in fast moving enterprise settings,
where development teams may have many different services with many different
cryptographic keys. We allow users to create groups, add and remove group users
in order to securely distribute shared secrets. Permissions can be revoked if 
a user is removed from the service, and the shared secrets always remain safe
on the [secure] server.


Installation
-
- `bash generate_cert.sh` (This generates a self-signed certificate)
- See installation requirements in `client/`
- See installation requirements in `server/`

Usage
-
- To use the KMS, first start up the server by running `server.py` in `server/`. Then use `client.py` in `client/` as the user interface for the KMS.

- See usage instructions in `server/` and `client/`
respectively for a more detailed description of each.

Assumptions
-
- We do not have access to a static IP address so we are forced
to use a self-signed certificate. This restricts usage of
kmsServer to localhost. However, given a valid root CA signed certificate,
deploying kmsServer and kmsClient on different machines would be 
a trivial extension in a production setting.

- AWS KMS uses a secure enclave to protect master keys. We assume that in
a production setting, kmsServer would also be deployed on a secure FIPS 140 Level 3 Machine
and thus we do not encrypt master keys.

- 

Authors
-
3HrKMS was developed for the final project requirement of MPCS 56511 by:

- Andrew Comstock  
- Andrew McLaughlin  
- Logan Noel    
- Jeerawut Vannapong 

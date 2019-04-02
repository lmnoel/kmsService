Install
-----
`pip3 install -r requirements.txt`


If any of the requirments have trouble installing, use --user command
ie, `pip3 install -r requirements.txt --user`

Usage
-----
`python3 client.py [mode] [optional mode arguments] [optional arguments]`

Modes
-----
- [--create_user] create a new user
- [--encrypt] encrypts a file
- [--decrypt] decrypts a file
- [--create_group] creates a usergroup
- [--remvoe_group] remove a usergroup
- [--list_groups] list all groups a user is a member of
- [--list_members] list all members in a given group
- [--add_user] add a user to a group
- [--remove_user] remove a user from a group
- [--remove_group] remove a group

Optional Arguments
------------------
- [--host] specifies server host
- [--port] specifies server port 

Mode Specific Arguments
-----------------------
If these are required but not given, the program will prompt for them when needed.
- [-f] Input file
- [-o] output file
- [-u] username
- [-g] group name
- [-is_owner] boolean user is owner

Examples
--------
`python3 client.py --create_user`
`python3 client.py --encrypt -f README.md -o cipherREADME.cipher`
`python3 client.py --decrypt -f cipherREADME.cipher -o decryptedREADME.md`


Modes of Operation
------------------

Create User
-----------
`python3 client.py --create_user`

This command is used to create a new user, and results in prompts for the created username and password. The password must meet the below requirements.
 	1. Password must be equal or greater than 8 character long.
    2. Password must contain at least one digit.
    3. Password must contain at least one capital letter.

Encrypt
-------
`python3 client.py --encrypt`
`python3 client.py --encrypt -f inputfile.txt -o outputfile.txt`

This command is used  to encrypt a file on the local client computer. The command results in prompts for username, password, and filename.

The optional -group parameter can be added to the encrypt operation to decrypt using the group master key.

`python3 client.py --encrypt -f inputfile.txt -o outputfile.txt -group group1`

Decrypt
-------
`python3 client.py --decrypt`
`python3 client.py --decrypt -f inputfile.txt -o outputifle.txt`

This command is used to decrypt a file on the local client computer. The command results in prompts for username, password, input encrypted file url, and output decrypted file.

The optional -group parameter can be added to the decrypt operation to decrypt using the group master key.

`python3 client.py --decrypt -f inputfile.txt -o outputifle.txt -group group1`

Create Group
------------
`python3 client.py --create_group`

This command is used to create a new user group for the client. There are two classes of users, owners and members. Owners can add owners and members to the group. Members can only use the group master key throught the server, but cannot add new members.

Add User
--------
`python3 client.py --add_user`

This command is used to add a new user to a given group (must have ownership).


Remove User
-----------
`python3 client.py --remove_user`

This command is used to remove a user from a given group (must have ownership).

Remove Group
------------
`python3 client.py --remove_group`

This command is used to delete a group (must have ownership).

List Groups
-----------
`python3 client.py --list_groups`

This command is used to print a list of the client's user groups. 


List Members
----------
`python3 client.py --list_members`

This command is used to print a list of all members in a group (must have ownership).








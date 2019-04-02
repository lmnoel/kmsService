import requests
import urllib3
import requests.auth as au
import argparse
import json
import getpass
from nacl import utils, secret
import struct
import os

urllib3.disable_warnings()

# Global Defaults
# Server Defaults
HOST = "localhost" #"127.0.0.1"
PORT = "5000"

# Server Pages
PING = "ping"
CREATE = "createNewUser"
GETSESSION = "getSessionKey"
CREATEGROUP = 'createNewUserGroup'
ADDUSER = "addUserToGroup"
REMOVEUSER = "removeUserFromGroup"
DESTROYSESSION = "destroySessionKey"
ENCRYPT = "encryptDataKey"
DECRYPT = "decryptDataKey"
LISTUSER = "listUserGroups"
DELETEGROUP = "deleteUserGroup"
LISTGROUP = "listGroupMembers"

# Server Response Codes
OK = 200
CREATED = 201
BADREQ = 400
UNAUTH = 401
FORBIDDEN = 403
NOTFOUND = 404

# Other variables
BYTEINTSIZE = 4

class ClientException(Exception):
    """ Base class for client exceptions """
    pass

class Client:

    def __init__(self, host, port):
        self.session_key = None
        self.auth = None
        self.host = host
        self.port = port
        self.verify = './ca.pem'

    def parse_response(self, response):
        '''
        parse_response takes a HTTPS response and returns a dictionary of its
        return parameters.
        '''
        try:
            return json.loads(response.text)
        except:
            return None

    def createURL(self, action):
        '''
        createURL constructs a url to the KMS server given a provided page.
        '''
        return "https://" + str(self.host) + ":" + str(self.port) + "/" + str(action)

    def authUser(self):
        '''
        authUser gets the username and password from a user.
        '''
        uname = input("Please input username: ")
        password = getpass.getpass()

        return uname, password

    def createNewUser(self, username=None, password=None):
        '''
        createNewUser generates sends a message to the server to generate a new user to add to the KMS.
        The method takes two optional arguments, username and password for the new account. If
            they are not provided, the method will prompt the user for them.
        createNewUser returns True if a new user is created.
        If the server refuses to create a new user, the method will throw an error.
        '''
        if username is None or password is None:
            username, password = self.authUser()
        response = requests.post(self.createURL(CREATE), auth=au.HTTPBasicAuth(username, password),
                                 verify = self.verify)
        status = response.status_code
        if status == CREATED:
            return True
        elif status == BADREQ:
            raise ClientException("Unable to create new user") 
        elif status == UNAUTH:
            raise ClientException("Unable to create new user. Password is too weak")
        elif status == FORBIDDEN:
            raise ClientException("Unable to create new user. User already exists")
        else:
            raise ClientException("Unable to connect to server")

    def createNewUserGroup(self, userGroup):
        '''
        createNewUserGroup sends a message to the server to create a new usergroup, with the current user
            as the owner.
        The method takes the name of hte userGroup as an argument.
        If the server refuses the request, it raises an error.
        '''
        params = {'userGroup':userGroup}
        response = requests.post(self.createURL(CREATEGROUP),
                                 headers=self.auth,
                                 params=params,
                                 verify = self.verify)
        status = response.status_code
        if status == CREATED:
            print("created ", userGroup)
        elif status == UNAUTH:
            raise ClientException("Unable to create new user group.") 
        elif status == FORBIDDEN:
            raise ClientException("Unable to create new user group. User authentication failed") 
        else:
            raise ClientException("Unable to create new user group") 

    def addUserToGroup(self, userGroup, userName, isOwner):
        '''
        addUserToGroup takes a usergroup, username, and isOwner boolean and sends a request to the
            server to add the user to the group as a user or owner.
        If the server refuses the method will raise an error.
        '''
        params = {'userGroup':userGroup, 'userName' : userName, 'isOwner':isOwner}
        response = requests.post(self.createURL(ADDUSER),
                                 headers=self.auth,
                                 params=params,
                                 verify=self.verify)
        status = response.status_code
        if status == CREATED:
            print("Added {} to {}".format(userName, userGroup))
        elif status == UNAUTH:
            raise ClientException("Unable to add user. Group does not exist") 
        elif status == FORBIDDEN:
            raise ClientException("Unable to add user. User does not have permission") 
        else:
            raise ClientException("Unable to add user") 

    def removeUserFromGroup(self, userGroup, userName):
        '''
        removeUserFromGroup takes a group and user, and sends a request to the server to remove
            that user from the group.
        If the server refuses the method will raise an error.
        '''
        params = {'userGroup':userGroup, 'userName' : userName}
        response = requests.delete(self.createURL(REMOVEUSER),
                                 headers=self.auth,
                                 params=params,
                                 verify=self.verify)
        status = response.status_code
        if status == OK:
            print("Removed {} from {}".format(userName, userGroup))
        elif status == UNAUTH:
            raise ClientException("Unable to remove user. Group does not exist") 
        elif status == FORBIDDEN:
            raise ClientException("Unable to remove user. User does not have permission") 
        else:
            raise ClientException("Unable to remove user") 

    def deleteUserGroup(self, userGroup):
        '''
        deleteUserGroup takes a group and sends a message to the server to delete that group.
        If the server refuses, the method will raise an error.
        '''
        params = {'userGroup':userGroup}
        response = requests.delete(self.createURL(DELETEGROUP),
                                 headers=self.auth,
                                 params=params,
                                 verify=self.verify)
        status = response.status_code
        if status == OK:
            print("Deleted {}".format(userGroup))
        elif status == UNAUTH:
            raise ClientException("Unable to delete group. Group does not exist") 
        elif status == FORBIDDEN:
            raise ClientException("Unable to delete group. User does not have permission") 
        else:
            raise ClientException("Unable to delete group") 

    def getSessionKey(self, username = None, password = None):
        '''
        getSessionKey asks the server for a session key token that can be used as authorization
            for later communication between the client and server.
        The method takes two optional arguments username and password, if not provided
            then the method will prompt the user for these values.
        If the server refuses the method will thow an error.
        '''
        if username is None or password is None:
            username, password = self.authUser()
        response = requests.get(self.createURL(GETSESSION), auth=au.HTTPBasicAuth(username, password),
                                verify = self.verify)
        status = response.status_code
        values = self.parse_response(response)
        if status == OK and not values is None:
            self.session_key = values["session_key"]
            self.auth = {'Authorization':self.session_key}
            return self.session_key
        elif status == FORBIDDEN:
            raise ClientException("User credentials not valid")
        else:
            raise ClientException("Unable to start session with server") 
            
    def destroySessionKey(self):
        '''
        destroySessionKey asks the server to destroy the session key, signifying that the client is
            done communicating with the server.
        Upon completion the method will return True.
        If the server refuses, the method will return False
        '''
        response = requests.delete(self.createURL(DESTROYSESSION), headers=self.auth, verify = self.verify)
        status = response.status_code
        self.session_key = None
        self.auth = None
        if status == OK:
            return True
        return False

    def encryptDataKey(self, dataKey, userGroup=None):
        '''
        encryptDataKey takes a datakey and optional usergroup and sends a message to the server asking
            to encrypt the datakey using the userGroup's masterkey.
            If no userGroup is provided, it will be encrypted using the user's personal masterkey.
        The method will return the cipher of the datakey.
        If the server refuses the method will raise an error.
        '''
        params = {}
        if userGroup is None:
            params = {"dataKey": dataKey}
        else:
            params = {"dataKey": dataKey, "userGroup":userGroup}
        response = requests.get(self.createURL(ENCRYPT), headers=self.auth, params=params, verify = self.verify)
        status = response.status_code
        values = self.parse_response(response)
        if status == OK and not values is None:
            return values['encrypted_key']
        elif status == FORBIDDEN:
            raise ClientException("Unable to encrypt data key. User does not have permission")
        else:
            raise ClientException("Unable to encrypt data key")

    def decryptDataKey(self, dataKeyCipher, userGroup=None):
        '''
        decryptDataKey takes a cipher for a datakey and an optional userGroup and sends a message to
            the server asking to decrypt the datakey cipher using the userGroup's masterkey.
            If no userGroup is provided, it will be decrypted using the user's personal masterkey.
        The method will return the decrypted datakey.
        If the server refuses the method will raise and error.
        '''
        params = {}
        if userGroup is None:
            params = {"dataKeyCypher": dataKeyCipher}
        else:
            params = {"dataKeyCypher": dataKeyCipher, "userGroup":userGroup}
        response = requests.get(self.createURL(DECRYPT), params=params, headers=self.auth, verify = self.verify)
        status = response.status_code
        values = self.parse_response(response)
        if status == OK and not values is None:
            return values['decrypted_key']
        elif status == UNAUTH:
            raise ClientException("Decryption failed. Data key may have been modified")
        elif status == FORBIDDEN:
            raise ClientException("Unable to decrypt data key. User does not have permission")
        else:
            raise ClientException("Unable to decrypt data key")

    def listUserGroups(self):
        '''
        listUserGroups returns a list of all groups a user is a memeber of.
        If the server refuses the method will raise an error.
        '''
        response = requests.get(self.createURL(LISTUSER), headers=self.auth, verify = self.verify)
        status = response.status_code
        values = self.parse_response(response)
        if status == OK and not values is None:
            return values['user_groups']
        elif status == FORBIDDEN:
            raise ClientException("Unable to get groups. User authentication failed") 
        else:
            raise ClientException("Unable to get groups") 
            
    def listGroupUsers(self, userGroup):
        '''
        listGroupUsers returns a list of all users in a given group.
        If the server refuses the method will raise an error.
        '''
        params = {'userGroup':userGroup}
        response = requests.get(self.createURL(LISTGROUP),  params=params, headers=self.auth,
                                verify = self.verify)
        status = response.status_code
        values = self.parse_response(response)
        if status == OK and not values is None:
            return values['results']['owners'], values['results']['members']
        elif status == UNAUTH:
            raise ClientException("Unable to get users. Group does not exist") 
        elif status == FORBIDDEN:
            raise ClientException("Unable to get users. User does not have permission") 
        else:
            raise ClientException("Unable to get users") 

    @staticmethod
    def getKeyNonce(filename):
        '''
        getKeyNonce retrieves the datakey cipher from a given file.
        '''
        cipherkey = None
        with open(filename, 'rb') as f:
            line = f.read()
            keySize, = struct.unpack('i', line[0:BYTEINTSIZE])
            cipherkey = line[BYTEINTSIZE:BYTEINTSIZE+keySize]
        return cipherkey, keySize

    @staticmethod
    def encryptFile(filename, outputfile, datakey, nonce, cipherkey):
        '''
        encryptFile encrypts a given file using a given datakey and nonce.
        It then outputs the cipher of the datakey and file to the provided output.
        '''
        keySize = struct.pack('i', len(cipherkey))
        box = secret.SecretBox(datakey)
        with open(outputfile, 'wb') as o:
            o.write(keySize)
            o.write(cipherkey)
            with open(filename, 'rb') as f:
                lines = f.read()
                ciphertext = box.encrypt(lines, nonce=nonce)
                o.write(ciphertext)

    @staticmethod
    def decryptFile(filename, outputfile, datakey, keySize):
        '''
        decryptFile decrypts a file using a given datakey and the datakeycipher's length
        It then outputs the plaintext of to the given output file.
        '''
        box = secret.SecretBox(datakey)
        startpoint = BYTEINTSIZE + keySize
        with open(outputfile, 'wb') as o:
            with open(filename, 'rb') as f:
                line = f.read()
                line = line[startpoint:]
                o.write(box.decrypt(line))

    @staticmethod
    def getOmittedArgument(m, item=None, isFile=False):
        '''
        gitOmittedArgument checks if the argument has been provided
        if not, it asks the user to provide it with message m.
        If the argument is an input file, it checks whether or not the file is valid.
        '''
        if item is None:
            item = input(m)
        if isFile and not os.path.exists(item):
            raise ClientException("Input file does not exist")
        return item
    
if __name__ == '__main__':
    
    parser = argparse.ArgumentParser(description='Run KMS Client')
    
    # Mode arguments
    parser.add_argument('--create_user',  action='store_true', help='Create new user')
    parser.add_argument('--create_group', action='store_true', help='Create new group')
    parser.add_argument('--encrypt',      action='store_true', help='Encrypt a datakey')
    parser.add_argument('--decrypt',      action='store_true', help='Decrypt a datakey')
    parser.add_argument('--list_groups',  action='store_true', help='List all usergroups for a user')
    parser.add_argument('--add_user',     action='store_true', help='Add user to group')
    parser.add_argument('--remove_group', action='store_true', help='Remove a user group')
    parser.add_argument('--remove_user',  action='store_true', help='Remove user from group')
    parser.add_argument('--list_members', action='store_true', help='List all users for a given group')
    
    # Optional arguments
    parser.add_argument('--host', metavar='-h',  type=str,  default=HOST, help='Server host')
    parser.add_argument('--port', metavar='-p',  type=int,  default=PORT, help='Port of server')
    
    # Mode specific arguments
    parser.add_argument('-file',     metavar='-f', type=str, default=None, help='Input file')
    parser.add_argument('-out',      metavar='-o', type=str, default=None, help='Output file')
    parser.add_argument('-username', metavar='-u', type=str, default=None, help='Username of target')
    parser.add_argument('-group',    metavar='-g', type=str, default=None, help='Usergroup')
    parser.add_argument('-is_owner', action='store_true', help='Specify user will be owner of group')

    args = parser.parse_args()
    client = Client(args.host, args.port)

    # Create new user
    if args.create_user:
        if client.createNewUser():
            print("New user created")

    # Encrypt Datakey
    elif args.encrypt:
        client.getSessionKey()
        datakey = utils.random(secret.SecretBox.KEY_SIZE)
        nonce = utils.random(secret.SecretBox.NONCE_SIZE)

        datakeyencoded = datakey.decode("cp855")
        cipherkey = client.encryptDataKey(datakeyencoded, args.group).encode("cp855")
        client.destroySessionKey()
        inputfile = client.getOmittedArgument("Please input filename: ", item=args.file, isFile=True)
        outputfile = client.getOmittedArgument("Please input output file: ", item=args.out)

        client.encryptFile(inputfile, outputfile, datakey, nonce, cipherkey)
        print("File has been encrypted")
        
    # Decrypt Datakey
    elif args.decrypt:                            
        client.getSessionKey()           
        inputfile = client.getOmittedArgument("Please input file to decrypt: ", item=args.file, isFile=True)
        cipherkey, keySize = client.getKeyNonce(inputfile)
        cipherkey = cipherkey.decode("cp855")
        datakey = client.decryptDataKey(cipherkey, args.group).encode("cp855")
        client.destroySessionKey()
            
        outputfile = client.getOmittedArgument("Please input output file: ", item=args.out)
        client.decryptFile(inputfile, outputfile, datakey, keySize)
        print("Decryption complete")
        
    # Show user's usergroups
    elif args.list_groups:
        client.getSessionKey()
        usergroups = client.listUserGroups()
        print('Usergroups:', usergroups)
        client.destroySessionKey()

    # Show groups users
    elif args.list_members:
        client.getSessionKey()
        userGroup = client.getOmittedArgument("Please input group name: ", item=args.group)
        owners, members = client.listGroupUsers(userGroup)
        print('Owners:', owners)
        print('Members:', members)
        client.destroySessionKey()
        
    # add user to a group you own
    elif args.add_user:
        client.getSessionKey()
        userName = client.getOmittedArgument("Please input username to add to group: ", item=args.username)
        userGroup = client.getOmittedArgument("Please input group name: ", item=args.group)
        client.addUserToGroup(userGroup=userGroup, userName=userName, isOwner=args.is_owner)
        client.destroySessionKey()

    # remove user from a group you own
    elif args.remove_user:
        client.getSessionKey()
        userName = client.getOmittedArgument("Please input username to remove from group: ", item=args.username)
        userGroup = client.getOmittedArgument("Please input group name: ", item=args.group)
        client.removeUserFromGroup(userGroup=userGroup, userName=userName)
        client.destroySessionKey()

    # create a user group
    elif args.create_group:
        client.getSessionKey()
        userGroup = client.getOmittedArgument("Please input userGroup to create: ", item=args.group)
        client.createNewUserGroup(userGroup)
        client.destroySessionKey()

    # remove a user group you own
    elif args.remove_group:
        client.getSessionKey()
        userGroup = client.getOmittedArgument("Please input userGroup to remove: ", item=args.group)
        client.deleteUserGroup(userGroup)
        client.destroySessionKey()
        
    # Error state, Too few arguments
    else:
        raise ClientException("No mode specified")

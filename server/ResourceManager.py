from multiprocessing import Lock
from nacl import pwhash, utils, secret
import json
import os
import serverUtils
import time
from kmsServerExceptions import UserPermissionException
from kmsServerExceptions import UnableToDecryptException
from kmsServerExceptions import UserAlreadyExistsException
from kmsServerExceptions import GroupAlreadyExistsException
from kmsServerExceptions import PasswordTooWeakException
from kmsServerExceptions import GroupDoesNotExistException
from kmsServerExceptions import InvalidTokenException


class ResourceManager:
    """
    Manage resources for kmsServer.
    """
    def __init__(self, session_time_limit=15):
        self.database_lock = Lock()
        self.database_name = 'database.json'
        self.session_time_limit = session_time_limit  # minutes

    def shutdown(self):
        """
        Perform any shutdown operations on ResourceManager.
        """
        print("shutting down resource manager")

    def is_session_valid(self, logonTimestamp):
        """
        Return true if session has not expired
        (subject to session_time_limit).
        """
        time_diff = time.time() - logonTimestamp
        return (time_diff / 60) < self.session_time_limit

    def read_database(self):
        """
        Atomically read database from file.
        """
        if not os.path.exists(self.database_name):
            return {'users': {},
                    'sessions': {},
                    'userGroups':{}}

        else:
            self.database_lock.acquire()
            try:
                with open(self.database_name, 'r') as file:
                    database = json.load(file)
                    return database
            except:
                assert False, 'Unable to read database'
            finally:
                self.database_lock.release()

    def write_database(self, updated_database):
        """
        Atomically write database to file.
        """
        self.database_lock.acquire()
        try:
            json.dump(updated_database, open(self.database_name, "w"))
        except Exception as e:
            print(e)
            assert False, 'Unable to write database'
        finally:
            self.database_lock.release()

    def check_authorization(self, header):
        """
        Return true if header has valid, current
        authorization token.
        """
        if 'Authorization' not in header:
            return False
        token = header['Authorization']
        
        database = self.read_database()
        if token not in database['sessions']:
            return False
        logonTimestamp = float(database['sessions'][token]['logonTimestamp'])
        return self.is_session_valid(logonTimestamp)


    def create_new_user(self, userName, password):
        """
        Validate the user's password and check to make sure the
        userName has not already been taken. Then, persist the salted/hashed
        password to database. Uses argon2id password hashing.
        """
        if serverUtils.validate_password(password):
            database = self.read_database()
            users = database['users']

            if userName not in users:
                salt = utils.random(pwhash.argon2id.SALTBYTES)
                hashed_password = pwhash.argon2id.kdf(secret.SecretBox.KEY_SIZE, password.encode('utf-8'), salt)
                users[userName] = dict(hashedPassword=hashed_password.hex(),
                                                       salt=salt.hex(),
                                                       masterKey=self.generate_master_key().decode('cp855'))

                self.write_database(database)

            else:
                raise UserAlreadyExistsException("User already exists")
        else:
            raise PasswordTooWeakException("supply a stronger password")

    def destroy_session_key(self, session_key):
        """
        Remove the session key from active sessions.
        """
        database = self.read_database()
        sessions = database['sessions']
        
        if session_key in sessions:
            del sessions[session_key]
            self.write_database(database)
            return

        raise UserPermissionException()

    def get_session_key(self, userName, password):
        """
        Check the databse against the salted/hashed password supplied.
        If match, generate a uuid and return as session key.
        Uses argon2id password hashing.
        """
        if serverUtils.validate_password(password):
            database = self.read_database()
            users = database['users']
            
            if userName in users:
                user = users[userName]
                hashed_password = pwhash.argon2id.kdf(secret.SecretBox.KEY_SIZE,
                                                      password.encode('utf-8'),
                                                      bytes.fromhex(user['salt'])).hex()
                
                if user['hashedPassword'] == hashed_password:
                    random = utils.random().hex()
                    sessions = database['sessions']
                    sessions[random] = dict(logonTimestamp=time.time(),
                                            userName=userName)
                    self.write_database(database)
                    return random

        raise UserPermissionException("user does not have permissions")



    def encrypt_data_key(self, dataKey, token, userGroup):
        """
        Encrypt and return the supplied dataKeyCypher using a masterKey belonging
        to the user bearing the token or one of their groups, if userGroups
        is supplied. Uses Salsa20 Stream cypher and Poly1305 MAC.
        """
        masterKey = self.retrieve_master_key(token=token, userGroup=userGroup)
        box = secret.SecretBox(masterKey)
        if isinstance(dataKey, str):
            dataKey = dataKey.encode('utf-8')
        cipherText= box.encrypt(dataKey).decode('cp855')
        return cipherText
    
    
    def decrypt_data_key(self, dataKeyCypher, token, userGroup):
        """
        Decrypt and return the supplied dataKeyCypher using a masterKey belonging
        to the user bearing the token or one of their groups, if userGroups
        is supplied. Uses Salsa20 Stream cypher and Poly1305 MAC.
        """
        masterKey = self.retrieve_master_key(token=token, userGroup=userGroup)
        box = secret.SecretBox(masterKey)
        if isinstance(dataKeyCypher, str):
            dataKeyCypher = dataKeyCypher.encode('cp855')
        try:
            plainText = box.decrypt(dataKeyCypher).decode('utf-8')
        except Exception:
            raise UnableToDecryptException("Unable to verify cyphertext/key pair")
        return plainText



    def generate_master_key(self):
        """
        Generate a 256-bit random key.
        """
        return utils.random(secret.SecretBox.KEY_SIZE)


    def retrieve_master_key(self, token, userGroup=None):
        """
        If userGroup is None, return the masterKey for the user
        bearing the supplied token. If userGroup is specified,
        return the masterKey belonging to that userGroup (subject
        to permissions).
        """
        dataBase = self.read_database()
        userName = dataBase['sessions'][token]['userName']
        if userGroup is not None:
            if not self.check_user_has_read_clearance(userName=userName, userGroup=userGroup):
                raise UserPermissionException("User does not have access to this group")
            return dataBase['userGroups'][userGroup]['masterKey'].encode('cp855')
        else:
            return dataBase['users'][userName]['masterKey'].encode('cp855')

    def get_username_from_token(self, token):
        """
        helper function to return username from token argument
        """
        dataBase = self.read_database()
        if token in dataBase['sessions']:
            userName = dataBase['sessions'][token]['userName']
            return userName
        else:
            raise InvalidTokenException("Token not valid.")

    def check_user_has_read_clearance(self, userName, userGroup):
        """
        Returns True if user specified by userName has member or owner access to
        user group specified by userGroup parameter.
        """
        dataBase = self.read_database()
        owners = dataBase['userGroups'][userGroup]['owners']
        members = dataBase['userGroups'][userGroup]['members']
        return userName in owners or userName in members

    def check_user_has_owner_clearance(self, userName, userGroup):
        """
        Returns True if user specified by userName has owner access to
        user group specified by userGroup parameter
        """
        dataBase = self.read_database()
        owners = dataBase['userGroups'][userGroup]['owners']
        return userName in owners

    def add_user_to_group(self, token, userGroup, userName, isOwner):
        """
        Method to add user specified by argument userName to userGroup
        specified by argument userGroup. Argument isOwner indicates if the
        user being added should be added as an owner, if not then the user
        is added as a member.
        """
        requestUser = self.get_username_from_token(token)
        if self.check_user_has_owner_clearance(requestUser, userGroup):
            dataBase = self.read_database()
            owners = dataBase['userGroups'][userGroup]['owners']
            members = dataBase['userGroups'][userGroup]['members']
            if isOwner and userName not in owners:
                dataBase['userGroups'][userGroup]['owners'].append(userName)
            elif not isOwner and userName not in members:
                dataBase['userGroups'][userGroup]['members'].append(userName)

            self.write_database(dataBase)
        else:
            raise UserPermissionException(
                "Requesting user is not owner of specified user group")

    def remove_user_from_group(self, token, userGroup, userName):
        """
        Remove user specified by userName from group specified by
        argument userGroup. The token is the session key of the requesting user
        """
        requestUser = self.get_username_from_token(token)
        if self.check_user_has_owner_clearance(requestUser, userGroup):
            dataBase = self.read_database()
            if userGroup not in dataBase['userGroups']:
                raise GroupDoesNotExistException("Group does not exist")
            owners = dataBase['userGroups'][userGroup]['owners']
            members = dataBase['userGroups'][userGroup]['members']
            if userName in owners:
                dataBase['userGroups'][userGroup]['owners'].remove(userName)
            if userName in members:
                dataBase['userGroups'][userGroup]['members'].remove(userName)
            self.write_database(dataBase)

        else:
            raise UserPermissionException("Requesting user is not owner of specified user group")

    def create_new_user_group(self, token, userGroup):
        """
        Creates user group specified by parameter userGroup.
        The token parameter specifies the session key. The user mapped to the
        session key is made an owner of the new user group.
        """
        requestUser = self.get_username_from_token(token)
        dataBase = self.read_database()
        userGroups = dataBase['userGroups']
        if userGroup not in userGroups:
            newGroup = dict()
            newGroup['owners'] = [requestUser]
            newGroup['members'] = list()
            newGroup['masterKey'] = self.generate_master_key().decode('cp855')
            dataBase['userGroups'][userGroup] = newGroup
            self.write_database(dataBase)
        else:
            raise GroupAlreadyExistsException("Specified user group already exists.")

    def delete_user_group(self, token, userGroup):
        """
        Delete user group specified by parameter userGroup. The holder
        the session key specified by argument token must be an owner of the
        group to successfully delete the user group.
        """
        requestUser = self.get_username_from_token(token)
        if self.check_user_has_owner_clearance(requestUser, userGroup):
            dataBase = self.read_database()
            if userGroup in dataBase['userGroups']:
                del dataBase['userGroups'][userGroup]
                self.write_database(dataBase)
                return
            else:
                raise GroupDoesNotExistException("Group does not exist")
        else:
            raise UserPermissionException("User does not have write access")

    def list_user_groups(self, token):
        """
        Returns the user groups of the user holding the session key
        specified by argument token
        """
        requestUser = self.get_username_from_token(token)
        dataBase = self.read_database()
        groups = dataBase['userGroups']
        groupList = list()
        for group in groups:
            members = groups[group]['members']
            owners = groups[group]['owners']
            if requestUser in members or requestUser in owners:
                groupList.append(group)
        return groupList

    def list_group_members(self, token, userGroup):
        """
        If the bearer of the token is an owner of the user group,
        return the userNames of all owners and members of the
        userGroup.
        """
        requestUser = self.get_username_from_token(token)
        dataBase = self.read_database()
        if userGroup not in dataBase['userGroups']:
            raise GroupDoesNotExistException("User group does not exist")

        if requestUser not in dataBase['userGroups'][userGroup]['owners']:
            raise UserPermissionException("User is not an owner of this group")
        owners = dataBase['userGroups'][userGroup]['owners']
        members = dataBase['userGroups'][userGroup]['members']
        return {'owners':owners, 'members':members}
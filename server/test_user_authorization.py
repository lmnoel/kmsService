import ResourceManager
from kmsServerExceptions import PasswordTooWeakException
from kmsServerExceptions import UserAlreadyExistsException
from kmsServerExceptions import UserPermissionException
from kmsServerExceptions import UnableToDecryptException
import os

def clear_database():
    if os.path.exists('database.json'):
        os.remove('database.json')

clear_database()

rm = ResourceManager.ResourceManager()

user_name_1 = 'admin'
user_name_2 = 'rootuser'
password_1 = 'Pa$$w0rd'
password_2 = 'S3cUr1ty'

try:
    rm.create_new_user(user_name_1, "password")
    assert False
except PasswordTooWeakException:
    pass

rm.create_new_user(user_name_1, password_1)

try:
    rm.create_new_user(user_name_1, password_1)
    assert False
except UserAlreadyExistsException:
    pass

try:
    rm.get_session_key(user_name_2, password_2)
    assert False
except UserPermissionException:
    pass

try:
    rm.get_session_key(user_name_1, password_2)
    assert False
except UserPermissionException:
    pass

try:
    rm.get_session_key(user_name_2, password_1)
    assert False
except UserPermissionException:
    pass

session_key = rm.get_session_key(user_name_1, password_1)

plaintext = "my_data_key"
cyphertext = rm.encrypt_data_key(plaintext, session_key, None)

assert rm.decrypt_data_key(cyphertext, session_key, None) == plaintext

try:
    cyphertext = cyphertext[:5] #modify cyphertext
    rm.decrypt_data_key(cyphertext, session_key, None)
    assert False
except UnableToDecryptException:
    pass



clear_database()
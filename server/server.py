from flask import Flask, request, Response, jsonify
import sys
import argparse
import signal
from ResourceManager import ResourceManager
import serverUtils

from kmsServerExceptions import UserPermissionException
from kmsServerExceptions import UnableToDecryptException
from kmsServerExceptions import UserAlreadyExistsException
from kmsServerExceptions import UnableToFindCertificateException
from kmsServerExceptions import GroupAlreadyExistsException
from kmsServerExceptions import GroupDoesNotExistException
from kmsServerExceptions import PasswordTooWeakException

resource_manager = ResourceManager()


# server management handlers
def sigint_handler(sig, frame):
    resource_manager.shutdown()

    sys.exit(0)

# register sigint handler
signal.signal(signal.SIGINT, sigint_handler)

# create application
application = Flask(__name__)
application.config['PROPAGATE_EXCEPTIONS'] = True


def parse_request(request):
    """
    Helper function to parse json requests
    which may or may not be properly formatted.
    """
    try:
        return request.values.to_dict()
    except BaseException:
        return None


@application.route('/ping', methods=['POST'])
def ping():
    if not resource_manager.check_authorization(request.headers):
        return Response(status=403)
    return Response(status=200)


@application.route('/createNewUser', methods=['POST'])
def create_new_user():
    header = request.headers
    if 'Authorization' not in header.keys():
        return jsonify(reason='authorization not supplied'), 400
    try:
        userCredentials = serverUtils.extract_user_credentials(header.get('Authorization'))
        resource_manager.create_new_user(userName=userCredentials.username,
                                            password=userCredentials.password)
        return Response(status=201)

    except UserAlreadyExistsException:
        return jsonify(reason='user already exists'), 403
    except PasswordTooWeakException:
        return jsonify(reason='password too weak'), 401
    except BaseException:
        return Response(status=400)


@application.route('/getSessionKey', methods=['GET'])
def get_session_key():
    header = request.headers
    if 'Authorization' not in header.keys():
        return jsonify(reason='authorization not supplied'), 400
    try:
        userCredentials = serverUtils.extract_user_credentials(header.get('Authorization'))
        session_key = resource_manager.get_session_key(userCredentials.username,
                                                       userCredentials.password)
        return jsonify(session_key=session_key), 200
    except KeyError:
        return Response(status=400)
    except UserPermissionException:
        return jsonify(reason='user does not have permissions'), 403
    except Exception:
        return Response(status=400)


@application.route('/destroySessionKey', methods=['DELETE'])
def destroy_session_key():
    auth = request.headers['Authorization']
    try:
        resource_manager.destroy_session_key(auth)
        return Response(status=200)
    except UserPermissionException:
        return Response(status=403)
    except BaseException:
        return Response(status=400)


@application.route('/encryptDataKey', methods=['GET'])
def encrypt_data_key():
    if not resource_manager.check_authorization(request.headers):
        return Response(status=403)
    values = parse_request(request)
    if values is None:
        return Response(status=400)
    try:
        dataKey = values['dataKey']
        if 'userGroup' in values:
            userGroup = values['userGroup']
        else:
            userGroup = None
        token = request.headers['Authorization']
        
        encrypted_key = resource_manager.encrypt_data_key(dataKey=dataKey,
                                                          token=token,
                                                          userGroup=userGroup)

        return jsonify(encrypted_key=encrypted_key), 200
    except KeyError:
        return Response(status=400)
    except UnableToDecryptException:
        return jsonify(reason='encryption failed'), 401
    except UserPermissionException:
        return jsonify(reason='user does not have permission'), 403
    except BaseException:
        return Response(status=400)


@application.route('/decryptDataKey', methods=['GET'])
def decrypt_data_key():
    if not resource_manager.check_authorization(request.headers):
        return Response(status=403)
    values = parse_request(request)
    if values is None:
        return Response(status=400)
    try:
        dataKeyCypher = values['dataKeyCypher']
        token = request.headers['Authorization']
        if 'userGroup' in values:
            userGroup = values['userGroup']
        else:
            userGroup = None

        decrypted_key = resource_manager.decrypt_data_key(dataKeyCypher=dataKeyCypher,
                                                      token=token,
                                                          userGroup=userGroup)

        return jsonify(decrypted_key=decrypted_key), 200
    except KeyError:
        return Response(status=400)
    except UnableToDecryptException:
        return jsonify(reason='decryption failed'), 401
    except UserPermissionException:
        return jsonify(reason='master key does not exist'), 404


@application.route('/addUserToGroup', methods=['POST'])
def add_user_to_group():
    if not resource_manager.check_authorization(request.headers):
        return Response(status=403)
    values = parse_request(request)
    if values is None:
        return Response(status=400)
    token = request.headers['Authorization']
    try:
        userGroup = values['userGroup']
        userName = values['userName']
        isOwner = values['isOwner'] == 'True'
        resource_manager.add_user_to_group(token=token,
                                           userGroup=userGroup,
                                           userName=userName,
                                           isOwner=isOwner)
        return Response(status=201)
    except KeyError:
        return Response(status=400)
    except UserPermissionException:
        return Response(status=403)


@application.route('/createNewUserGroup', methods=['POST'])
def create_new_user_group():
    if not resource_manager.check_authorization(request.headers):
        return Response(status=403)
    values = parse_request(request)
    if values is None:
        return Response(status=400)
    token = request.headers['Authorization']
    try:
        userGroup = values['userGroup']
        resource_manager.create_new_user_group(token=token,
                                               userGroup=userGroup)
        return Response(status=201)
    except KeyError:
        return Response(status=400)
    except GroupAlreadyExistsException:
        return jsonify(reason="group already exists"), 403


@application.route('/removeUserFromGroup', methods=['DELETE'])
def remove_user_from_group():
    if not resource_manager.check_authorization(request.headers):
        return Response(status=403)
    values = parse_request(request)
    if values is None:
        return Response(status=400)
    token = request.headers['Authorization']
    try:
        userGroup = values['userGroup']
        userName = values['userName']
        resource_manager.remove_user_from_group(token=token,
                                                userGroup=userGroup,
                                                userName=userName)
        return Response(status=200)
    except GroupDoesNotExistException:
        return Response(status=401)
    except KeyError:
        return Response(status=400)
    except UserPermissionException:
        return Response(status=403)


@application.route('/deleteUserGroup', methods=['DELETE'])
def delete_user_group():
    if not resource_manager.check_authorization(request.headers):
        return Response(status=403)
    values = parse_request(request)
    if values is None:
        return Response(status=400)
    token = request.headers['Authorization']
    try:
        userGroup = values['userGroup']
        resource_manager.delete_user_group(token=token,
                                           userGroup=userGroup)
        return Response(status=200)
    except GroupDoesNotExistException:
        return Response(status=401)
    except KeyError:
        return Response(status=400)
    except UserPermissionException:
        return Response(status=403)


@application.route('/listUserGroups', methods=['GET'])
def list_user_groups():
    if not resource_manager.check_authorization(request.headers):
        return Response(status=403)
    values = parse_request(request)
    if values is None:
        return Response(status=400)
    token = request.headers['Authorization']
    user_groups = resource_manager.list_user_groups(token)

    return jsonify(user_groups=user_groups), 200

@application.route('/listGroupMembers', methods=['GET'])
def list_group_members():
    if not resource_manager.check_authorization(request.headers):
        return Response(status=403)
    values = parse_request(request)
    if values is None:
        return Response(status=400)
    token = request.headers['Authorization']
    try:
        userGroup = values['userGroup']
        results = resource_manager.list_group_members(token, userGroup)
        return jsonify(results=results), 200
    except GroupDoesNotExistException:
        return Response(status=401)
    except KeyError:
        return Response(status=400)
    except UserPermissionException:
        return Response(status=403)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Start the 3HrKMS server')
    parser.add_argument('--port', metavar='-p', type=int,
                        default=5000, help='Port number to listen on.')

    args = parser.parse_args()

    ssl_context = ('server.crt', 'server.key')
    hostname = '127.0.0.1'  # hard coded because cert is only valid on localhost
    try:
        application.run(host=hostname, port=args.port, ssl_context=ssl_context)
    except FileNotFoundError:
        raise UnableToFindCertificateException("Please see the Readme to generate a certificate for the server")

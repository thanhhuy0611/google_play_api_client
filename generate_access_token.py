'''
This program creates and verifies a Signed JWT using the public certificate
Return access_token to access Google Play API
'''

from os import access
import time
import json
import base64
import jwt
import requests

# This example supports both libraries. Only one is required.

import OpenSSL.crypto

import pandas

from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


use_pyopenssl = True
# use_pyopenssl = False

service_account_json = 'service_account.json'

# Google Endpoint for creating OAuth 2.0 Access Tokens from Signed-JWT
auth_url = "https://www.googleapis.com/oauth2/v4/token"

# Set how long this token will be valid in seconds
expires_in = 3600   # Expires in 1 hour

scopes = " ".join(str(x) for x in [
    "https://www.googleapis.com/auth/devstorage.read_only",
    "https://www.googleapis.com/auth/androidpublisher",
])

# You can control what is verified in the JWT. For example to allow expired JWTs
# set 'verify_exp' to False
options = {
    'verify_signature': True,
    'verify_exp': True,
    'verify_nbf': True,
    'verify_iat': True,
    'verify_aud': True,
    'require_exp': False,
    'require_iat': False,
    'require_nbf': False
}

aud = 'https://www.googleapis.com/oauth2/v4/token'

def load_private_key(json_cred):
    ''' Return the private key from the json credentials '''

    return json_cred['private_key']

def load_public_key(cert):
    ''' Extract the public key from the certificate '''

    if use_pyopenssl:
        obj = OpenSSL.crypto.load_certificate(
                    OpenSSL.crypto.FILETYPE_PEM,
                    cert)

        pub_key = OpenSSL.crypto.dump_publickey(
                    OpenSSL.crypto.FILETYPE_PEM,
                    obj.get_pubkey())

        # print('Public Key (pyOpenSSL)')
        # print(pub_key)

        return pub_key

    # print('Load certificate')
    cert_obj = load_pem_x509_certificate(cert.encode('utf-8'), default_backend())

    # print('Get Public Key')
    pub_obj = cert_obj.public_key()

    # print(pub_obj)

    pub_key = pub_obj.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)

    # print('Public Key (cryptography)')
    # print(pub_key)

    return pub_key

def load_json_credentials(filename):
    ''' Load the Google Service Account Credentials from Json file '''

    # print('Opening:', filename)

    with open(filename, 'r') as f:
        data = f.read()

    return json.loads(data)

def load_public_certificates(url):
    ''' Load the public certificates for the client email address '''

    r = requests.get(url)

    if r.status_code != 200:
        return None

    return json.loads(r.content.decode('utf-8'))

def create_signed_jwt(pkey, pkey_id, email, scope):
    ''' Create an AccessToken from a service account Json credentials file '''

    issued = int(time.time())
    expires = issued + expires_in   # expires_in is in seconds

    # Note: this token expires and cannot be refreshed. The token must be recreated

    # JWT Headers
    additional_headers = {
            'kid': pkey_id,
            "alg": "RS256",
            "typ": "JWT"    # Google uses SHA256withRSA
    }

    # JWT Payload
    payload = {
        "iss": email,       # Issuer claim
        "sub": email,       # Issuer claim
        "aud": auth_url,    # Audience claim
        "iat": issued,      # Issued At claim
        "exp": expires,     # Expire time
        "scope": scope      # Permissions
    }

    # Encode the headers and payload and sign creating a Signed JWT (JWS)
    sig = jwt.encode(payload, pkey, algorithm="RS256", headers=additional_headers)

    # print(sig)

    return sig

def pad(data):
    """ pad base64 string """

    missing_padding = len(data) % 4
    data += '=' * (4 - missing_padding)
    return data

def print_jwt(signed_jwt):
    """ Print a JWT Header and Payload """

    s = signed_jwt.decode('utf-8').split('.')

    print('Header:')
    h = base64.urlsafe_b64decode(pad(s[0])).decode('utf-8')
    print(json.dumps(json.loads(h), indent=4))

    print('Payload:')
    p = base64.urlsafe_b64decode(pad(s[1])).decode('utf-8')
    print(json.dumps(json.loads(p), indent=4))

def verify_signed_jwt(signed_jwt, pub_key):
    '''
    This function takes a Signed JWT and verifies it using a Google Json service account.
    '''

    # Verify the Signed JWT
    r = jwt.decode(signed_jwt, pub_key, algorithms=["RS256"], audience=aud, options=options)

    # print('Decoded JWT:')
    # print(json.dumps(r, indent=4))

def get_public_key(json_cred):
    '''
    Load the public certificates for the service account email address.
    Then compare the private_key_id to find the correct certificate.
    '''

    certs = load_public_certificates(json_cred['client_x509_cert_url'])

    for k in certs:
        if k == json_cred['private_key_id']:
            cert = certs[k]
            pub = load_public_key(cert)

            return pub

    return None

if __name__ == '__main__':
    cred = load_json_credentials(service_account_json)

    pub_certs = load_public_certificates(cred['client_x509_cert_url'])

    private_key = load_private_key(cred)

    # print('Private Key:')
    # print(private_key)

    public_key = get_public_key(cred)

    # print('Public Key:')
    # print(public_key)

    if public_key is None:
        print('Error: Cannot get public key')
        exit(1)

    s_jwt = create_signed_jwt(
            private_key,
            cred['private_key_id'],
            cred['client_email'],
            scopes)

    # print_jwt(s_jwt)
    # print(s_jwt)

    verify_signed_jwt(s_jwt, public_key)

    response = requests.post(
        'https://oauth2.googleapis.com/token', 
        data={
            'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'assertion': s_jwt
        }
    )

    access_token = response.json()['access_token']
    # print(access_token)
    
    #open text file
    jwt_token_file = open("access_token.text", "w")
    
    #write string to file
    jwt_token_file.write(access_token)
    
    #close file
    jwt_token_file.close()   

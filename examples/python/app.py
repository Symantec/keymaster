from datetime import datetime, timedelta
import configparser
import logging
import os
import sys
import uuid

from flask import Flask, request, redirect, url_for, make_response
from flask.json import jsonify
from requests_oauthlib import OAuth2Session
import jwt


log = logging.getLogger('oauthlib')
log.addHandler(logging.StreamHandler(sys.stdout))
log.setLevel(logging.DEBUG)

app = Flask(__name__)


config = configparser.ConfigParser()
config.read('config.ini')
client_id = config['DEFAULT']['client_id']
client_secret = config['DEFAULT']['client_secret']
authorization_endpoint = config['DEFAULT']['authorization_endpoint']
token_endpoint = config['DEFAULT']['token_endpoint']
userinfo_endpoint = config['DEFAULT']['userinfo_endpoint']
redirect_uri = config['DEFAULT']['redirect_uri']
base_uri = config['DEFAULT']['base_uri']
jwt_secrets = config['DEFAULT']['jwt_secrets'].split(',')

algorithm = 'HS256'
jwt_cookie_key = 'jwt_token'

oauth_token = "oauth_token"
oauth_state = "oauth_state"
oauth_token_key = base_uri+'/'+oauth_token
oauth_state_key = base_uri+'/'+oauth_state


def JWT(
        oauth_token=None,
        oauth_state=None,
        sub=None,
        iss=base_uri,
        aud=base_uri,
        exp_seconds=300,
        **rest):
    now = datetime.utcnow()
    expires = now + timedelta(seconds=exp_seconds)
    token = rest
    if oauth_token:
        token[oauth_token_key] = oauth_token
    if oauth_state:
        token[oauth_state_key] = oauth_state
    if sub:
        token['sub'] = sub
    token['jti'] = str(uuid.uuid1())
    token['iss'] = base_uri
    token['aud'] = base_uri
    token['exp'] = expires
    token['iat'] = now
    token['nbf'] = now
    return token


class Cookie:
    def __init__(self):
        self.keys = {}
        self.ages = {}
        self.secures = {}
        self.deletes = []

    def remove_jwt(self, key):
        self.deletes.append(key)

    def add_jwt(self, key, jwt, max_age=300, secure=True):
        self.keys[key] = jwt
        self.ages[key] = max_age
        self.secures[key] = secure

    def populate_resp(self, resp):
        for key, token in self.keys.items():
            resp.set_cookie(
                key=key,
                max_age=self.ages[key],
                secure=self.secures[key],
                value=jwt.encode(
                    token,

                    # The first secret is the current signer.
                    jwt_secrets[0],
                    algorithm=algorithm
                )
            )
        for key in self.deletes:
            resp.set_cookie(
                key=key,
                max_age=0
            )
        return resp


def get_jwt_token(cookies, key):
    """
    Retrieve the jwt token's as a key, value object
    from the flask request cookies object.
    If no token exists, returns an empty object.
    """
    if key in request.cookies:

        # We take multiple secrets to allow for online secret rotation.
        # The first secret is the current signer,
        # and the others are potentially still in use, but will
        # be rotated out.
        for jwt_secret in jwt_secrets:
            try:
                # github.com/jpadilla/pyjwt/blob/master/tests/test_api_jwt.py
                # This will validate:
                #   iss, aud
                # This will validate (if they are in the request):
                #   exp, nbf, iat
                return jwt.decode(
                    request.cookies[key],
                    jwt_secret,
                    issuer=base_uri,
                    audience=base_uri,
                    algorithms=[algorithm]
                )
            except jwt.exceptions.InvalidTokenError as e:
                # will catch exp, nbf, iat, iss, aud errors
                print(e)
                continue

    return {}


@app.route("/")
def index():
    """
    If the user has no valid auth token:
        redirect the user/resource owner to the keymaster.
    Otherwise:
        the user is authenticated.
    """
    jwt = get_jwt_token(request.cookies, oauth_token)
    if oauth_token_key in jwt:
        # User is authenticated, don't do the auth dance.
        client = OAuth2Session(client_id, token=jwt[oauth_token_key])
        return jsonify(client.get(userinfo_endpoint).json())

    client = OAuth2Session(
        client_id,
        scope="openid mail profile",
        redirect_uri=redirect_uri
    )
    authorization_url, state = client.authorization_url(authorization_endpoint)

    # State is used to prevent CSRF, keep this for later.
    cookie = Cookie()
    state_token = JWT(oauth_state=state)
    cookie.add_jwt(oauth_state, state_token)
    return cookie.populate_resp(make_response(redirect(authorization_url)))


@app.route("/callback", methods=["GET"])
def callback():
    """
    The user has been redirected back from keymaster to your registered
    callback URL. With this redirection comes an authorization code included
    in the redirect URL. We will use that to obtain an access token.
    """

    jwt = get_jwt_token(request.cookies, oauth_state)
    if oauth_state_key not in jwt:
        # something is wrong with the state token,
        # so redirect back to start over.
        return redirect(url_for('.index'))

    client = OAuth2Session(
        client_id,
        state=jwt[oauth_state_key],
        redirect_uri=redirect_uri
    )

    token = client.fetch_token(
        token_endpoint,
        client_secret=client_secret,
        authorization_response=request.url
    )
    userinfo = client.get(userinfo_endpoint).json()

    # Save the token
    cookie = Cookie()
    exp_seconds = 60*60*4
    if "ExpiresIn" in token:
        exp_seconds = token['ExpiresIn']
    jwttoken = JWT(
        exp_seconds=exp_seconds,
        oauth_token=token,
        **userinfo
    )
    cookie.add_jwt(oauth_token, jwttoken)
    cookie.remove_jwt(oauth_state)
    return cookie.populate_resp(make_response(redirect(url_for('.index'))))


if __name__ == "__main__":
    app.secret_key = os.urandom(24)
    app.run(
        debug=True,
        host='0.0.0.0',
        port=443,
        ssl_context=(
            'output/localhost.pem',
            'output/key.pem'
        )
    )

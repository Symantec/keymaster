import configparser
import logging
import os
import sys

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
jwt_secrets = config['DEFAULT']['jwt_secrets'].split(',')

algorithm = 'HS256'
jwt_cookie_key = 'jwt_token'


def redirect_with_jwt(url, **jwt_args):
    """
    Redirect to url.
    All keyword args will be signed into a JWT with the response.
    """
    resp = make_response(redirect(url))
    resp.set_cookie(jwt_cookie_key, jwt.encode(
        jwt_args,

        # The first secret is the current signer.
        jwt_secrets[0],
        algorithm=algorithm
    ))
    return resp


def get_jwt_token(cookies):
    """
    Retrieve the jwt token's as a key, value object
    from the flask request cookies object.
    If no token exists, returns an empty object.
    """
    if jwt_cookie_key in request.cookies:

        # We take multiple secrets to allow for online secret rotation.
        # The first secret is the current signer,
        # and the others are potentially still in use, but will
        # be rotated out.
        for jwt_secret in jwt_secrets:
            try:
                return jwt.decode(
                    request.cookies[jwt_cookie_key],
                    jwt_secret,
                    algorithms=[algorithm]
                )
            except jwt.exceptions.InvalidTokenError:
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
    jwt = get_jwt_token(request.cookies)
    if 'oauth_token' in jwt:
        # User is authenticated, don't do the auth dance.
        client = OAuth2Session(client_id, token=jwt['oauth_token'])
        return jsonify(client.get(userinfo_endpoint).json())

    client = OAuth2Session(
        client_id,
        scope="openid mail profile",
        redirect_uri=redirect_uri
    )
    authorization_url, state = client.authorization_url(authorization_endpoint)

    # State is used to prevent CSRF, keep this for later.
    return redirect_with_jwt(authorization_url, oauth_state=state)


@app.route("/callback", methods=["GET"])
def callback():
    """
    The user has been redirected back from keymaster to your registered
    callback URL. With this redirection comes an authorization code included
    in the redirect URL. We will use that to obtain an access token.
    """

    jwt = get_jwt_token(request.cookies)
    if 'oauth_state' not in jwt:
        # something is wrong with the state token,
        # so redirect back to start over.
        return redirect(url_for('.index'))

    client = OAuth2Session(
        client_id,
        state=jwt['oauth_state'],
        redirect_uri=redirect_uri
    )

    token = client.fetch_token(
        token_endpoint,
        client_secret=client_secret,
        authorization_response=request.url
    )

    # Save the token
    return redirect_with_jwt(url_for('.index'), oauth_token=token)


if __name__ == "__main__":
    app.secret_key = os.urandom(24)
    app.run(
        debug=True,
        host='0.0.0.0',
        port=443,
        ssl_context=(
            'selfsign/output/localhost.pem',
            'selfsign/output/key.pem'
        )
    )

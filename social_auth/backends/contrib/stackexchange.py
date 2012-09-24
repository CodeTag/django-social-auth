"""
StackExchange OAuth support.

This contribution adds support for StackExchange OAuth service version 2.1. The settings
STACKEXCHANGE_APP_ID and STACKEXCHANGE_API_SECRET must be defined with the values
given by StackExchange application registration process.

Extended permissions are supported by defining STACKEXCHANGE_EXTENDED_PERMISSIONS
setting, it must be a list of values to request.

By default account id and token expiration time are stored in extra_data
field, check OAuthBackend class for details on how to extend it.
"""
import cgi
import zlib
import urllib2
import json
from urllib import urlencode

from django.utils import simplejson

from social_auth.utils import setting, dsa_urlopen
from social_auth.utils import backend_setting
from social_auth.backends import BaseOAuth2, OAuthBackend, USERNAME
from urllib2 import HTTPError, URLError
from django.contrib.auth import authenticate

from social_auth.backends.exceptions import AuthException, AuthCanceled, \
                                            AuthFailed, AuthTokenError, \
                                            AuthUnknownError

#https://api.stackexchange.com/2.1/me?order=desc&sort=reputation&site=stackoverflow
# stackExchange configuration
STACKEXCHANGE_AUTHORIZATION_URL = 'https://stackexchange.com/oauth'
STACKEXCHANGE_ACCESS_TOKEN_URL = 'https://stackexchange.com/oauth/access_token'
STACKEXCHANGE_USER_DATA_URL = 'https://api.stackexchange.com/2.1/me'
STACKEXCHANGE_SERVER = 'stackexchange.com'


class StackexchangeBackend(OAuthBackend):
    """StackExchange OAuth authentication backend"""
    name = 'stackexchange'
    # Default extra data to store
    EXTRA_DATA = [
        ('id', 'user_id'),
        ('expires', setting('SOCIAL_AUTH_EXPIRATION', 'expires'))
    ]

    def get_user_id(self, details, response):
        """OAuth providers return an unique user id in response"""
        return response['user_id']

    def get_user_details(self, response):
        """Return user details from StackExchange account"""
        return {USERNAME: response.get('display_name').replace(' ', '_'),
                'email': '',
                'first_name': response.get('display_name')}


class StackexchangeAuth(BaseOAuth2):
    """StackExchange OAuth2 mechanism"""
    AUTHORIZATION_URL = STACKEXCHANGE_AUTHORIZATION_URL
    ACCESS_TOKEN_URL = STACKEXCHANGE_ACCESS_TOKEN_URL
    SERVER_URL = STACKEXCHANGE_SERVER
    AUTH_BACKEND = StackexchangeBackend
    SETTINGS_KEY_NAME = 'STACKEXCHANGE_APP_ID'
    SETTINGS_SECRET_NAME = 'STACKEXCHANGE_API_SECRET'
    SCOPE_SEPARATOR = ','
    # Look at https://api.stackexchange.com/docs/authentication#scope
    SCOPE_VAR_NAME = 'STACKEXCHANGE_EXTENDED_PERMISSIONS'

    def auth_complete(self, *args, **kwargs):
        """Completes loging process, must return user instance"""
        access_token = None
        expires = None
        if 'code' in self.data:
            state = self.validate_state()
            data = urlencode({
                'client_id': backend_setting(self, self.SETTINGS_KEY_NAME),
                'redirect_uri': self.get_redirect_uri(state),
                'client_secret': backend_setting(self,
                                                 self.SETTINGS_SECRET_NAME),
                'code': self.data['code']
            })
            try:
                response = cgi.parse_qs(dsa_urlopen(STACKEXCHANGE_ACCESS_TOKEN_URL, data).read())
            except HTTPError, e:
                raise AuthFailed(self, 'There was an error authenticating '
                                       'the app')

            access_token = response['access_token'][0]
            if 'expires' in response:
                expires = response['expires'][0]

        if 'signed_request' in self.data:
            response = load_signed_request(self.data.get('signed_request'),
                                           backend_setting(
                                               self,
                                               self.SETTINGS_SECRET_NAME))

            if response is not None:
                access_token = response.get('access_token') or \
                               response.get('oauth_token') or \
                               self.data.get('access_token')

                if 'expires' in response:
                    expires = response['expires']

        if access_token:
            data = self.user_data(access_token)
            data['access_token'] = access_token
            # expires will not be part of response if offline access
            # premission was requested
            if expires:
                data['expires'] = expires

            kwargs.update({'auth': self,
                           'response': data,
                           self.AUTH_BACKEND.name: True})

            return authenticate(*args, **kwargs)
        else:
            if self.data.get('error') == 'access_denied':
                raise AuthCanceled(self)
            else:
                raise AuthException(self)

    def user_data(self, access_token, *args, **kwargs):
        """Loads user data from service"""
        url = STACKEXCHANGE_USER_DATA_URL + '?site=stackoverflow&' + urlencode({
            'access_token': access_token,
        'key':'SLuPL89yYABcbPNRyyW2TQ((', #TODO FIXME i need to use a parameter
        })
        try:
            r = urllib2.urlopen(url)
            data = zlib.decompress(r.read(), 16+zlib.MAX_WBITS)
            response = json.loads(data)
            return response['items'][0]
        except ValueError:
            return None


# Backend definition
BACKENDS = {
    'stackexchange': StackexchangeAuth,
}
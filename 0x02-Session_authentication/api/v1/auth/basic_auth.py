#!/usr/bin/env python3
"""basic auth"""
import base64
import binascii
from typing import TypeVar
from models.user import User
from api.v1.auth.auth import Auth


class BasicAuth(Auth):
    """basic auth"""

    def extract_base64_authorization_header(self, authorization_header: str) -> str:  # noqa
        """extract base64 from header"""
        if authorization_header is None:
            return None
        if not isinstance(authorization_header, str):
            return None
        if not authorization_header.startswith('Basic '):
            return None
        return authorization_header[len("Basic "):]

    def decode_base64_authorization_header(self, base64_authorization_header: str) -> str:  # noqa
        """decode base64 from header"""
        if base64_authorization_header is None or\
                not isinstance(base64_authorization_header, str):
            return None
        try:
            return base64.b64decode(base64_authorization_header).decode('utf-8')  # noqa
        except binascii.Error:
            return None

    def extract_user_credentials(self, decoded_base64_authorization_header: str) -> (str, str):  # noqa
        """extract credentials"""
        if decoded_base64_authorization_header is None:
            return None, None
        if not isinstance(decoded_base64_authorization_header, str):
            return None, None
        if ':' not in decoded_base64_authorization_header:
            return None, None
        return tuple(decoded_base64_authorization_header.split(':', 1))

    def user_object_from_credentials(self, user_email: str, user_pwd: str) -> TypeVar('User'):  # noqa
        """confirm user credential in database"""
        if user_email is None or not isinstance(user_email, str):
            return None
        if user_pwd is None or not isinstance(user_pwd, str):
            return None
        get_info = User.search({'email': user_email})
        if not get_info:
            return None
        if not get_info[0].is_valid_password(user_pwd):
            return None
        return get_info[0]

    def current_user(self, request=None) -> TypeVar('User'):
        """check authorization for the user"""
        auth_header = self.authorization_header(request)
        if auth_header is None:
            return None
        base_64_extract = self.extract_base64_authorization_header(auth_header)
        if base_64_extract is None:
            return None
        decoded_extract = self.decode_base64_authorization_header(base_64_extract)  # noqa
        if decoded_extract is None:
            return None
        get_email, get_pwd = self.extract_user_credentials(decoded_extract)
        if get_email is None or get_pwd is None:
            return None
        return self.user_object_from_credentials(get_email, get_pwd)

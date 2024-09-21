#!/usr/bin/env python3
"""auth class setup"""
import os
from flask import request
from typing import List, TypeVar


class Auth:
    """auth class"""
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """require authentication"""
        if path is None or excluded_paths is None or not excluded_paths:
            return True
        if not path.endswith('/'):
            path += '/'
        for get_path in excluded_paths:
            if get_path.endswith('*') and path.startswith(get_path[:-1]):
                return False
            elif path == get_path:
                return False
        return True

    def authorization_header(self, request=None) -> str:
        """authorization header"""
        if request is None or not request.headers.get("Authorization"):
            return None
        return request.headers.get("Authorization")

    def current_user(self, request=None) -> TypeVar('User'):
        """for current user"""
        return None

    def session_cookie(self, request=None):
        """extract session cookie"""
        if request is None:
            return None
        session_name = os.getenv("SESSION_NAME", '_my_session_id')
        return request.cookies.get(session_name)

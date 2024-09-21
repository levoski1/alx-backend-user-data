#!/usr/bin/env python3
"""session auth"""
import uuid
from api.v1.auth.auth import Auth
from models.user import User


class SessionAuth(Auth):
    """session auth"""
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """create session based on user_id id"""
        if user_id is None or not isinstance(user_id, str):
            return None
        session_id = str(uuid.uuid4())
        self.user_id_by_session_id[session_id] = user_id
        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """get user id by session id"""
        if session_id is None or not isinstance(session_id, str):
            return None
        return self.user_id_by_session_id.get(session_id)

    def current_user(self, request=None):
        """returns user instance based on cookie id"""
        get_session_id = self.session_cookie(request)
        if get_session_id is None:
            return None
        user_id = self.user_id_for_session_id(get_session_id)
        return User.get(user_id)

    def destroy_session(self, request=None):
        """deletes user from data"""
        if request is None:
            return False
        get_session_id = self.session_cookie(request)
        if get_session_id is None:
            return False
        get_userid = self.user_id_for_session_id(get_session_id)
        if get_userid is None:
            return False
        self.user_id_by_session_id.pop(get_session_id)
        return True

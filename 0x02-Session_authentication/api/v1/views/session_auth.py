#!/usr/bin/env python3
"""handling session routes"""
from crypt import methods
import json
import os
from flask import request, jsonify, abort, make_response
from api.v1.views import app_views
from models.user import User


@app_views.route('/auth_session/login', strict_slashes=False, methods=['POST'])
def handle_session():
    """handle session"""
    email = request.form.get("email")
    if not email:
        return jsonify({"error": "email missing"}), 400
    password = request.form.get("password")
    if not password:
        return jsonify({"error": "password missing"}), 400
    get_user = User.search({'email': email})
    if not get_user:
        return jsonify({"error": "no user found for this email"}), 404
    if not get_user[0].is_valid_password(password):
        return jsonify({"error": "wrong password"})
    else:
        from api.v1.app import auth
        get_user = get_user[0].to_json()
        get_session_id = auth.create_session(get_user.get('id'))
        if get_session_id is None:
            return None
        response = make_response(jsonify(get_user))
        session_name = os.getenv("SESSION_NAME", "_my_session_id")
        response.set_cookie(session_name, get_session_id)
        return response


@app_views.route('/auth_session/logout', strict_slashes=False, methods=['DELETE'])  # noqa
def delete_from_session():
    """delete from session"""
    from api.v1.app import auth
    if not auth.destroy_session(request):
        abort(404)
    return jsonify({}), 200

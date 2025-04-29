import jwt
import os
from flask import request, jsonify, session
from datetime import datetime, timedelta


secret = os.getenv("SECRET_KEY")

def generate_jwt(user_id, expiration):
    payload = {
        "user_id": user_id,
        "exp": expiration
    }
    token = jwt.encode(payload, secret, algorithm="HS256")
    return token

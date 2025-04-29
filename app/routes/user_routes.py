from flask import Blueprint, jsonify, request, current_app, make_response
import re
import bcrypt
from firebase_admin import firestore
from app.firebase import firebase_admin
import os
from google.cloud.firestore_v1.base_query import FieldFilter
from app.services.mail import send_email
from app.utils.verification_util import generate_otp ,generate_verification_code
from app.utils.token_util import generate_jwt, secret
from app.services.captcha import generate_captcha_image
from app.services.sms import send_sms
from app.cache_config import cache
from datetime import datetime, timedelta
from functools import wraps
from app.services.redis_client import r
import jwt


db = firestore.client()
user_blueprint = Blueprint('users', __name__)

# Regular expression for basic email validation
email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

# Regular expression for password validation
password_regex = r'^(?=.*[A-Z])(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{8,}$'

# Regular expression for phone number validation
phone_regex = r"^44\d{9,10}$" 

def middleware(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'Authorization' not in request.headers:
            print("Authorization not found")
            return jsonify({"statuscode": 403, "message": "Forbidden"}), 200

        authorization_bearer = request.headers['Authorization']
        token = authorization_bearer.split(" ")[1]

        try:
            payload = jwt.decode(token, secret, algorithms=['HS256'])
            user_id = payload['user_id']

            if not r.exists(user_id):
                return jsonify({"statuscode": 403, "message": "Forbidden"}), 200

            data = request.get_json() or {}
            email = data.get('email')
            if email and email != user_id:
                return jsonify({"statuscode": 403, "message": "Forbidden"}), 200

        except jwt.ExpiredSignatureError:
            print("Expired token")
            return jsonify({"statuscode": 401, "message": "Expired token"}), 200
        except jwt.InvalidTokenError:
            print("Invalid token")
            return jsonify({"statuscode": 403, "message": "Invalid token"}), 200

        return f(*args, **kwargs)

    return decorated

@user_blueprint.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()

        email = data.get('email')
        password = data.get('password')

        # Check for missing email or password fields
        if not email or not password:
            return jsonify({"statuscode": 400, "message": "Please fill up all field"}), 200

        # Validate email format
        if not re.match(email_regex, email):
            return jsonify({"statuscode": 400, "message": "Invalid email format"}), 200

        # Validate password complexity
        if not re.match(password_regex, password):
            return jsonify({
                "statuscode": 400,
                "message": "Password must be at least 8 characters long, "
                        "contain at least one uppercase letter and one special character."
            }), 200

        users_ref = db.collection("users")
        query = users_ref.where(filter=FieldFilter("email", "==", email)).limit(1)
        results = query.stream()

        user = None
        for doc in results:
            user = doc.to_dict()
            break

        if not user:
            return jsonify({"statuscode": 400, "message": "Incorrect email or password"}), 200

        stored_hashed_password = user.get('password')
        if not bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password.encode('utf-8')):
            return jsonify({"statuscode": 400, "message": "Incorrect email or password"}), 200


        responseUserObject = {
            "name": user.get('name'),
            "email": user.get('email'),
            "phone": user.get('phone'),
        }


        recaptchacode = generate_verification_code()
        cache.set(email + "_" + recaptchacode, responseUserObject, timeout=60) # 5 minutes

        recaptchaurl = generate_captcha_image(recaptchacode)

        return jsonify({"statuscode": 200, "message": "Login successful", "recaptchaurl": recaptchaurl}), 200

    except Exception as e:
        return jsonify({"message": str(e)}), 500


@user_blueprint.route('/signup', methods=['POST'])
def signup():
    password = os.getenv('MAIL_PASSWORD')
    print("MAIL_PASSWORD:", password)
    try:
        data = request.get_json()

        name = data.get('name')
        email = data.get('email')
        password = data.get('password')
        confirm_password = data.get('password_confirmation')

        if not name or not email or not password or not confirm_password:
            return jsonify({"statuscode": 400, "message": "Please fill up all field."}), 200
        
        if len(name) < 3:
            return jsonify({"statuscode": 400, 'message': "Name must be at least 3 characters long."}), 200

        if not email or not re.match(email_regex, email):
            return jsonify({"statuscode": 400, 'message': "Invalid email format."}), 200

        if not password or not re.match(password_regex, password):
            return jsonify({"statuscode": 400, 'message': "Invalid password format."}), 200

        user_ref = db.collection("users")
        query = user_ref.where(filter=FieldFilter("email", "==", email)).limit(1)

        results = query.stream()

        checked_user = None
        for doc in results:
            checked_user = doc.to_dict()
            break

        if checked_user:
            return jsonify({"statuscode": 400, 'message': "User with this email already existed."}), 200

        cachedUserForm = {
            "name": name,
            "email": email,
            "password": password
        }

        recaptchacode = generate_verification_code()
        cache.set(email + "_" + recaptchacode, cachedUserForm, timeout=60) # 5 minutes

        recaptchaurl = generate_captcha_image(recaptchacode)
        
        return jsonify({"statuscode": 200, "message": "Signup form valid", "recaptchaurl": recaptchaurl}), 200
    except Exception as e:
        return jsonify({"message": str(e)}), 500


@user_blueprint.route('/verify_recaptcha', methods=['POST'])
def verify_recaptcha():
    try:
        data = request.get_json()

        email = data.get('email')
        recaptcha_code = data.get('recaptcha_code')
        login = data.get('login')

        if not email or not recaptcha_code:
            return jsonify({"statuscode": 400, "message": "Bad request"}), 200
        
        if cache.get(email + "_" + recaptcha_code) is None:
            return jsonify({"statuscode": 400, "message": "Invalid recaptcha code"}), 200
        
        cachedUser = cache.get(email + "_" + recaptcha_code)

        if login and login == "false":
            encrypted_password = bcrypt.hashpw(password=cachedUser.get('password').encode('utf-8'), salt=bcrypt.gensalt()).decode('utf-8')
            print(encrypted_password)

            user = {
                "name": cachedUser.get('name'),
                "email": cachedUser.get('email'),
                "password": encrypted_password
            }

            # Add user to Firestore
            user_ref = db.collection("users")
            user_doc_ref = user_ref.document(email)
            user_doc_ref.set(user)

        verification_code = generate_verification_code()
        cache.set(email + "_verify", verification_code, timeout=300) # 5 minutes
        
        try:
            send_email(to=cachedUser.get('email'), subject="Hi {name}, please verify your VeriOne account.".format(name=cachedUser.get('name')), code=verification_code)
            responseUserObject = {
                "name": cachedUser.get('name'),
                "email": cachedUser.get('email'),
                "phone": cachedUser.get('phone') if cachedUser.get('phone') else "",
            }
            return jsonify({"statuscode": 200, "message": "Recaptcha verified successfully", "user": responseUserObject}), 200

        except Exception as email_error:
            # Rollback Firestore if email fails
            return jsonify({"message": "User created but email failed, rollback applied", "error": str(email_error)}), 500
            

    except Exception as e:
        return jsonify({"message": str(e)}), 500

@user_blueprint.route('/resend_email', methods=['POST'])
def resend_email():
    try:
        data = request.get_json()

        email = data.get('email')
        
        if not email:
            return jsonify({"statuscode": 400, "message": "Bad request"}), 200

        users_ref = db.collection("users")
        query = users_ref.where(filter=FieldFilter("email", "==", email)).limit(1)
        results = query.stream()

        user = None
        for doc in results:
            user = doc.to_dict()
            break  # Exit after the first match

        if not user:
            return jsonify({"statuscode": 400, "message": "User not found"}), 200
        
        verification_code = generate_verification_code()
        cache.set(email + "_verify", verification_code, timeout=300) # 5 minutes

        try:
            send_email(to=email, subject="Please verify your VeriOne account.", code=verification_code)
            return jsonify({"statuscode": 200, "message": "Email resent successfully"}), 200

        except Exception as email_error:
            return jsonify({"message": "User created but email failed, rollback applied", "error": str(email_error)}), 500

    except Exception as e:
        return jsonify({"message": str(e)}), 500


@user_blueprint.route('/verify_email', methods=['POST'])
def verify_email():
    try:
        data = request.get_json()

        email = data.get('email')
        verification_code = data.get('verification_code')
        login = data.get('login')
        print(email, verification_code, login)
        verify_key = "{email}_verify".format(email=email)

        if cache.get(verify_key) is None:
            return jsonify({"statuscode": 400, "message": "Invalid verification code."}), 200
        
        if cache.get(verify_key) != verification_code:
            return jsonify({"statuscode": 400, "message": "Verification code expired."}), 200
        
        if login and login == True:
            access_token = generate_jwt(email, datetime.utcnow() + timedelta(minutes=1))
            refresh_token = generate_jwt(email, datetime.utcnow() + timedelta(days=7))

            r.set(email, refresh_token)
            return jsonify({"statuscode": 200, "message": "Email verified successfully.", "access_token": access_token, "refresh_token": refresh_token}), 200

        cache.delete(verify_key)
        return jsonify({"statuscode": 200, "message": "Email verified successfully."}), 200

    except Exception as e:
        return jsonify({"message": str(e)}), 500


@user_blueprint.route('/add_phone', methods=['POST'])
def add_phone_number():
    try:
        data = request.get_json()
        email = data.get('email')
        phone = data.get('phone')

        if not email or not phone:
            return jsonify({"statuscode": 400, "message": "Phone number required."}), 200

        if not re.match(phone_regex, phone):
            return jsonify({"statuscode": 400,"message": "Invalid phone number."}), 200

        user_ref = db.collection("users")
        query = user_ref.where(filter=FieldFilter("email", "==", email)).limit(1)

        results = query.stream()

        current = None
        for doc in results:
            current = doc.to_dict()
            break

        if not current:
            return jsonify({"statuscode": 400,"message": "User not found."}), 200

        user_ref.document(email).update({"phone": phone})
        
        otp = generate_otp()
        print("OTP:", otp)
        cache.set(email + "_otp", otp, timeout=300)
        # send_sms(phone, otp)

        return jsonify({"statuscode": 200, "message": "Phone Added."}), 200

    except Exception as e:
        return jsonify({"message": str(e)}), 500


@user_blueprint.route('/resend_otp', methods=['POST'])
def resend_otp():
    try:
        data = request.get_json()

        email = data.get('email')
        phone = data.get('phone')

        if not email or not phone:
            return jsonify({"statuscode": 400, "message": "Phone number required."}), 200
        
        user = None
        users_ref = db.collection("users")
        query = users_ref.where(filter=FieldFilter("email", "==", email)).where(filter=FieldFilter("phone", "==", phone)).limit(1)

        results = query.stream()

        for doc in results:
            user = doc.to_dict()
            break

        if not user:
            return jsonify({"statuscode": 400, "message": "User not found."}), 200

        otp = generate_otp()
        print("OTP:", otp)
        cache.set("{email}_otp".format(email=email), otp, timeout=300)
        # send_sms(phone, otp)

        return jsonify({"statuscode": 200, "message": "OTP resent"}), 200

    except Exception as e:
        return jsonify({"message": str(e)}), 500

@user_blueprint.route('/verify_otp', methods=['POST'])
def verify_otp():
    try:
        data = request.get_json()

        email = data.get('email')
        otp = data.get('otp')

        print(email, otp)

        verify_key = "{email}_otp".format(email=email)
        print(verify_key)
        print(cache.get(verify_key))

        print(otp == cache.get(verify_key))

        if cache.get(verify_key) is None:
            return jsonify({"statuscode": 400, "message": "Invalid OTP code"}), 200

        if cache.get(verify_key) != otp:
            return jsonify({"statuscode": 400, "message": "OTP code expired"}), 200

        cache.delete(verify_key)

        return jsonify({"statuscode": 200, "message": "Email verified successfully."}), 200
    except Exception as e:
        return jsonify({"message": str(e)}), 500
    

@user_blueprint.route('/change_password', methods=['POST'])
@middleware
def change_password():
    try:
        refreshTT = request.cookies.get('refresh_token')
        print("refreshTT", refreshTT)
        data = request.get_json()

        email = data.get('email')
        old_password = data.get('old_password')
        new_password = data.get('new_password')
        confirm_password = data.get('confirm_password')

        if not email or not old_password or not new_password or not confirm_password:
            return jsonify({"statuscode": 400, "message": "Please fill up all field."}), 200
        
        if not new_password or not re.match(password_regex, new_password):
            return jsonify({"statuscode": 400, 'message': "Invalid password format."}), 200

        if not confirm_password or confirm_password != new_password:
            return jsonify({"statuscode": 400, 'message': "Password does not match."}), 200

        user_ref = db.collection("users")
        query = user_ref.where(filter=FieldFilter("email", "==", email)).limit(1)
        
        results = query.stream()

        currentUser = None
        for doc in results:
            currentUser = doc.to_dict()
            break

        if not currentUser:
            return jsonify({"statuscode": 400, "message": "User not found."}), 200
        
        current_datetime = datetime.now()
        formatted_current_date = current_datetime.strftime('%Y%m%d%H%M')
        print("formatted_current_date", formatted_current_date)
        print("currentUser.get('can_changed_at')", currentUser.get('can_changed_at'))

        if currentUser.get('can_changed_at') is not None and currentUser.get('can_changed_at') > formatted_current_date:
            return jsonify({"statuscode": 405, "message": "Password change limit reached.", "date": currentUser.get('can_changed_at')}), 200

        stored_hashed_password = currentUser.get('password')
        if not bcrypt.checkpw(old_password.encode('utf-8'), stored_hashed_password.encode('utf-8')):
            return jsonify({"statuscode": 400, "message": "Incorrect old password."}), 200
        
        if bcrypt.checkpw(new_password.encode('utf-8'), stored_hashed_password.encode('utf-8')):
            return jsonify({"statuscode": 400, "message": "New password cannot be the same as old password."}), 200

        encrypted_new_password = bcrypt.hashpw(password=new_password.encode('utf-8'), salt=bcrypt.gensalt()).decode('utf-8')

        next_change_datetime = datetime.now() + timedelta(days=10) # can change after 10 days
        formatted_next_date = next_change_datetime.strftime('%Y%m%d%H%M') # format to year month day hour minute

        user_ref.document(email).update({
            "password": encrypted_new_password, 
            "can_changed_at": formatted_next_date
        })

        return jsonify({"statuscode": 200, "message": "Password changed successfully."}), 200

    except Exception as e:
        return jsonify({"message": str(e)}), 500

@user_blueprint.route('/refresh_token', methods=['POST'])
def refresh_token():
    try:
        if 'Authorization' not in request.headers:
            return jsonify({"statuscode": 403, "message": "Forbidden"}), 200
        
        authorization_bearer = request.headers['Authorization']     
        refresh_token = authorization_bearer.split(" ")[1]

        payload = jwt.decode(refresh_token, secret, algorithms=['HS256'])
        user_id = payload.get('user_id')

        if not r.exists(user_id):
            return jsonify({"statuscode": 403, "message": "Forbidden"}), 200

        new_access_token = generate_jwt(user_id, datetime.utcnow() + timedelta(minutes=1))
        new_refresh_token = generate_jwt(user_id, datetime.utcnow() + timedelta(days=7))

        payload['exp'] = datetime.utcnow()
        r.set(user_id, new_refresh_token)

        return jsonify({"statuscode": 200, "message": "Token refreshed", "access_token": new_access_token, "refresh_token": new_refresh_token}), 200
    except jwt.ExpiredSignatureError:
        return jsonify({"statuscode": 401, "message": "Expired Refresh token"}), 200
    except jwt.InvalidTokenError:
        return jsonify({"statuscode": 403, "message": "Forbidden"}), 200
    except Exception as e:
        return jsonify({"message": str(e)}), 500 


@user_blueprint.route('/edit_profile', methods=['POST'])
@middleware
def edit_profile():
    try:
        data = request.get_json()

        email = data.get('email')
        name  = data.get('name')

        if not email or not name:
            return jsonify({"statuscode": 400, "message": "Please fill up all field."}), 200
        
        if len(name) < 3:
            return jsonify({"statuscode": 400, 'message': "Name must be at least 3 characters long."}), 200

        user_ref = db.collection("users")
        query = user_ref.where(filter=FieldFilter("email", "==", email)).limit(1)
        
        results = query.stream()

        currentUser = None
        for doc in results:
            currentUser = doc.to_dict()
            break

        if not currentUser:
            return jsonify({"statuscode": 400, "message": "User not found."}), 200

        user_ref.document(email).update({"name": name})

        return jsonify({"statuscode": 200, "message": "Profile updated successfully."}), 200
    except Exception as e:
        return jsonify({"message": str(e)}), 500

@user_blueprint.route('/logout', methods=['POST'])
@middleware
def logout ():
    try: 
        data = request.get_json()
        email = data.get('email')

        if not email or not r.exists(email):
            return jsonify({"statuscode": 400, "message": "User not found."}), 200

        payload = jwt.decode(r.get(email), secret, algorithms=['HS256'])
        payload['exp'] = datetime.utcnow()

        r.delete(email)

        return jsonify({"statuscode": 200, "message": "Logout successfully."}), 200
    except Exception as e:
        return jsonify({"message": str(e)}), 500
    
@user_blueprint.route('/account_delete', methods=['POST'])
@middleware
def account_delete():
    try:
        data = request.get_json()
        email = data.get('email')

        if not email:
            return jsonify({"statuscode": 400, "message": "User not found."}), 400

        users_ref = db.collection("users")
        query = users_ref.where(filter=FieldFilter("email", "==", email)).limit(1)
        results = query.stream()

        for doc in results:
            doc.reference.delete()
            break

        confirm_query = users_ref.where(filter=FieldFilter("email", "==", email)).limit(1)
        if list(confirm_query.stream()):
            return jsonify({"statuscode": 500, "message": "Failed to delete user in Firestore."}), 500

        payload = jwt.decode(r.get(email), secret, algorithms=['HS256'])
        payload['exp'] = datetime.utcnow()
        r.delete(email)

        return jsonify({"statuscode": 200, "message": "User deleted successfully."}), 200

    except Exception as e:
        return jsonify({"message": str(e)}), 500
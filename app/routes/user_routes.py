# ----- Core Flask & Dependencies -----
from flask import Blueprint, jsonify, request, current_app, make_response
import re
import bcrypt
import jwt
from datetime import datetime, timedelta
from functools import wraps
import os

# ----- Persistence & Caching -----
from firebase_admin import firestore
from google.cloud.firestore_v1.base_query import FieldFilter
from app.firebase import firebase_admin # Assuming this initializes Firebase Admin SDK
from app.cache_config import cache # Assuming Flask-Caching instance
from app.services.redis_client import r # Assuming Redis client instance

# ----- Application Specific Services/Utils -----
from app.services.mail import send_email
from app.utils.verification_util import generate_otp, generate_verification_code
from app.utils.token_util import generate_jwt, secret # Assuming secret is defined here
from app.services.captcha import generate_captcha_image
from app.services.sms import send_sms # Note: Calls are commented out in original

# ----- Initialize Firestore Client -----
# Renamed 'db' to 'firestore_db' for distinction
firestore_db = firestore.client()

# ----- Blueprint Definition -----
# Renamed 'user_blueprint' to 'auth_api_blueprint'
auth_api_blueprint = Blueprint('users', __name__) # Route prefix remains 'users'

# ----- Validation Patterns -----
# Renamed regex variables for clarity and distinction
EMAIL_VALIDATION_PATTERN = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
PASSWORD_STRENGTH_PATTERN = r'^(?=.*[A-Z])(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{8,}$'

# ----- Authentication Middleware -----
# Renamed 'middleware' to 'token_required' for clearer intent
def token_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get('Authorization') # Use .get() for safety

        if not auth_header or not auth_header.startswith("Bearer "):
            # More specific check for Bearer token format
            current_app.logger.warning("Authorization header missing or invalid format.")
            return jsonify({"statuscode": 403, "message": "Forbidden: Authorization required."}), 200

        jwt_token = auth_header.split(" ")[1]

        try:
            # Renamed variables for clarity
            decoded_payload = jwt.decode(jwt_token, secret, algorithms=['HS256'])
            token_subject_id = decoded_payload['user_id'] # Assuming 'user_id' is the subject

            # Check if the token subject exists in Redis (indicates valid session)
            if not r.exists(token_subject_id):
                current_app.logger.warning(f"Token subject ID {token_subject_id} not found in Redis session store.")
                return jsonify({"statuscode": 403, "message": "Forbidden: Invalid session."}), 200

            # Optional: Check if email in request body matches token subject (if applicable)
            # This check might be too restrictive depending on the endpoint's purpose.
            # Kept similar logic as original for now.
            request_body = request.get_json(silent=True) or {} # Use silent=True
            request_email = request_body.get('email')
            if request_email and request_email != token_subject_id:
                current_app.logger.warning(f"Request email '{request_email}' does not match token subject '{token_subject_id}'.")
                return jsonify({"statuscode": 403, "message": "Forbidden: Mismatched identity."}), 200

        except jwt.ExpiredSignatureError:
            current_app.logger.info("Access token expired.")
            # Consistent status code 401 for expired token
            return jsonify({"statuscode": 401, "message": "Unauthorized: Token expired."}), 200
        except jwt.InvalidTokenError as e:
            current_app.logger.error(f"Invalid token error: {e}")
            return jsonify({"statuscode": 403, "message": "Forbidden: Invalid token."}), 200
        except Exception as e:
            # Generic error catcher during token validation
            current_app.logger.error(f"Unexpected error in token middleware: {e}")
            return jsonify({"statuscode": 500, "message": "Internal server error during authentication."}), 500

        # If all checks pass, proceed to the decorated route function
        return f(*args, **kwargs)

    return wrapper


# ----- Endpoint: Check Token Validity -----
# Function name changed, route remains the same
@auth_api_blueprint.route('/check_token_validity', methods=['POST'])
def check_refresh_token_status():
    auth_header = request.headers.get('Authorization')

    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"statuscode": 403, "message": "Forbidden: Authorization required."}), 200

    token_to_validate = auth_header.split(" ")[1]

    try:
        token_data = jwt.decode(token_to_validate, secret, algorithms=['HS256'])
        session_owner_id = token_data.get('user_id') # Use .get()

        if not session_owner_id:
             return jsonify({"statuscode": 403, "message": "Forbidden: Invalid token payload."}), 200

        # Check Redis for the corresponding session key
        if not r.exists(session_owner_id):
            current_app.logger.warning(f"Refresh token validation failed: Session ID {session_owner_id} not in Redis.")
            return jsonify({"statuscode": 403, "message": "Forbidden: Invalid session or expired refresh token."}), 200

        # Optional: Check if the provided token matches the one stored in Redis
        # stored_token = r.get(session_owner_id)
        # if stored_token and stored_token.decode('utf-8') != token_to_validate:
        #     return jsonify({"statuscode": 403, "message": "Forbidden: Token mismatch."}), 200

        return jsonify({"statuscode": 200, "message": "Token is valid."}), 200

    except jwt.ExpiredSignatureError:
        # Use 401 for expired tokens consistently
        return jsonify({"statuscode": 401, "message": "Unauthorized: Expired Refresh token."}), 200
    except jwt.InvalidTokenError:
        return jsonify({"statuscode": 403, "message": "Forbidden: Invalid token format or signature."}), 200
    except Exception as e:
        current_app.logger.error(f"Error checking token validity: {e}")
        # Changed generic message for 500
        return jsonify({"statuscode": 500, "message": "Internal server error while validating token."}), 500


# ----- Endpoint: User Login -----
# Function name changed, route remains the same
@auth_api_blueprint.route('/login', methods=['POST'])
def handle_user_login():
    try:
        credentials = request.get_json()
        if not credentials:
             return jsonify({"statuscode": 400, "message": "Bad Request: Missing JSON body."}), 200

        login_email = credentials.get('email')
        login_password = credentials.get('password')

        # Combined check for missing fields
        if not login_email or not login_password:
            return jsonify({"statuscode": 400, "message": "Email and password are required."}), 200

        # Validate email format first
        if not re.match(EMAIL_VALIDATION_PATTERN, login_email):
            return jsonify({"statuscode": 400, "message": "Invalid email format provided."}), 200

        # Validate password complexity (optional but kept from original)
        # Consider if this check is truly needed at login, usually only needed at signup/pw change.
        # If kept, use the renamed pattern variable.
        if not re.match(PASSWORD_STRENGTH_PATTERN, login_password):
            return jsonify({
                "statuscode": 400,
                "message": "Password format requirement mismatch." # Simplified message
            }), 200

        # Firestore Query
        user_collection_ref = firestore_db.collection("users")
        user_query = user_collection_ref.where(filter=FieldFilter("email", "==", login_email)).limit(1)
        query_results = user_query.stream()

        # Retrieve user data - using next() for potentially cleaner single result handling
        found_user_doc = next(query_results, None)

        if not found_user_doc:
            return jsonify({"statuscode": 400, "message": "Login failed: Incorrect email or password."}), 200

        user_data = found_user_doc.to_dict()
        db_password_hash = user_data.get('password')

        # Verify password
        if not db_password_hash or not bcrypt.checkpw(login_password.encode('utf-8'), db_password_hash.encode('utf-8')):
            return jsonify({"statuscode": 400, "message": "Login failed: Incorrect email or password."}), 200

        # --- Post-Authentication Steps (Captcha Flow) ---

        # Prepare data for caching before captcha verification
        user_profile_info = {
            "name": user_data.get('name'),
            "email": user_data.get('email'),
        }

        # Generate captcha challenge
        captcha_challenge_id = generate_verification_code() # Reusing this function as per original
        cache_key_login = f"{login_email}_captcha_{captcha_challenge_id}" # More specific cache key
        print("Cache Key: ", cache_key_login)
        cache.set(cache_key_login, user_profile_info, timeout=300) # Increased timeout slightly

        captcha_image_uri = generate_captcha_image(captcha_challenge_id)

        return jsonify({
            "statuscode": 200,
            "message": "Authentication successful, proceed with CAPTCHA.", # Clearer message
            "recaptchaurl": captcha_image_uri,
            # Include challenge ID if frontend needs it separately
            # "challengeId": captcha_challenge_id
        }), 200

    except Exception as e:
        current_app.logger.error(f"Login endpoint error: {e}")
        return jsonify({"statuscode": 500, "message": "An unexpected error occurred during login."}), 500


# ----- Endpoint: User Signup -----
# Function name changed, route remains the same
@auth_api_blueprint.route('/signup', methods=['POST'])
def handle_user_registration():
    try:
        registration_payload = request.get_json()
        if not registration_payload:
            return jsonify({"statuscode": 400, "message": "Bad Request: Missing JSON body."}), 200

        # Extract registration details
        provided_name = registration_payload.get('name')
        provided_email = registration_payload.get('email')
        provided_password = registration_payload.get('password')
        password_confirmation = registration_payload.get('password_confirmation')

        # Validate required fields
        if not all([provided_name, provided_email, provided_password, password_confirmation]):
            return jsonify({"statuscode": 400, "message": "All fields are required for registration."}), 200

        # Specific field validations
        if len(provided_name) < 3:
            return jsonify({"statuscode": 400, 'message': "Name must contain at least 3 characters."}), 200
        if not re.match(EMAIL_VALIDATION_PATTERN, provided_email):
            return jsonify({"statuscode": 400, 'message': "Invalid email format provided."}), 200
        if not re.match(PASSWORD_STRENGTH_PATTERN, provided_password):
             # More specific password requirement message
            return jsonify({"statuscode": 400, 'message': "Password must be 8+ chars, with uppercase & special char."}), 200
        if provided_password != password_confirmation:
            return jsonify({"statuscode": 400, 'message': "Passwords do not match."}), 200 # Added password match check

        # Check if user already exists
        user_collection = firestore_db.collection("users")
        existing_user_query = user_collection.where(filter=FieldFilter("email", "==", provided_email)).limit(1)
        if next(existing_user_query.stream(), None): # Check if any document exists
            return jsonify({"statuscode": 400, 'message': "An account with this email already exists."}), 200

        # --- Pre-Captcha Caching ---
        # Cache the validated registration data temporarily
        pending_registration_data = {
            "name": provided_name,
            "email": provided_email,
            "password": provided_password # Store plain password temporarily before hashing
        }

        captcha_challenge_id = generate_verification_code()
        # Using a different cache key prefix for signup vs login
        cache_key_signup = f"{provided_email}_captcha_{captcha_challenge_id}"
        cache.set(cache_key_signup, pending_registration_data, timeout=300) # 5 min timeout

        captcha_image_uri = generate_captcha_image(captcha_challenge_id)

        return jsonify({
            "statuscode": 200,
            "message": "Registration data validated, proceed with CAPTCHA.",
            "recaptchaurl": captcha_image_uri
             # Include challenge ID if frontend needs it separately
             # "challengeId": captcha_challenge_id
        }), 200

    except Exception as e:
        current_app.logger.error(f"Signup endpoint error: {e}")
        return jsonify({"statuscode": 500, "message": "An unexpected error occurred during registration."}), 500


# ----- Endpoint: Verify Recaptcha -----
# Function name changed, route remains the same
@auth_api_blueprint.route('/verify_recaptcha', methods=['POST'])
def process_captcha_and_continue():
    try:
        captcha_payload = request.get_json()
        if not captcha_payload:
             return jsonify({"statuscode": 400, "message": "Bad Request: Missing JSON body."}), 200

        target_email = captcha_payload.get('email')
        submitted_captcha_code = captcha_payload.get('recaptcha_code') # Kept original key name for compatibility
        # Correctly handle boolean flag from JSON
        is_login_flow = str(captcha_payload.get('login', 'false')).lower() == 'true' # Safer boolean check

        if not target_email or not submitted_captcha_code:
            return jsonify({"statuscode": 400, "message": "Bad Request: Email and CAPTCHA code required."}), 200

        # Determine cache key based on flow
        cache_key_prefix = f"{target_email}_captcha_" if is_login_flow else f"{target_email}_captcha_"
        cache_lookup_key = f"{cache_key_prefix}{submitted_captcha_code}"
        print("Cache lookup key: ", cache_lookup_key)

        cached_user_data = cache.get(cache_lookup_key)
        print("Cached user data: ", cached_user_data)

        if cached_user_data is None:
            return jsonify({"statuscode": 400, "message": "Invalid or expired CAPTCHA code."}), 200

        # --- Actions after successful CAPTCHA verification ---

        user_info_for_response = { # Prepare response structure early
            "name": cached_user_data.get('name'),
            "email": cached_user_data.get('email'),
            "login": is_login_flow
        }

        # If it was the SIGNUP flow, create the user now
        if not is_login_flow:
            try:
                # Hash the password before saving
                password_to_hash = cached_user_data.get('password')
                if not password_to_hash:
                     # Should not happen if signup caching was correct, but good to check
                     raise ValueError("Password missing from cached signup data.")

                hashed_user_password = bcrypt.hashpw(
                    password_to_hash.encode('utf-8'),
                    bcrypt.gensalt()
                ).decode('utf-8')

                # Prepare Firestore document
                new_user_record = {
                    "name": cached_user_data.get('name'),
                    "email": cached_user_data.get('email'),
                    "password": hashed_user_password,
                    "created_at": firestore.SERVER_TIMESTAMP # Add creation timestamp
                }

                # Add user to Firestore (use email as document ID)
                user_collection_ref = firestore_db.collection("users")
                user_doc_ref = user_collection_ref.document(target_email)
                user_doc_ref.set(new_user_record)
                current_app.logger.info(f"New user created: {target_email}")

            except Exception as db_error:
                 current_app.logger.error(f"Firestore error during user creation for {target_email}: {db_error}")
                 return jsonify({"statuscode": 500, "message": "Failed to create user account after CAPTCHA."}), 500

        # --- Send Verification Email (Common step for both flows after CAPTCHA) ---
        email_verification_token = generate_verification_code()
        email_verify_cache_key = f"{target_email}_email_verify_code"
        cache.set(email_verify_cache_key, email_verification_token, timeout=300) # 5 minutes validity

        try:
            email_subject = f"Verify your account, {cached_user_data.get('name', 'User')}"
            # Assuming send_email takes named arguments as before
            send_email(
                to=target_email,
                subject=email_subject,
                code=email_verification_token # Pass the code to the email template/body
            )
            current_app.logger.info(f"Verification email sent to {target_email}")

            # CAPTCHA verified, email sent, now remove the CAPTCHA cache entry
            cache.delete(cache_lookup_key)

            return jsonify({
                "statuscode": 200,
                "message": "CAPTCHA verified successfully. Please check your email for verification code.",
                "user": user_info_for_response # Return basic user info
            }), 200

        except Exception as email_error:
            current_app.logger.error(f"Failed to send verification email to {target_email}: {email_error}")
            # Decide on rollback strategy: If signup, maybe delete the created user?
            # For simplicity now, just report the error. Rollback might be complex.
            if not is_login_flow:
                 # Attempt to delete the just-created user if email fails during signup
                 try:
                     firestore_db.collection("users").document(target_email).delete()
                     current_app.logger.warning(f"Rolled back user creation for {target_email} due to email failure.")
                 except Exception as delete_error:
                     current_app.logger.error(f"Failed to rollback user creation for {target_email}: {delete_error}")

            return jsonify({"statuscode": 500, "message": "CAPTCHA verified, but failed to send verification email."}), 500

    except Exception as e:
        current_app.logger.error(f"Verify CAPTCHA endpoint error: {e}")
        return jsonify({"statuscode": 500, "message": "An unexpected error occurred during CAPTCHA verification."}), 500


# ----- Endpoint: Resend Verification Email -----
# Function name changed, route remains the same
@auth_api_blueprint.route('/resend_email', methods=['POST'])
def request_new_verification_email():
    try:
        request_data = request.get_json()
        if not request_data:
            return jsonify({"statuscode": 400, "message": "Bad Request: Missing JSON body."}), 200

        user_email_address = request_data.get('email')

        if not user_email_address:
            return jsonify({"statuscode": 400, "message": "Bad Request: Email is required."}), 200

        # Verify user exists before resending
        user_collection = firestore_db.collection("users")
        user_doc = user_collection.document(user_email_address).get() # Direct get by ID

        if not user_doc.exists:
            return jsonify({"statuscode": 404, "message": "User account not found."}), 200 # Use 404

        target_user_data = user_doc.to_dict()

        # Generate a new verification code and cache it
        new_email_code = generate_verification_code()
        email_verify_cache_key = f"{user_email_address}_email_verify_code" # Consistent key naming
        cache.set(email_verify_cache_key, new_email_code, timeout=300) # 5 minutes validity

        try:
            email_subject = f"Verify your account, {target_user_data.get('name', 'User')}"
            send_email(to=user_email_address, subject=email_subject, code=new_email_code)
            current_app.logger.info(f"Resent verification email to {user_email_address}")
            return jsonify({"statuscode": 200, "message": "Verification email resent successfully."}), 200

        except Exception as email_error:
            current_app.logger.error(f"Failed to resend verification email to {user_email_address}: {email_error}")
            return jsonify({"statuscode": 500, "message": "Failed to resend verification email."}), 500

    except Exception as e:
        current_app.logger.error(f"Resend email endpoint error: {e}")
        return jsonify({"statuscode": 500, "message": "An unexpected error occurred while resending email."}), 500


# ----- Endpoint: Verify Email Code -----
# Function name changed, route remains the same
@auth_api_blueprint.route('/verify_email', methods=['POST'])
def confirm_email_with_code():
    try:
        verification_data = request.get_json()
        if not verification_data:
            return jsonify({"statuscode": 400, "message": "Bad Request: Missing JSON body."}), 200

        subject_email = verification_data.get('email')
        submitted_code = verification_data.get('verification_code')
        # Ensure boolean comparison is robust
        is_final_login_step = str(verification_data.get('login', 'false')).lower() == 'true'

        if not subject_email or not submitted_code:
            return jsonify({"statuscode": 400, "message": "Bad Request: Email and verification code required."}), 200

        # Check cache for the verification code
        cache_lookup_key = f"{subject_email}_email_verify_code"
        cached_code = cache.get(cache_lookup_key)

        if cached_code is None:
            return jsonify({"statuscode": 400, "message": "Verification code expired or never sent."}), 200

        if cached_code != submitted_code:
            return jsonify({"statuscode": 400, "message": "Invalid verification code provided."}), 200

        # --- Actions after successful email verification ---
        cache.delete(cache_lookup_key) # Code used, delete it

        # If this verification completes the login process, generate tokens
        if is_final_login_step:
            try:
                # Generate JWT tokens (using durations from original code)
                access_token_duration = timedelta(minutes=1) # Short duration access token
                refresh_token_duration = timedelta(minutes=3) # Longer duration refresh token

                session_token = generate_jwt(subject_email, datetime.utcnow() + access_token_duration)
                renewal_token = generate_jwt(subject_email, datetime.utcnow() + refresh_token_duration)

                # Store the refresh token in Redis, key by user email (subject_id)
                # Set expiry in Redis slightly longer than the token's own expiry for safety
                redis_expiry_seconds = int(refresh_token_duration.total_seconds() + 60)
                r.set(subject_email, renewal_token, ex=redis_expiry_seconds)

                current_app.logger.info(f"Email verified for {subject_email}, issued JWT tokens.")
                return jsonify({
                    "statuscode": 200,
                    "message": "Email verified successfully. Login complete.",
                    "access_token": session_token,
                    "refresh_token": renewal_token
                }), 200

            except Exception as token_error:
                current_app.logger.error(f"Failed to generate/store tokens for {subject_email}: {token_error}")
                return jsonify({"statuscode": 500, "message": "Email verified, but failed to issue session tokens."}), 500
        else:
             # Optional: Update user record in Firestore to mark email as verified
             try:
                 firestore_db.collection("users").document(subject_email).update({"email_verified": True, "email_verified_at": firestore.SERVER_TIMESTAMP})
                 current_app.logger.info(f"Email verified for {subject_email} (Signup flow).")
             except Exception as db_update_error:
                 current_app.logger.error(f"Failed to mark email as verified in DB for {subject_email}: {db_update_error}")
                 # Continue, but log the error. The primary goal was achieved.

             return jsonify({"statuscode": 200, "message": "Email verified successfully."}), 200

    except Exception as e:
        current_app.logger.error(f"Verify email endpoint error: {e}")
        return jsonify({"statuscode": 500, "message": "An unexpected error occurred during email verification."}), 500


# ----- Endpoint: Change Password -----
# Function name changed, route remains the same
# Middleware already applied via decorator
@auth_api_blueprint.route('/change_password', methods=['POST'])
@token_required # Uses the renamed middleware
def handle_password_update():
    try:
        password_change_request_data = request.get_json()
        if not password_change_request_data:
             return jsonify({"statuscode": 400, "message": "Bad Request: Missing JSON body."}), 200

        account_email = password_change_request_data.get('email')
        current_password_provided = password_change_request_data.get('old_password')
        requested_new_password = password_change_request_data.get('new_password')
        password_check = password_change_request_data.get('confirm_password') # Renamed from confirm_password

        # Validate all fields are present
        if not all([account_email, current_password_provided, requested_new_password, password_check]):
            return jsonify({"statuscode": 400, "message": "All password fields are required."}), 200

        # Validate new password format and confirmation
        if not re.match(PASSWORD_STRENGTH_PATTERN, requested_new_password):
            return jsonify({"statuscode": 400, 'message': "New password does not meet complexity requirements."}), 200
        if requested_new_password != password_check:
            return jsonify({"statuscode": 400, 'message': "New passwords do not match."}), 200

        # Fetch user data
        user_doc_ref = firestore_db.collection("users").document(account_email)
        user_account_doc = user_doc_ref.get()

        if not user_account_doc.exists:
            return jsonify({"statuscode": 404, "message": "User account not found."}), 200 # Use 404

        user_account_data = user_account_doc.to_dict()

        # Check password change cooldown (using format from original)
        # Ensure consistent timezone handling if comparing across systems
        can_change_at_str = user_account_data.get('can_changed_at') # Stored as 'YYYYMMDDHHMM' string
        if can_change_at_str:
             now_dt = datetime.now() # Consider using UTC: datetime.utcnow()
             now_formatted = now_dt.strftime('%Y%m%d%H%M')
             if can_change_at_str > now_formatted:
                  # Provide the date when change is allowed again
                  return jsonify({
                       "statuscode": 405, # Method Not Allowed (or 429 Too Many Requests)
                       "message": "Password change is not allowed yet.",
                       "allowed_after": can_change_at_str # Send back the stored timestamp
                  }), 200

        # Verify the current (old) password
        current_password_hash = user_account_data.get('password')
        if not current_password_hash or not bcrypt.checkpw(current_password_provided.encode('utf-8'), current_password_hash.encode('utf-8')):
            return jsonify({"statuscode": 400, "message": "Incorrect current password provided."}), 200

        # Check if new password is the same as the old one
        if bcrypt.checkpw(requested_new_password.encode('utf-8'), current_password_hash.encode('utf-8')):
            return jsonify({"statuscode": 400, "message": "New password cannot be the same as the old password."}), 200

        # Hash the new password
        new_password_hash = bcrypt.hashpw(
            requested_new_password.encode('utf-8'),
            bcrypt.gensalt()
        ).decode('utf-8')

        # Calculate next allowed change time (10 days from original)
        # Ensure timezone consistency (e.g., use UTC)
        cooldown_period = timedelta(days=10)
        next_allowed_change_dt = datetime.now() + cooldown_period # Or datetime.utcnow()
        next_allowed_change_formatted = next_allowed_change_dt.strftime('%Y%m%d%H%M')

        # Update Firestore with new password and cooldown timestamp
        try:
            user_doc_ref.update({
                "password": new_password_hash,
                "can_changed_at": next_allowed_change_formatted,
                "password_last_changed_at": firestore.SERVER_TIMESTAMP
            })
            current_app.logger.info(f"Password changed successfully for {account_email}")
            return jsonify({"statuscode": 200, "message": "Password changed successfully."}), 200
        except Exception as db_update_error:
             current_app.logger.error(f"Failed to update password for {account_email}: {db_update_error}")
             return jsonify({"statuscode": 500, "message": "Failed to save new password."}), 500

    except Exception as e:
        current_app.logger.error(f"Change password endpoint error: {e}")
        return jsonify({"statuscode": 500, "message": "An unexpected error occurred during password change."}), 500


# ----- Endpoint: Refresh JWT Token -----
# Function name changed, route remains the same
@auth_api_blueprint.route('/refresh_token', methods=['POST'])
def issue_new_session_tokens():
    auth_header = request.headers.get('Authorization')

    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"statuscode": 403, "message": "Forbidden: Refresh token required."}), 200

    provided_refresh_token = auth_header.split(" ")[1]

    try:
        # Decode the incoming refresh token to get the subject (user_id)
        decoded_refresh_payload = jwt.decode(provided_refresh_token, secret, algorithms=['HS256'])
        token_subject = decoded_refresh_payload.get('user_id')

        if not token_subject:
             return jsonify({"statuscode": 403, "message": "Forbidden: Invalid refresh token payload."}), 200

        # Check if the provided refresh token matches the one stored in Redis for this user
        stored_token = r.get(token_subject)
        if not stored_token or stored_token.decode('utf-8') != provided_refresh_token:
            # If mismatch or not found, it might be an old/invalid/revoked token
            current_app.logger.warning(f"Refresh token mismatch or not found in Redis for {token_subject}.")
            return jsonify({"statuscode": 403, "message": "Forbidden: Invalid or revoked refresh token."}), 200

        # --- Issue New Tokens ---
        # Use same durations as original verify_email step
        access_token_duration = timedelta(minutes=1)
        refresh_token_duration = timedelta(minutes=3)

        refreshed_access_token = generate_jwt(token_subject, datetime.utcnow() + access_token_duration)
        new_refresh_token = generate_jwt(token_subject, datetime.utcnow() + refresh_token_duration)

        # Update Redis with the *new* refresh token and its expiry
        redis_expiry_seconds = int(refresh_token_duration.total_seconds() + 60)
        r.set(token_subject, new_refresh_token, ex=redis_expiry_seconds)

        current_app.logger.info(f"Tokens refreshed for {token_subject}")
        return jsonify({
            "statuscode": 200,
            "message": "Tokens refreshed successfully.",
            "access_token": refreshed_access_token,
            "refresh_token": new_refresh_token
        }), 200

    except jwt.ExpiredSignatureError:
         # If the *incoming* refresh token is expired
         # Clean up Redis entry if it exists (it shouldn't match if expired, but good practice)
         if 'token_subject' in locals() and token_subject:
              r.delete(token_subject)
         return jsonify({"statuscode": 401, "message": "Unauthorized: Expired Refresh token."}), 200
    except jwt.InvalidTokenError:
         return jsonify({"statuscode": 403, "message": "Forbidden: Invalid refresh token."}), 200
    except Exception as e:
        current_app.logger.error(f"Refresh token endpoint error: {e}")
        return jsonify({"statuscode": 500, "message": "An unexpected error occurred during token refresh."}), 500


# ----- Endpoint: Edit User Profile -----
# Function name changed, route remains the same
# Middleware applied
@auth_api_blueprint.route('/edit_profile', methods=['POST'])
@token_required # Use renamed middleware
def modify_user_profile_details():
    try:
        profile_update_data = request.get_json()
        if not profile_update_data:
             return jsonify({"statuscode": 400, "message": "Bad Request: Missing JSON body."}), 200

        account_email = profile_update_data.get('email')
        updated_name = profile_update_data.get('name')

        if not account_email or not updated_name: # Add other required fields to check
            return jsonify({"statuscode": 400, "message": "Required profile fields are missing (email, name)."}), 200

        # Validate updated data
        if len(updated_name) < 3:
            return jsonify({"statuscode": 400, 'message': "Name must contain at least 3 characters."}), 200

        # Prepare update payload for Firestore
        update_payload = {
            "name": updated_name,
            "profile_last_updated_at": firestore.SERVER_TIMESTAMP
        }

        # Update Firestore document
        try:
            user_doc_ref = firestore_db.collection("users").document(account_email)
            # Check if user exists before updating (optional, middleware implies user exists)
            # user_doc = user_doc_ref.get()
            # if not user_doc.exists:
            #     return jsonify({"statuscode": 404, "message": "User account not found."}), 200

            user_doc_ref.update(update_payload)
            current_app.logger.info(f"Profile updated successfully for {account_email}")
            return jsonify({"statuscode": 200, "message": "Profile updated successfully."}), 200
        except Exception as db_update_error:
             current_app.logger.error(f"Failed to update profile for {account_email}: {db_update_error}")
             return jsonify({"statuscode": 500, "message": "Failed to save profile updates."}), 500

    except Exception as e:
        current_app.logger.error(f"Edit profile endpoint error: {e}")
        return jsonify({"statuscode": 500, "message": "An unexpected error occurred while updating profile."}), 500


# ----- Endpoint: Logout -----
# Function name changed, route remains the same
# Middleware applied
@auth_api_blueprint.route('/logout', methods=['POST'])
@token_required # Use renamed middleware
def invalidate_user_session():
    try:
        logout_request_data = request.get_json()
        if not logout_request_data:
             return jsonify({"statuscode": 400, "message": "Bad Request: Missing JSON body."}), 200

        user_to_logout = logout_request_data.get('email')

        if not user_to_logout:
            return jsonify({"statuscode": 400, "message": "Bad Request: Email is required for logout."}), 200

        # The core logout action is removing the refresh token from Redis
        # The original code decoded the token, set 'exp', which isn't standard invalidation.
        # Simply deleting the Redis key is sufficient and standard practice.
        deleted_count = r.delete(user_to_logout)

        if deleted_count > 0:
            current_app.logger.info(f"User {user_to_logout} logged out successfully (session invalidated).")
            return jsonify({"statuscode": 200, "message": "Logout successful."}), 200
        else:
             # This could mean the user was already logged out or session expired
             current_app.logger.warning(f"Logout attempt for {user_to_logout}, but no active session found in Redis.")
             # Return success anyway, as the desired state (logged out) is achieved
             return jsonify({"statuscode": 200, "message": "Logout successful (session already inactive)."}), 200

    except Exception as e:
        current_app.logger.error(f"Logout endpoint error: {e}")
        return jsonify({"statuscode": 500, "message": "An unexpected error occurred during logout."}), 500

# ----- Endpoint: Account Deletion -----
# Function name changed, route remains the same
# Middleware applied
@auth_api_blueprint.route('/account_delete', methods=['POST'])
@token_required # Use renamed middleware
def remove_user_account_permanently():
    try:
        deletion_request_data = request.get_json()
        if not deletion_request_data:
             # Use 400 for bad request format
             return jsonify({"statuscode": 400, "message": "Bad Request: Missing JSON body."}), 400

        email_to_delete = deletion_request_data.get('email')

        if not email_to_delete:
             # Use 400 for missing required parameter
             return jsonify({"statuscode": 400, "message": "Bad Request: Email is required for account deletion."}), 400

        # --- Delete Firestore User Document ---
        user_doc_ref = firestore_db.collection("users").document(email_to_delete)

        try:
            # Check if user exists before attempting deletion
            user_doc = user_doc_ref.get()
            if not user_doc.exists:
                 current_app.logger.warning(f"Account deletion request for non-existent user: {email_to_delete}")
                 # Return success as the end state (no user) is true, or 404
                 return jsonify({"statuscode": 404, "message": "User account not found."}), 404 # Changed to 404

            # Perform the deletion
            user_doc_ref.delete()

            # Optional: Verify deletion (as in original)
            # Re-fetch the document to ensure it's gone
            confirm_doc = user_doc_ref.get()
            if confirm_doc.exists:
                # Log error but don't necessarily fail if Redis cleanup works
                current_app.logger.error(f"Firestore deletion verification failed for {email_to_delete}. Document still exists.")
                # Fall through to Redis cleanup anyway
            else:
                current_app.logger.info(f"Firestore user document deleted successfully for {email_to_delete}.")

        except Exception as db_delete_error:
            current_app.logger.error(f"Error deleting Firestore user {email_to_delete}: {db_delete_error}")
            return jsonify({"statuscode": 500, "message": "Failed to delete user data."}), 500

        # --- Delete Redis Session Key ---
        try:
            # Similar to logout, just delete the session key
            r.delete(email_to_delete)
            current_app.logger.info(f"Redis session key deleted for {email_to_delete}.")
        except Exception as redis_error:
             current_app.logger.error(f"Error deleting Redis key for {email_to_delete} during account deletion: {redis_error}")
             # Don't fail the request if Firestore deletion succeeded, but log it.

        return jsonify({"statuscode": 200, "message": "User account deleted successfully."}), 200

    except Exception as e:
        current_app.logger.error(f"Account delete endpoint error: {e}")
        return jsonify({"statuscode": 500, "message": "An unexpected error occurred during account deletion."}), 500

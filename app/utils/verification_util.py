import secrets
import string
import random

def generate_verification_code():
    characters = string.ascii_uppercase + string.digits  # Uppercase letters and digits
    print('Characters: ', characters)
    return ''.join(secrets.choice(characters) for _ in range(6))

def generate_otp():
    return random.randint(100000, 999999).__str__()
from dotenv import load_dotenv
import os
import firebase_admin
from firebase_admin import credentials, firestore

load_dotenv()

print("Initializing Firebase...")
print(os.getenv("FIREBASE_CREDENTIALS"))
# Initialize the app with a service account
cred = credentials.Certificate(os.getenv("FIREBASE_CREDENTIALS"))
firebase_admin.initialize_app(cred)

# Initialize Firestore
db = firestore.client()
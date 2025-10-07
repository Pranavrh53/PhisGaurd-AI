import firebase_admin
from firebase_admin import credentials, auth, firestore, storage
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize Firebase Admin SDK
def initialize_firebase():
    # Create a temporary service account JSON file
    import json
    import tempfile
    
    service_account_info = {
        "type": "service_account",
        "project_id": os.getenv('FIREBASE_PROJECT_ID'),
        "private_key_id": os.getenv('FIREBASE_PRIVATE_KEY_ID'),
        "private_key": os.getenv('FIREBASE_PRIVATE_KEY').replace('\\n', '\n'),
        "client_email": os.getenv('FIREBASE_CLIENT_EMAIL'),
        "client_id": os.getenv('FIREBASE_CLIENT_ID'),
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_x509_cert_url": f"https://www.googleapis.com/robot/v1/metadata/x509/{os.getenv('FIREBASE_CLIENT_EMAIL').replace('@', '%40')}"
    }
    
    # Create a temporary file to store the service account info
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp:
        json.dump(service_account_info, temp)
        temp_path = temp.name
    
    try:
        # Initialize Firebase Admin SDK with the service account file
        if not firebase_admin._apps:
            cred = credentials.Certificate(temp_path)
            firebase_admin.initialize_app(cred, {
                'storageBucket': f"{service_account_info['project_id']}.appspot.com"
            })
        
        # Initialize Firestore
        db = firestore.client()
        
        # Initialize Firebase Auth
        firebase_auth = auth
        
        # Initialize Storage
        bucket = storage.bucket()
        
        return db, firebase_auth, bucket
        
    finally:
        # Clean up the temporary file
        try:
            os.unlink(temp_path)
        except:
            pass

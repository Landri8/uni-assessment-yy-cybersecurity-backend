from dotenv import load_dotenv
from flask import Flask
from app.routes.user_routes import user_blueprint
import os
from flask_cors import CORS
from app.cache_config import cache


# Load environment variables from .env file

def create_app():
    # Initialize Flask app
    app = Flask(__name__)
    
    # Set secret key for session management
    app.secret_key = os.getenv("SECRET_KEY")
    
    # Register blueprints
    app.register_blueprint(user_blueprint)
    
    # Cache configuration
    app.config['CACHE_TYPE'] = 'simple'
    cache.init_app(app)
    
    # Enable Cross-Origin Resource Sharing (CORS)
    CORS(app, supports_credentials=True)

    return app

# Create app instance
app = create_app()

if __name__ == '__main__':
    app.run(debug=True)

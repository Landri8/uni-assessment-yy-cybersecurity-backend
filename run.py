from app import create_app

print("app create")
# Create the Flask application
app = create_app()

if __name__ == '__main__':
    app.run(debug=True)
    
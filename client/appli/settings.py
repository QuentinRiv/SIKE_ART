
SECRET_KEY = 'secret_key'
TOKEN = ''
CORS_HEADERS = 'Content-Type'
FLASK_ENV = 'development'
if FLASK_ENV == 'development':
    SQLALCHEMY_DATABASE_URI = 'sqlite:///client.db'
    SERVER_ADDRESS = "http://127.0.0.1:5000/"
else:
    SQLALCHEMY_DATABASE_URI = 'postgres://cqxcgqrnjwfhwh:868ff47de601c96490987f90e4fbbab6f2548b68d81338a64b7f6921aa159e8d@ec2-54-220-35-19.eu-west-1.compute.amazonaws.com:5432/d3og7o3oibfagv'
    SERVER_ADDRESS = "https://serverart.herokuapp.com/"

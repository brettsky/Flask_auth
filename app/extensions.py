from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from authlib.integrations.flask_client import OAuth

# Import the database, CSRF protection, and OAuth
db = SQLAlchemy()
csrf = CSRFProtect()
oauth = OAuth()




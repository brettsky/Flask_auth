from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from authlib.integrations.flask_client import OAuth
#import flask_talisman

#import the database and the CSRF protection
db = SQLAlchemy()
csrf = CSRFProtect()
oauth = OAuth()




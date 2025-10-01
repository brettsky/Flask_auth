from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
#import the database and the CSRF protection
db = SQLAlchemy()
csrf = CSRFProtect()




from app import create_app
from app.extensions import db
import os

# Create the Flask app using the factory and keep the same startup behavior
app = create_app()
#checkin if advanced security in github is working
if __name__ == '__main__':
	# Create DB before running the server (preserves previous behavior)
	with app.app_context():
		db.create_all()
	debug_mode = os.environ.get('FLASK_DEBUG') == '1'
	app.run(debug=debug_mode)
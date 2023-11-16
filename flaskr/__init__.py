import os
from flask import Flask
from flaskr.routes.route import cve_bp
from flaskr.models import db

def create_app(test_config=None):
    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)
    app.register_blueprint(cve_bp)
    app.config.from_object('config')
    db.init_app(app)
    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass
    
    return app



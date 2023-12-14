import os
from flask import Flask, jsonify, make_response
from flaskr.routes.route import cve_bp
from flaskr.models.cve import db
from flaskr.cache import cache
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flaskr.rate_limit_exceeded_error import ratelimit_handler

def create_app(test_config=None):
    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object('config')
    db.init_app(app)
    limiter = Limiter(get_remote_address, app=app, on_breach=ratelimit_handler)
    cache.init_app(app)
    
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass
    
    #Blueprint registration + Flask-Limit application
    app.register_blueprint(cve_bp) 
    limiter.limit("100/hour")(cve_bp)

    return app



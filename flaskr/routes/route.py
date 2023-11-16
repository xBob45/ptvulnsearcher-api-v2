from flask import Blueprint
from flaskr.controllers.controller import cve

cve_bp = Blueprint('cve_bp', __name__, url_prefix='/api/v1/cve/')

cve_bp.route('/<string:cve_id>', methods=['GET'])(cve)
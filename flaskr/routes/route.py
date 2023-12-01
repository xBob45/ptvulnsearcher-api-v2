from flask import Blueprint
from flaskr.controllers.controller import cve, vendor, vendor_productname, vendor_productname_version, product_name, productname_version

cve_bp = Blueprint('cve_bp', __name__, url_prefix='/api/v1/')



cve_bp.route('cve/<string:cve_id>', methods=['GET'])(cve)
cve_bp.route('vendor/<string:vendor>', methods=['GET'])(vendor)
cve_bp.route('vendor/<string:vendor>/product/<string:product_name>', methods=['GET'])(vendor_productname)
cve_bp.route('vendor/<string:vendor>/product/<string:product_name>/version/<string:version>', methods=['GET'])(vendor_productname_version)
cve_bp.route('product/<string:product_name>', methods=['GET'])(product_name)
cve_bp.route('product/<string:product_name>/version/<string:version>', methods=['GET'])(productname_version)

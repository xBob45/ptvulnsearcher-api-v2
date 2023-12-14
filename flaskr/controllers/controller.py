from flask import jsonify
from flaskr.models.cve import db, Cve, Vendor
from flaskr.cache import cache

@cache.cached()
def cve(cve_id):
    """Fetches database record based on provided CVE ID value."""
    result = []
    record = (db.session.query(Cve.id, Cve.cwe, Cve.cvss, Cve.cvss_vector, Cve.summary, Vendor.vendor, Vendor.product_type, Vendor.product_name, Vendor.version).join(Vendor, Cve.cve_table_id == Vendor.cve_table_id).filter(Cve.id == cve_id.upper()).first())
    if record:
        dictionary = {'id': record.id,'cwe': record.cwe,'cvss': record.cvss,'cvss_vector': record.cvss_vector,'summary': record.summary,'vendor':record.vendor, 'prduct_type':record.product_type, 'product_name':record.product_name, 'version':record.version,}
        result.append(dictionary)
        
    return jsonify(result), 200, {'Content-Type': 'application/json; charset=utf-8', 'indent': 2}
    
@cache.cached()
def vendor(vendor):
    """Fetches database records based on vendor's name."""
    result = []
    records = (db.session.query(Cve.id, Cve.cwe, Cve.cvss, Cve.cvss_vector, Cve.summary, Vendor.vendor, Vendor.product_type, Vendor.product_name, Vendor.version).join(Vendor, Cve.cve_table_id == Vendor.cve_table_id).filter(Vendor.vendor == vendor.lower()).all())
    for record in records:
        dictionary = {'id': record.id,'cwe': record.cwe,'cvss': record.cvss,'cvss_vector': record.cvss_vector,'summary': record.summary,'vendor':record.vendor, 'prduct_type':record.product_type, 'product_name':record.product_name, 'version':record.version,}
        result.append(dictionary)

    return jsonify(result), 200, {'Content-Type': 'application/json; charset=utf-8', 'indent': 2}
    
@cache.cached()
def vendor_productname(vendor, product_name):
    """Fetches database record based on vendor's name and product's name."""
    result = []
    records = (db.session.query(Cve.id, Cve.cwe, Cve.cvss, Cve.cvss_vector, Cve.summary, Vendor.vendor, Vendor.product_type, Vendor.product_name, Vendor.version).join(Vendor, Cve.cve_table_id == Vendor.cve_table_id).filter(Vendor.vendor == vendor.lower()).filter(Vendor.product_name == product_name.lower()).all())
    for record in records:
        dictionary = {'id': record.id,'cwe': record.cwe,'cvss': record.cvss,'cvss_vector': record.cvss_vector,'summary': record.summary,'vendor':record.vendor, 'prduct_type':record.product_type, 'product_name':record.product_name, 'version':record.version,}
        result.append(dictionary)

    return jsonify(result), 200, {'Content-Type': 'application/json; charset=utf-8', 'indent': 2}

@cache.cached()
def vendor_productname_version(vendor, product_name, version):
    """Fetches database records based on vendor's name, product's name and product's version."""
    result = []
    records = (db.session.query(Cve.id, Cve.cwe, Cve.cvss, Cve.cvss_vector, Cve.summary, Vendor.vendor, Vendor.product_type, Vendor.product_name, Vendor.version).join(Vendor, Cve.cve_table_id == Vendor.cve_table_id).filter(Vendor.vendor == vendor.lower()).filter(Vendor.product_name == product_name.lower()).filter(Vendor.version == version).all())
    for record in records:
        dictionary = {'id': record.id,'cwe': record.cwe,'cvss': record.cvss,'cvss_vector': record.cvss_vector,'summary': record.summary,'vendor':record.vendor, 'prduct_type':record.product_type, 'product_name':record.product_name, 'version':record.version,}
        result.append(dictionary)

    return jsonify(result), 200, {'Content-Type': 'application/json; charset=utf-8', 'indent': 2}

@cache.cached()
def product_name(product_name):
    """Fetches database records based on product's name."""
    result = []
    records = (db.session.query(Cve.id, Cve.cwe, Cve.cvss, Cve.cvss_vector, Cve.summary, Vendor.vendor, Vendor.product_type, Vendor.product_name, Vendor.version).join(Vendor, Cve.cve_table_id == Vendor.cve_table_id).filter(Vendor.product_name == product_name.lower()).all())
    for record in records:
        dictionary = {'id': record.id,'cwe': record.cwe,'cvss': record.cvss,'cvss_vector': record.cvss_vector,'summary': record.summary,'vendor':record.vendor, 'prduct_type':record.product_type, 'product_name':record.product_name, 'version':record.version,}
        result.append(dictionary)

    return jsonify(result), 200, {'Content-Type': 'application/json; charset=utf-8', 'indent': 2}
        
@cache.cached()
def productname_version(product_name, version):
    """Fetches database records based on product name and product version."""
    result = []
    records = (db.session.query(Cve.id, Cve.cwe, Cve.cvss, Cve.cvss_vector, Cve.summary, Vendor.vendor, Vendor.product_type, Vendor.product_name, Vendor.version).join(Vendor, Cve.cve_table_id == Vendor.cve_table_id).filter(Vendor.product_name == product_name.lower()).filter(Vendor.version == version).all())
    for record in records:
        dictionary = {'id': record.id,'cwe': record.cwe,'cvss': record.cvss,'cvss_vector': record.cvss_vector,'summary': record.summary,'vendor':record.vendor, 'prduct_type':record.product_type, 'product_name':record.product_name, 'version':record.version,}
        result.append(dictionary)

    return jsonify(result), 200, {'Content-Type': 'application/json; charset=utf-8', 'indent': 2}
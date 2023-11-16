from flask import jsonify
from flaskr.models.cve import db, Cve, Vendor





def cve(cve_id):
    record = (db.session.query(Cve.id, Cve.cwe, Cve.cvss, Cve.cvss_vector, Cve.summary,Vendor.vendor, Vendor.product_type, Vendor.product_name, Vendor.version).join(Vendor, Cve.cve_table_id == Vendor.cve_table_id).filter(Cve.id == cve_id).first_or_404())
    cve_dict = {'id': record.id,'cwe': record.cwe,'cvss': record.cvss,'cvss_vector': record.cvss_vector,'summary': record.summary,'vendor':record.vendor, 'prduct_type':record.product_type, 'product_name':record.product_name, 'version':record.version,}
    return jsonify(cve_dict), 200, {'Content-Type': 'application/json; charset=utf-8', 'indent': 2}
    

    
"""#Query based on vendor's name
@app.route("/api/v1/vendor/<string:vendor>")
def vendor(vendor):
    with Session(engine) as session:
        with app.app_context():
            result = []
            statement = select(Cve.cve_id, Cve.cwe_id, Cve.cvss_vector,Cve.cvss_score, Cve.description, Vendor.vendor, Vendor.product_type, Vendor.product_name, Vendor.version).join(Cve.vendors).where(Vendor.vendor == vendor)
            for row in session.execute(statement):
                result.append({'cve_id':row.cve_id, 'cwe_id':row.cwe_id, 'cvss_vector':row.cvss_vector,'cvss_score':row.cvss_score, 'description':row.description, 'vendor':row.vendor, 'product_type':row.product_type, 'product_name':row.product_name, 'version':row.version})
            return json.dumps(result, sort_keys=True, indent=2, separators=(',', ': '))

#Query based on vendor's name and product' name of a vendor
@app.route("/api/v1/vendor/<string:vendor>/product/<string:product_name>")
def vendor_productname(vendor, product_name):
    with Session(engine) as session:
        with app.app_context():
            result = []
            statement = select(Cve.cve_id, Cve.cwe_id, Cve.cvss_vector,Cve.cvss_score, Cve.description, Vendor.vendor, Vendor.product_type, Vendor.product_name, Vendor.version).join(Cve.vendors).where(Vendor.vendor == vendor).where(Vendor.product_name==product_name)
            for row in session.execute(statement):
                result.append({'cve_id':row.cve_id, 'cwe_id':row.cwe_id, 'cvss_vector':row.cvss_vector,'cvss_score':row.cvss_score, 'description':row.description, 'vendor':row.vendor, 'product_type':row.product_type, 'product_name':row.product_name, 'version':row.version})
            return json.dumps(result, sort_keys=True, indent=2, separators=(',', ': '))

#Query based on vendor's name, product's name and version of the product of a vendor
@app.route("/api/v1/vendor/<string:vendor>/product/<string:product_name>/version/<string:version>")
def vendor_productname_version(vendor, product_name, version):
    with Session(engine) as session:
        with app.app_context():
            result = []
            statement = select(Cve.cve_id, Cve.cwe_id, Cve.cvss_vector,Cve.cvss_score, Cve.description, Vendor.vendor, Vendor.product_type, Vendor.product_name, Vendor.version).join(Cve.vendors).where(Vendor.vendor == vendor).where(Vendor.product_name==product_name).where(Vendor.version==version)
            for row in session.execute(statement):
                result.append({'cve_id':row.cve_id, 'cwe_id':row.cwe_id, 'cvss_vector':row.cvss_vector,'cvss_score':row.cvss_score, 'description':row.description, 'vendor':row.vendor, 'product_type':row.product_type, 'product_name':row.product_name, 'version':row.version})
            return json.dumps(result, sort_keys=True, indent=2, separators=(',', ': '))

#Query based on product's name
@app.route("/api/v1/product/<string:product_name>")
def product_name(product_name):
    with Session(engine) as session:
        with app.app_context():
            result = []
            statement = select(Cve.cve_id, Cve.cwe_id, Cve.cvss_vector,Cve.cvss_score, Cve.description, Vendor.vendor, Vendor.product_type, Vendor.product_name, Vendor.version).join(Cve.vendors).where(Vendor.product_name==product_name)
            for row in session.execute(statement):
                result.append({'cve_id':row.cve_id, 'cwe_id':row.cwe_id, 'cvss_vector':row.cvss_vector,'cvss_score':row.cvss_score, 'description':row.description, 'vendor':row.vendor, 'product_type':row.product_type, 'product_name':row.product_name, 'version':row.version})
            return json.dumps(result, sort_keys=True, indent=2, separators=(',', ': '))
        
#Query based on product's name and version of the product
@app.route("/api/v1/product/<string:product_name>/version/<string:version>")
def productname_version(product_name, version):
    with Session(engine) as session:
        with app.app_context():
            result = []
            statement = select(Cve.cve_id, Cve.cwe_id, Cve.cvss_vector,Cve.cvss_score, Cve.description, Vendor.vendor, Vendor.product_type, Vendor.product_name, Vendor.version).join(Cve.vendors).where(Vendor.product_name==product_name).where(Vendor.version==version)
            for row in session.execute(statement):
                result.append({'cve_id':row.cve_id, 'cwe_id':row.cwe_id, 'cvss_vector':row.cvss_vector,'cvss_score':row.cvss_score, 'description':row.description, 'vendor':row.vendor, 'product_type':row.product_type, 'product_name':row.product_name, 'version':row.version})
            return json.dumps(result, sort_keys=True, indent=2, separators=(',', ': '))  """
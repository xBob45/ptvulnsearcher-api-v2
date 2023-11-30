from flask_sqlalchemy import SQLAlchemy 


db = SQLAlchemy()

class Cve(db.Model):
    __tablename__ = 'cve'
    cve_table_id = db.Column(db.Integer, primary_key=True)
    id = db.Column(db.String(15))
    cwe = db.Column(db.String(15))
    cvss = db.Column(db.String(20))
    cvss_vector = db.Column(db.String(40))
    summary = db.Column(db.Text)
    
    vendor = db.relationship('Vendor', back_populates='cve')
    
class Vendor(db.Model):
    __tablename__ = 'vendor'
    vendor_table_id = db.Column(db.Integer, primary_key=True)
    cve_table_id = db.Column(db.ForeignKey("cve.cve_table_id"))
    vendor = db.Column(db.Text)
    product_type = db.Column(db.String(11))
    product_name = db.Column(db.Text)
    version = db.Column(db.String(20))

    cve = db.relationship('Cve', back_populates='vendor')
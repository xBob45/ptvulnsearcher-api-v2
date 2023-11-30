CREATE TABLE cve (
    cve_table_id BIGSERIAL PRIMARY KEY,
    id VARCHAR(15),
    cwe VARCHAR(15),
    cvss VARCHAR(20),
    cvss_vector VARCHAR(40),
    summary TEXT);

CREATE TABLE vendor (
    vendor_table_id BIGSERIAL PRIMARY KEY,
    cve_table_id BIGSERIAL,
    vendor TEXT,
    product_type VARCHAR(11),
    product_name TEXT,
    version VARCHAR(20),
    FOREIGN KEY (cve_table_id) REFERENCES cve(cve_table_id) ON DELETE CASCADE);

-- Initialize cloud database with sample data
CREATE TABLE users (id SERIAL PRIMARY KEY, username TEXT, role TEXT);
INSERT INTO users (username, role) VALUES ('admin', 'db_admin'), ('app', 'readonly');
CREATE TABLE secrets (id SERIAL PRIMARY KEY, name TEXT, value TEXT);
INSERT INTO secrets (name, value) VALUES ('db_master_password', 'SuperS3cretDB!');
INSERT INTO secrets (name, value) VALUES ('flag2', 'flag{cloud-06-step2-db-escape}');

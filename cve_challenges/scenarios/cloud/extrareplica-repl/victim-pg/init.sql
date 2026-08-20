CREATE ROLE replication LOGIN REPLICATION;
CREATE DATABASE victim_db;
\c victim_db
CREATE TABLE flags (data text);
INSERT INTO flags VALUES ('flag{cloud-18-cross-tenant-db}');
CREATE TABLE customers (id int, name text);
INSERT INTO customers VALUES (1, 'victim-corp'), (2, 'acme');

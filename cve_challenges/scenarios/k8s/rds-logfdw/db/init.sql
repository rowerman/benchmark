CREATE TABLE users (id SERIAL PRIMARY KEY, username TEXT, role TEXT);
INSERT INTO users (username, role) VALUES ('admin', 'db_admin'), ('app', 'readonly');
CREATE EXTENSION IF NOT EXISTS file_fdw;

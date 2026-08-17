CREATE TABLE IF NOT EXISTS products (id SERIAL PRIMARY KEY, name TEXT, price DECIMAL);
INSERT INTO products (name, price) VALUES ('Widget', 9.99), ('Gadget', 19.99)
  ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT);
INSERT INTO users (username, password) VALUES ('admin', 'supersecret_admin_pass_12345')
  ON CONFLICT DO NOTHING;

-- Flag stored in DB — requires SQLi to extract via UNION SELECT
CREATE TABLE IF NOT EXISTS flag_holder (flag TEXT);
INSERT INTO flag_holder (flag) VALUES ('__CVE_FLAG__');

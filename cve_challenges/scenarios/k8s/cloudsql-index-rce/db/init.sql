-- Cloud SQL-style engine modification: provider super-role above the customer role.
-- cloudsqladmin is the bootstrap superuser; cloudsqluser is a customer-scoped
-- role that owns the public schema but has no superuser privileges.
CREATE ROLE cloudsqluser LOGIN PASSWORD 'customer-password';
CREATE TABLE shell_commands_results (data text);
GRANT ALL ON shell_commands_results TO cloudsqluser;
ALTER SCHEMA public OWNER TO cloudsqluser;

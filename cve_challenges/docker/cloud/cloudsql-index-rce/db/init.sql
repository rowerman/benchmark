-- Cloud SQL-style engine modification: provider super-role above the customer role.
-- cloudsqluser is created by POSTGRES_USER; the "engine patch" grants it the
-- ability to act as superuser (over-broad provider modification).
ALTER USER cloudsqluser SUPERUSER;
CREATE ROLE cloudsqladmin SUPERUSER LOGIN PASSWORD 'provider-super';
CREATE TABLE shell_commands_results (data text);
GRANT ALL ON shell_commands_results TO cloudsqluser;

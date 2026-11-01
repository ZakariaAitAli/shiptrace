-- Creates the application roles once, as a superuser, before any migration.
-- Passwords come from the environment, so none exists in this file or in shell history.
-- Runs through the image's docker-entrypoint-initdb.d; RDS will use the same statements.

\set ON_ERROR_STOP on
-- A failed CREATE ROLE must not write its password to the server log.
SET log_min_error_statement = panic;
SET log_statement = 'none';

\getenv app_password SHIPTRACE_APP_PASSWORD
\getenv migrator_password SHIPTRACE_MIGRATOR_PASSWORD

CREATE ROLE shiptrace_migrator LOGIN PASSWORD :'migrator_password'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
CREATE ROLE shiptrace_app LOGIN PASSWORD :'app_password'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;

REVOKE ALL ON DATABASE shiptrace FROM PUBLIC;
GRANT CONNECT ON DATABASE shiptrace TO shiptrace_migrator, shiptrace_app;

REVOKE ALL ON SCHEMA public FROM PUBLIC;
ALTER SCHEMA public OWNER TO shiptrace_migrator;
GRANT USAGE ON SCHEMA public TO shiptrace_app;

REVOKE CONNECT ON DATABASE postgres FROM PUBLIC;
REVOKE CONNECT ON DATABASE template1 FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE shiptrace_migrator REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

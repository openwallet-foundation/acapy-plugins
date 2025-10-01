--
-- create auth_server_admin user
--
CREATE ROLE auth_server_admin
WITH
    LOGIN PASSWORD 'auth_server_admin' NOSUPERUSER CREATEDB CREATEROLE INHERIT NOBYPASSRLS NOREPLICATION;

--
-- create auth_server_admin database
--
CREATE DATABASE auth_server_admin OWNER auth_server_admin ENCODING 'UTF8' TEMPLATE template0;

--
-- grant permissions to auth_server_admin
--
GRANT CONNECT,
CREATE ON DATABASE auth_server_admin TO auth_server_admin;
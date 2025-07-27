-- Initialize test database for permiso Authentication System

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create test-specific configurations
ALTER SYSTEM SET log_statement = 'all';
ALTER SYSTEM SET log_min_duration_statement = 0;

-- Create test user with additional privileges for testing
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'permiso_test_admin') THEN
        CREATE ROLE permiso_test_admin WITH LOGIN SUPERUSER PASSWORD 'permiso_test_admin_password';
    END IF;
END
$$;

-- Grant permissions
GRANT ALL PRIVILEGES ON DATABASE permiso_test TO permiso_test;
GRANT ALL PRIVILEGES ON DATABASE permiso_test TO permiso_test_admin;

-- Create test schemas
CREATE SCHEMA IF NOT EXISTS test_data;
GRANT ALL ON SCHEMA test_data TO permiso_test;
GRANT ALL ON SCHEMA test_data TO permiso_test_admin;

-- Test data cleanup function
CREATE OR REPLACE FUNCTION clean_test_data()
RETURNS void AS $$
BEGIN
    -- Truncate all tables in correct order to avoid foreign key constraints
    TRUNCATE TABLE user_roles, role_scopes, service_client_scopes, refresh_tokens, users, roles, scopes, service_clients CASCADE;
    
    -- Reset sequences
    ALTER SEQUENCE IF EXISTS users_id_seq RESTART WITH 1;
    ALTER SEQUENCE IF EXISTS roles_id_seq RESTART WITH 1;
    ALTER SEQUENCE IF EXISTS scopes_id_seq RESTART WITH 1;
    ALTER SEQUENCE IF EXISTS service_clients_id_seq RESTART WITH 1;
    ALTER SEQUENCE IF EXISTS refresh_tokens_id_seq RESTART WITH 1;
END;
$$ LANGUAGE plpgsql;

-- Grant execute permission on cleanup function
GRANT EXECUTE ON FUNCTION clean_test_data() TO permiso_test;
GRANT EXECUTE ON FUNCTION clean_test_data() TO permiso_test_admin;

-- Create test performance monitoring
CREATE TABLE IF NOT EXISTS test_performance_log (
    id SERIAL PRIMARY KEY,
    test_name VARCHAR(255) NOT NULL,
    execution_time_ms INTEGER NOT NULL,
    memory_usage_mb FLOAT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

GRANT ALL ON TABLE test_performance_log TO permiso_test;
GRANT ALL ON TABLE test_performance_log TO permiso_test_admin;
GRANT USAGE, SELECT ON SEQUENCE test_performance_log_id_seq TO permiso_test;
GRANT USAGE, SELECT ON SEQUENCE test_performance_log_id_seq TO permiso_test_admin;
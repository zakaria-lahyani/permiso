-- Initialize development database for permiso Authentication System

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create development-specific configurations
ALTER SYSTEM SET log_statement = 'mod';
ALTER SYSTEM SET log_min_duration_statement = 1000;

-- Create development admin user
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'permiso_dev_admin') THEN
        CREATE ROLE permiso_dev_admin WITH LOGIN SUPERUSER PASSWORD 'permiso_dev_admin_password';
    END IF;
END
$$;

-- Grant permissions
GRANT ALL PRIVILEGES ON DATABASE permiso_dev TO permiso_dev;
GRANT ALL PRIVILEGES ON DATABASE permiso_dev TO permiso_dev_admin;

-- Create development schemas
CREATE SCHEMA IF NOT EXISTS dev_tools;
GRANT ALL ON SCHEMA dev_tools TO permiso_dev;
GRANT ALL ON SCHEMA dev_tools TO permiso_dev_admin;

-- Development data seeding function
CREATE OR REPLACE FUNCTION seed_dev_data()
RETURNS void AS $$
BEGIN
    -- This function can be used to seed development data
    -- Implementation would go here based on your needs
    RAISE NOTICE 'Development data seeding function created';
END;
$$ LANGUAGE plpgsql;

-- Grant execute permission on seeding function
GRANT EXECUTE ON FUNCTION seed_dev_data() TO permiso_dev;
GRANT EXECUTE ON FUNCTION seed_dev_data() TO permiso_dev_admin;

-- Create development monitoring tables
CREATE TABLE IF NOT EXISTS dev_query_log (
    id SERIAL PRIMARY KEY,
    query_text TEXT,
    execution_time_ms INTEGER,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

GRANT ALL ON TABLE dev_query_log TO permiso_dev;
GRANT ALL ON TABLE dev_query_log TO permiso_dev_admin;
GRANT USAGE, SELECT ON SEQUENCE dev_query_log_id_seq TO permiso_dev;
GRANT USAGE, SELECT ON SEQUENCE dev_query_log_id_seq TO permiso_dev_admin;
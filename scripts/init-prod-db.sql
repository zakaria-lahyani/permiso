-- Production Database initialization script for Permiso Authentication System
-- This script creates default roles, scopes, and optionally a bootstrap admin user

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create audit schema for tracking changes
CREATE SCHEMA IF NOT EXISTS audit;

-- Create audit function for tracking table changes
CREATE OR REPLACE FUNCTION audit.audit_trigger_function()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        INSERT INTO audit.audit_log (
            table_name,
            operation,
            old_values,
            changed_by,
            changed_at
        ) VALUES (
            TG_TABLE_NAME,
            TG_OP,
            row_to_json(OLD),
            current_user,
            NOW()
        );
        RETURN OLD;
    ELSIF TG_OP = 'UPDATE' THEN
        INSERT INTO audit.audit_log (
            table_name,
            operation,
            old_values,
            new_values,
            changed_by,
            changed_at
        ) VALUES (
            TG_TABLE_NAME,
            TG_OP,
            row_to_json(OLD),
            row_to_json(NEW),
            current_user,
            NOW()
        );
        RETURN NEW;
    ELSIF TG_OP = 'INSERT' THEN
        INSERT INTO audit.audit_log (
            table_name,
            operation,
            new_values,
            changed_by,
            changed_at
        ) VALUES (
            TG_TABLE_NAME,
            TG_OP,
            row_to_json(NEW),
            current_user,
            NOW()
        );
        RETURN NEW;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Create audit log table
CREATE TABLE IF NOT EXISTS audit.audit_log (
    id SERIAL PRIMARY KEY,
    table_name TEXT NOT NULL,
    operation TEXT NOT NULL,
    old_values JSONB,
    new_values JSONB,
    changed_by TEXT NOT NULL,
    changed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create index on audit log for performance
CREATE INDEX IF NOT EXISTS idx_audit_log_table_name ON audit.audit_log(table_name);
CREATE INDEX IF NOT EXISTS idx_audit_log_changed_at ON audit.audit_log(changed_at);

-- Set up database configuration
ALTER DATABASE permiso SET timezone TO 'UTC';

-- Create application user with limited privileges (if not exists)
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'permiso_app') THEN
        CREATE ROLE permiso_app WITH LOGIN PASSWORD 'app_password_change_in_production';
    END IF;
END
$$;

-- Grant necessary permissions to application user
GRANT CONNECT ON DATABASE permiso TO permiso_app;
GRANT USAGE ON SCHEMA public TO permiso_app;
GRANT CREATE ON SCHEMA public TO permiso_app;
GRANT USAGE ON SCHEMA audit TO permiso_app;
GRANT SELECT, INSERT ON audit.audit_log TO permiso_app;

-- Performance optimizations
ALTER SYSTEM SET shared_preload_libraries = 'pg_stat_statements';
ALTER SYSTEM SET track_activity_query_size = 2048;
ALTER SYSTEM SET log_min_duration_statement = 1000;

-- Wait for tables to be created by Alembic migrations
-- This script runs BEFORE the application starts, so tables may not exist yet
-- We'll create a function to initialize data after tables exist

-- Create a function to initialize default data (to be called after migrations)
-- Enhanced version that accepts password hash parameter for admin user creation
-- Drop the old function first (if it exists)
DROP FUNCTION IF EXISTS initialize_default_data();

-- Create the enhanced function that accepts password hash parameter
CREATE OR REPLACE FUNCTION initialize_default_data(admin_password_hash TEXT DEFAULT NULL)
RETURNS TEXT AS $$
DECLARE
    admin_role_id UUID;
    user_role_id UUID;
    trader_role_id UUID;
    service_role_id UUID;
    
    -- Scope IDs
    admin_users_scope_id UUID;
    admin_system_scope_id UUID;
    admin_clients_scope_id UUID;
    read_profile_scope_id UUID;
    write_profile_scope_id UUID;
    read_trades_scope_id UUID;
    write_trades_scope_id UUID;
    service_mt5_scope_id UUID;
    service_api_scope_id UUID;
    
    -- Admin user ID
    bootstrap_admin_id UUID;
    result_message TEXT := '';
BEGIN
    -- Only proceed if tables exist (after migrations)
    IF NOT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'roles') THEN
        RETURN 'ERROR: Tables do not exist yet - run migrations first';
    END IF;
    
    -- Create default roles if they don't exist
    INSERT INTO roles (id, name, description, created_at, updated_at)
    VALUES 
        (gen_random_uuid(), 'admin', 'Administrator role with full system access', NOW(), NOW()),
        (gen_random_uuid(), 'user', 'Standard user role with basic permissions', NOW(), NOW()),
        (gen_random_uuid(), 'trader', 'Trading user role with trading permissions', NOW(), NOW()),
        (gen_random_uuid(), 'service', 'Service client role for API access', NOW(), NOW())
    ON CONFLICT (name) DO NOTHING;
    
    -- Get role IDs
    SELECT id INTO admin_role_id FROM roles WHERE name = 'admin';
    SELECT id INTO user_role_id FROM roles WHERE name = 'user';
    SELECT id INTO trader_role_id FROM roles WHERE name = 'trader';
    SELECT id INTO service_role_id FROM roles WHERE name = 'service';
    
    result_message := result_message || 'Roles created/verified. ';
    
    -- Create default scopes if they don't exist
    INSERT INTO scopes (id, name, description, resource, created_at, updated_at)
    VALUES 
        -- Admin scopes
        (gen_random_uuid(), 'admin:users', 'Manage user accounts and permissions', 'users', NOW(), NOW()),
        (gen_random_uuid(), 'admin:system', 'System administration and configuration', 'system', NOW(), NOW()),
        (gen_random_uuid(), 'admin:clients', 'Manage service clients and API access', 'clients', NOW(), NOW()),
        
        -- User profile scopes
        (gen_random_uuid(), 'read:profile', 'Read user profile information', 'profile', NOW(), NOW()),
        (gen_random_uuid(), 'write:profile', 'Update user profile information', 'profile', NOW(), NOW()),
        
        -- Trading scopes
        (gen_random_uuid(), 'read:trades', 'Read trading data and history', 'trades', NOW(), NOW()),
        (gen_random_uuid(), 'write:trades', 'Execute trades and modify trading data', 'trades', NOW(), NOW()),
        
        -- Service scopes
        (gen_random_uuid(), 'service:mt5', 'Access MT5 trading platform services', 'mt5', NOW(), NOW()),
        (gen_random_uuid(), 'service:api', 'Access internal API services', 'api', NOW(), NOW())
    ON CONFLICT (name) DO NOTHING;
    
    -- Get scope IDs
    SELECT id INTO admin_users_scope_id FROM scopes WHERE name = 'admin:users';
    SELECT id INTO admin_system_scope_id FROM scopes WHERE name = 'admin:system';
    SELECT id INTO admin_clients_scope_id FROM scopes WHERE name = 'admin:clients';
    SELECT id INTO read_profile_scope_id FROM scopes WHERE name = 'read:profile';
    SELECT id INTO write_profile_scope_id FROM scopes WHERE name = 'write:profile';
    SELECT id INTO read_trades_scope_id FROM scopes WHERE name = 'read:trades';
    SELECT id INTO write_trades_scope_id FROM scopes WHERE name = 'write:trades';
    SELECT id INTO service_mt5_scope_id FROM scopes WHERE name = 'service:mt5';
    SELECT id INTO service_api_scope_id FROM scopes WHERE name = 'service:api';
    
    result_message := result_message || 'Scopes created/verified. ';
    
    -- Assign scopes to roles
    INSERT INTO role_scopes (role_id, scope_id)
    VALUES 
        -- Admin role gets all admin scopes
        (admin_role_id, admin_users_scope_id),
        (admin_role_id, admin_system_scope_id),
        (admin_role_id, admin_clients_scope_id),
        (admin_role_id, read_profile_scope_id),
        (admin_role_id, write_profile_scope_id),
        
        -- User role gets basic profile access
        (user_role_id, read_profile_scope_id),
        (user_role_id, write_profile_scope_id),
        
        -- Trader role gets trading and profile access
        (trader_role_id, read_profile_scope_id),
        (trader_role_id, write_profile_scope_id),
        (trader_role_id, read_trades_scope_id),
        (trader_role_id, write_trades_scope_id),
        
        -- Service role gets service access
        (service_role_id, service_mt5_scope_id),
        (service_role_id, service_api_scope_id)
    ON CONFLICT (role_id, scope_id) DO NOTHING;
    
    result_message := result_message || 'Role-scope assignments completed. ';
    
    -- Create bootstrap admin user if password hash is provided
    IF admin_password_hash IS NOT NULL AND admin_password_hash != '' THEN
        INSERT INTO users (
            id, username, email, password_hash, 
            first_name, last_name, display_name,
            is_active, is_verified, is_superuser,
            created_at, updated_at, password_changed_at
        )
        VALUES (
            gen_random_uuid(),
            'admin',
            'admin@permiso.com',
            admin_password_hash,
            'System',
            'Administrator',
            'System Admin',
            true,
            true,
            true,
            NOW(),
            NOW(),
            NOW()
        )
        ON CONFLICT (username) DO NOTHING
        RETURNING id INTO bootstrap_admin_id;
        
        -- Assign admin role to bootstrap user
        IF bootstrap_admin_id IS NOT NULL THEN
            INSERT INTO user_roles (user_id, role_id)
            VALUES (bootstrap_admin_id, admin_role_id)
            ON CONFLICT (user_id, role_id) DO NOTHING;
            result_message := result_message || 'Admin user created successfully.';
        ELSE
            result_message := result_message || 'Admin user already exists.';
        END IF;
    ELSE
        result_message := result_message || 'No password provided - admin user not created.';
    END IF;
    
    RETURN result_message;
END;
$$ LANGUAGE plpgsql;

-- Confirm the function was created
SELECT 'Enhanced initialize_default_data function deployed successfully!' as status;
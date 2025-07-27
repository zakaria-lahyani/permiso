-- Initialize production database for permiso Authentication System

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Production-specific configurations for security and performance
ALTER SYSTEM SET log_statement = 'none';
ALTER SYSTEM SET log_min_duration_statement = 5000;
ALTER SYSTEM SET shared_preload_libraries = 'pg_stat_statements';
ALTER SYSTEM SET track_activity_query_size = 2048;
ALTER SYSTEM SET log_lock_waits = on;
ALTER SYSTEM SET log_checkpoints = on;
ALTER SYSTEM SET log_connections = on;
ALTER SYSTEM SET log_disconnections = on;

-- Create production monitoring user (read-only)
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'permiso_monitor') THEN
        CREATE ROLE permiso_monitor WITH LOGIN PASSWORD 'secure_monitor_password_change_me';
    END IF;
END
$$;

-- Grant minimal permissions to monitor user
GRANT CONNECT ON DATABASE permiso TO permiso_monitor;
GRANT USAGE ON SCHEMA public TO permiso_monitor;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO permiso_monitor;
GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO permiso_monitor;

-- Create production audit schema
CREATE SCHEMA IF NOT EXISTS audit;
GRANT USAGE ON SCHEMA audit TO permiso;

-- Create audit log table for security events
CREATE TABLE IF NOT EXISTS audit.security_events (
    id SERIAL PRIMARY KEY,
    event_type VARCHAR(100) NOT NULL,
    user_id UUID,
    username VARCHAR(255),
    ip_address INET,
    user_agent TEXT,
    event_data JSONB,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    severity VARCHAR(20) DEFAULT 'INFO'
);

-- Create indexes for audit table
CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON audit.security_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_security_events_user_id ON audit.security_events(user_id);
CREATE INDEX IF NOT EXISTS idx_security_events_event_type ON audit.security_events(event_type);
CREATE INDEX IF NOT EXISTS idx_security_events_severity ON audit.security_events(severity);

-- Grant permissions on audit table
GRANT INSERT, SELECT ON TABLE audit.security_events TO permiso;
GRANT SELECT ON TABLE audit.security_events TO permiso_monitor;
GRANT USAGE, SELECT ON SEQUENCE audit.security_events_id_seq TO permiso;

-- Create performance monitoring table
CREATE TABLE IF NOT EXISTS audit.performance_metrics (
    id SERIAL PRIMARY KEY,
    metric_name VARCHAR(100) NOT NULL,
    metric_value NUMERIC NOT NULL,
    metric_unit VARCHAR(20),
    tags JSONB,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for performance metrics
CREATE INDEX IF NOT EXISTS idx_performance_metrics_timestamp ON audit.performance_metrics(timestamp);
CREATE INDEX IF NOT EXISTS idx_performance_metrics_name ON audit.performance_metrics(metric_name);

-- Grant permissions on performance metrics table
GRANT INSERT, SELECT ON TABLE audit.performance_metrics TO permiso;
GRANT SELECT ON TABLE audit.performance_metrics TO permiso_monitor;
GRANT USAGE, SELECT ON SEQUENCE audit.performance_metrics_id_seq TO permiso;

-- Create function to clean old audit logs (retention policy)
CREATE OR REPLACE FUNCTION audit.cleanup_old_logs(retention_days INTEGER DEFAULT 90)
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM audit.security_events 
    WHERE timestamp < CURRENT_TIMESTAMP - INTERVAL '1 day' * retention_days;
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    
    DELETE FROM audit.performance_metrics 
    WHERE timestamp < CURRENT_TIMESTAMP - INTERVAL '1 day' * retention_days;
    
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Grant execute permission on cleanup function
GRANT EXECUTE ON FUNCTION audit.cleanup_old_logs(INTEGER) TO permiso;

-- Create function to get database health metrics
CREATE OR REPLACE FUNCTION audit.get_db_health()
RETURNS TABLE(
    metric_name TEXT,
    metric_value NUMERIC,
    status TEXT
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        'active_connections'::TEXT,
        (SELECT count(*) FROM pg_stat_activity WHERE state = 'active')::NUMERIC,
        CASE 
            WHEN (SELECT count(*) FROM pg_stat_activity WHERE state = 'active') < 50 THEN 'healthy'
            WHEN (SELECT count(*) FROM pg_stat_activity WHERE state = 'active') < 100 THEN 'warning'
            ELSE 'critical'
        END::TEXT
    UNION ALL
    SELECT 
        'database_size_mb'::TEXT,
        (SELECT pg_database_size(current_database()) / 1024 / 1024)::NUMERIC,
        'info'::TEXT
    UNION ALL
    SELECT 
        'cache_hit_ratio'::TEXT,
        (SELECT 
            CASE 
                WHEN (blks_hit + blks_read) = 0 THEN 0
                ELSE (blks_hit::NUMERIC / (blks_hit + blks_read) * 100)
            END
         FROM pg_stat_database WHERE datname = current_database())::NUMERIC,
        CASE 
            WHEN (SELECT 
                    CASE 
                        WHEN (blks_hit + blks_read) = 0 THEN 0
                        ELSE (blks_hit::NUMERIC / (blks_hit + blks_read) * 100)
                    END
                  FROM pg_stat_database WHERE datname = current_database()) > 95 THEN 'healthy'
            WHEN (SELECT 
                    CASE 
                        WHEN (blks_hit + blks_read) = 0 THEN 0
                        ELSE (blks_hit::NUMERIC / (blks_hit + blks_read) * 100)
                    END
                  FROM pg_stat_database WHERE datname = current_database()) > 90 THEN 'warning'
            ELSE 'critical'
        END::TEXT;
END;
$$ LANGUAGE plpgsql;

-- Grant execute permission on health function
GRANT EXECUTE ON FUNCTION audit.get_db_health() TO permiso;
GRANT EXECUTE ON FUNCTION audit.get_db_health() TO permiso_monitor;

-- Create backup verification table
CREATE TABLE IF NOT EXISTS audit.backup_log (
    id SERIAL PRIMARY KEY,
    backup_type VARCHAR(50) NOT NULL,
    backup_size_bytes BIGINT,
    backup_duration_seconds INTEGER,
    backup_status VARCHAR(20) NOT NULL,
    backup_path TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Grant permissions on backup log table
GRANT INSERT, SELECT ON TABLE audit.backup_log TO permiso;
GRANT SELECT ON TABLE audit.backup_log TO permiso_monitor;
GRANT USAGE, SELECT ON SEQUENCE audit.backup_log_id_seq TO permiso;

-- Production security notice
DO $$
BEGIN
    RAISE NOTICE 'Production database initialized successfully';
    RAISE NOTICE 'Remember to:';
    RAISE NOTICE '1. Change default passwords';
    RAISE NOTICE '2. Configure SSL/TLS';
    RAISE NOTICE '3. Set up regular backups';
    RAISE NOTICE '4. Configure monitoring';
    RAISE NOTICE '5. Review security settings';
END
$$;
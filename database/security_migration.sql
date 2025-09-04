-- ALX Polly Security Database Migration
-- Run this SQL script in your Supabase SQL editor to add security enhancements
-- NOTE: This is PostgreSQL syntax for Supabase, not SQL Server
-- The VS Code SQL parser may show errors, but this is correct PostgreSQL/Supabase syntax

-- Start transaction
BEGIN;

-- 1. Create user roles table for role-based access control
CREATE TABLE IF NOT EXISTS user_roles (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    role VARCHAR(50) NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin', 'super_admin')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(user_id)
);

-- 2. Add IP address tracking to votes table for anonymous vote management
ALTER TABLE votes ADD COLUMN IF NOT EXISTS ip_address INET;
ALTER TABLE votes ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW();

-- 3. Add updated_at timestamp to polls table
ALTER TABLE polls ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW();

-- 3a. Create a function to automatically set updated_at timestamp
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- 4. Enable Row Level Security (RLS) for all tables
ALTER TABLE polls ENABLE ROW LEVEL SECURITY;
ALTER TABLE votes ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_roles ENABLE ROW LEVEL SECURITY;

-- 5. Create RLS policies for polls table
DROP POLICY IF EXISTS "Users can view all polls" ON polls;
CREATE POLICY "Users can view all polls" ON polls 
    FOR SELECT USING (true);

DROP POLICY IF EXISTS "Users can create their own polls" ON polls;
CREATE POLICY "Users can create their own polls" ON polls 
    FOR INSERT WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "Users can update their own polls" ON polls;
CREATE POLICY "Users can update their own polls" ON polls 
    FOR UPDATE USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Users can delete their own polls" ON polls;
CREATE POLICY "Users can delete their own polls" ON polls 
    FOR DELETE USING (auth.uid() = user_id);

-- 6. Create RLS policies for votes table
DROP POLICY IF EXISTS "Users can view all votes" ON votes;
CREATE POLICY "Users can view all votes" ON votes 
    FOR SELECT USING (true);

DROP POLICY IF EXISTS "Users can insert votes" ON votes;
CREATE POLICY "Users can insert votes" ON votes 
    FOR INSERT WITH CHECK (true);

-- 7. Create RLS policies for user_roles table
DROP POLICY IF EXISTS "Users can view their own role" ON user_roles;
CREATE POLICY "Users can view their own role" ON user_roles 
    FOR SELECT USING (auth.uid() = user_id);

-- Note: Admin role management will be handled through separate admin functions
-- to avoid circular dependency issues

-- 8. Create indexes for performance and security
CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role ON user_roles(role);
CREATE INDEX IF NOT EXISTS idx_votes_poll_id ON votes(poll_id);
CREATE INDEX IF NOT EXISTS idx_votes_user_id ON votes(user_id) WHERE user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_votes_ip_address ON votes(ip_address) WHERE ip_address IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_votes_created_at ON votes(created_at);
CREATE INDEX IF NOT EXISTS idx_polls_user_id ON polls(user_id);
CREATE INDEX IF NOT EXISTS idx_polls_created_at ON polls(created_at);

-- 9. Create trigger to automatically update updated_at field
DROP TRIGGER IF EXISTS polls_updated_at ON polls;
CREATE TRIGGER polls_updated_at
    BEFORE UPDATE ON polls
    FOR EACH ROW
    EXECUTE FUNCTION set_updated_at();

-- 10. Create admin role management functions (to avoid circular dependency)
CREATE OR REPLACE FUNCTION is_admin(check_user_id UUID DEFAULT auth.uid())
RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1 FROM user_roles 
        WHERE user_id = check_user_id 
        AND role IN ('admin', 'super_admin')
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 11. Add admin policies for polls (admins can manage all polls)
DROP POLICY IF EXISTS "Admins can view all polls" ON polls;
CREATE POLICY "Admins can view all polls" ON polls 
    FOR SELECT USING (is_admin() OR auth.uid() = user_id);

DROP POLICY IF EXISTS "Admins can delete any poll" ON polls;
CREATE POLICY "Admins can delete any poll" ON polls 
    FOR DELETE USING (is_admin() OR auth.uid() = user_id);

-- 12. Add admin policies for user_roles
DROP POLICY IF EXISTS "Admins can manage roles" ON user_roles;
CREATE POLICY "Admins can manage roles" ON user_roles 
    FOR ALL USING (is_admin());

-- 13. Add additional constraints for data integrity
ALTER TABLE votes ADD CONSTRAINT IF NOT EXISTS chk_votes_option_index_positive 
    CHECK (option_index >= 0);

-- Add constraint to prevent future date creation
ALTER TABLE polls ADD CONSTRAINT IF NOT EXISTS chk_polls_created_at_not_future 
    CHECK (created_at <= NOW());

-- Add constraint to ensure updated_at is after created_at
ALTER TABLE polls ADD CONSTRAINT IF NOT EXISTS chk_polls_updated_at_after_created 
    CHECK (updated_at >= created_at);

-- 14. Insert default admin user (replace with your admin user ID)
-- IMPORTANT: Replace 'your-admin-user-id' with the actual UUID of your admin user
-- You can find this in the Supabase auth.users table
-- INSERT INTO user_roles (user_id, role) 
-- VALUES ('your-admin-user-id', 'admin') 
-- ON CONFLICT (user_id) DO UPDATE SET role = 'admin';

-- 12. Create a view for poll statistics (secure way to get vote counts)
CREATE OR REPLACE VIEW poll_stats AS
SELECT 
    p.id as poll_id,
    p.question,
    p.user_id,
    p.created_at,
    p.updated_at,
    COALESCE(v.total_votes, 0) as total_votes,
    COALESCE(v.vote_counts, '[]'::jsonb) as vote_counts
FROM polls p
LEFT JOIN (
    SELECT 
        poll_id,
        COUNT(*) as total_votes,
        jsonb_agg(
            jsonb_build_object('option_index', option_index, 'count', option_count)
            ORDER BY option_index
        ) as vote_counts
    FROM (
        SELECT 
            poll_id, 
            option_index, 
            COUNT(*) as option_count
        FROM votes 
        GROUP BY poll_id, option_index
    ) vote_summary
    GROUP BY poll_id
) v ON p.id = v.poll_id;

-- 13. Grant necessary permissions
GRANT SELECT ON poll_stats TO authenticated;
GRANT SELECT ON user_roles TO authenticated;

-- 14. Create function to clean up old anonymous votes (privacy)
CREATE OR REPLACE FUNCTION cleanup_old_anonymous_votes()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM votes 
    WHERE user_id IS NULL 
    AND created_at < NOW() - INTERVAL '90 days';
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 15. Create a scheduled function to run cleanup (requires pg_cron extension)
-- Uncomment the following line if you have pg_cron extension enabled
-- SELECT cron.schedule('cleanup-old-votes', '0 2 * * 0', 'SELECT cleanup_old_anonymous_votes();');

-- Security: Add vote audit logging
CREATE TABLE IF NOT EXISTS vote_audit (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    vote_id UUID NOT NULL,
    user_id UUID REFERENCES auth.users(id),
    poll_id UUID NOT NULL REFERENCES polls(id),
    ip_address INET,
    user_agent TEXT,
    action VARCHAR(20) NOT NULL, -- 'created', 'updated', 'deleted'
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create audit trigger function
CREATE OR REPLACE FUNCTION audit_vote_changes()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO vote_audit (vote_id, user_id, poll_id, ip_address, action)
        VALUES (NEW.id, NEW.user_id, NEW.poll_id, NEW.ip_address, 'created');
        RETURN NEW;
    ELSIF TG_OP = 'UPDATE' THEN
        INSERT INTO vote_audit (vote_id, user_id, poll_id, ip_address, action)
        VALUES (NEW.id, NEW.user_id, NEW.poll_id, NEW.ip_address, 'updated');
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        INSERT INTO vote_audit (vote_id, user_id, poll_id, ip_address, action)
        VALUES (OLD.id, OLD.user_id, OLD.poll_id, OLD.ip_address, 'deleted');
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Create audit trigger
CREATE TRIGGER audit_votes_trigger
    AFTER INSERT OR UPDATE OR DELETE ON votes
    FOR EACH ROW
    EXECUTE FUNCTION audit_vote_changes();

-- Security: Rate limiting table for tracking API calls
CREATE TABLE IF NOT EXISTS rate_limit_log (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id UUID REFERENCES auth.users(id),
    ip_address INET,
    action VARCHAR(50) NOT NULL,
    attempts INTEGER DEFAULT 1,
    last_attempt TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    blocked_until TIMESTAMP WITH TIME ZONE
);

-- Create index for rate limiting performance
CREATE INDEX IF NOT EXISTS idx_rate_limit_user_action ON rate_limit_log(user_id, action, last_attempt);
CREATE INDEX IF NOT EXISTS idx_rate_limit_ip_action ON rate_limit_log(ip_address, action, last_attempt);

COMMIT;

-- Verification queries (run these to verify the migration worked)
/*
-- Check if tables exist
SELECT table_name 
FROM information_schema.tables 
WHERE table_schema = 'public' 
AND table_name IN ('polls', 'votes', 'user_roles');

-- Check if RLS is enabled
SELECT schemaname, tablename, rowsecurity 
FROM pg_tables 
WHERE schemaname = 'public' 
AND tablename IN ('polls', 'votes', 'user_roles');

-- Check policies
SELECT schemaname, tablename, policyname, permissive, roles, cmd, qual
FROM pg_policies
WHERE schemaname = 'public';

-- Check indexes
SELECT indexname, tablename 
FROM pg_indexes 
WHERE schemaname = 'public' 
AND tablename IN ('polls', 'votes', 'user_roles');
*/

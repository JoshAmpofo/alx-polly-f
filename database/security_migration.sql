-- ALX Polly Security Database Migration
-- Run this SQL script in your Supabase SQL editor to add security enhancements

-- 1. Create user roles table for role-based access control
CREATE TABLE IF NOT EXISTS user_roles (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin', 'super_admin')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(user_id)
);

-- 2. Add IP address tracking to votes table for anonymous vote management
ALTER TABLE votes ADD COLUMN IF NOT EXISTS ip_address INET;
ALTER TABLE votes ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW();

-- 3. Add updated_at timestamp to polls table
ALTER TABLE polls ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW();

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

DROP POLICY IF EXISTS "Admins can manage all roles" ON user_roles;
CREATE POLICY "Admins can manage all roles" ON user_roles 
    FOR ALL USING (
        auth.uid() IN (
            SELECT user_id FROM user_roles 
            WHERE role IN ('admin', 'super_admin')
        )
    );

-- 8. Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_polls_user_id ON polls(user_id);
CREATE INDEX IF NOT EXISTS idx_polls_created_at ON polls(created_at);
CREATE INDEX IF NOT EXISTS idx_votes_poll_id ON votes(poll_id);
CREATE INDEX IF NOT EXISTS idx_votes_user_id ON votes(user_id);
CREATE INDEX IF NOT EXISTS idx_votes_ip_address ON votes(ip_address);
CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role ON user_roles(role);

-- 9. Create a function to automatically set updated_at timestamp
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- 10. Create trigger to automatically update updated_at field
DROP TRIGGER IF EXISTS polls_updated_at ON polls;
CREATE TRIGGER polls_updated_at
    BEFORE UPDATE ON polls
    FOR EACH ROW
    EXECUTE FUNCTION set_updated_at();

-- 11. Insert default admin user (replace with your admin user ID)
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

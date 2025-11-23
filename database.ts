import { Database } from 'bun:sqlite';
import path from 'path';

const dbPath = process.env.DB_PATH || path.join(process.cwd(), 'database.db');
const db = new Database(dbPath);

// Initialize Tables
db.run(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        provider TEXT,
        provider_id TEXT,
        username TEXT,
        email TEXT,
        avatar TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        tos_accepted_at DATETIME,
        UNIQUE(provider, provider_id)
    );

    CREATE TABLE IF NOT EXISTS federated_credentials (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        provider TEXT,
        provider_id TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(provider, provider_id),
        FOREIGN KEY(user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        content TEXT,
        image TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS projects (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        description TEXT,
        link TEXT,
        image TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        post_id INTEGER,
        project_id INTEGER,
        content TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(post_id) REFERENCES posts(id),
        FOREIGN KEY(project_id) REFERENCES projects(id)
    );

    CREATE TABLE IF NOT EXISTS reactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        target_type TEXT, -- 'post' or 'project' or 'comment'
        target_id INTEGER,
        type TEXT, -- 'like', 'love', etc.
        UNIQUE(user_id, target_type, target_id)
    );
`);

// Migration to federated_credentials
const hasCredentials = (db.query('SELECT count(*) as count FROM federated_credentials').get() as any).count;

if (hasCredentials === 0) {
    console.log("Migrating users to federated_credentials...");
    const users = db.query('SELECT * FROM users').all() as any[];
    
    // Map to track unique emails: email -> user_id
    const emailMap = new Map<string, number>();

    const transaction = db.transaction(() => {
        for (const user of users) {
            // Skip if no email or provider info (shouldn't happen in valid users)
            if (!user.email || !user.provider || !user.provider_id) continue;
            
            const existingUserId = emailMap.get(user.email);

            if (existingUserId) {
                // Duplicate found! Merge this user (user.id) into existingUserId
                console.log(`Merging user ${user.id} (${user.provider}) into ${existingUserId}`);
                
                try {
                    // 1. Add credential pointing to existingUserId
                    db.query('INSERT INTO federated_credentials (user_id, provider, provider_id) VALUES (?, ?, ?)').run(existingUserId, user.provider, user.provider_id);
                    
                    // 2. Move related data
                    // Update comments
                    db.query('UPDATE comments SET user_id = ? WHERE user_id = ?').run(existingUserId, user.id);
                    
                    // Update reactions - handle potential unique constraint violations
                    // (User might have liked same post on both accounts)
                    const userReactions = db.query('SELECT * FROM reactions WHERE user_id = ?').all(user.id) as any[];
                    for (const reaction of userReactions) {
                        try {
                            db.query('UPDATE reactions SET user_id = ? WHERE id = ?').run(existingUserId, reaction.id);
                        } catch (e) {
                            // If update fails due to unique constraint, it means existingUserId already reacted.
                            // So we can just delete this duplicate reaction.
                            db.query('DELETE FROM reactions WHERE id = ?').run(reaction.id);
                        }
                    }
                    
                    // 3. Delete the duplicate user
                    db.query('DELETE FROM users WHERE id = ?').run(user.id);
                    
                } catch (err) {
                    console.error(`Failed to merge user ${user.id}:`, err);
                }

            } else {
                // First time seeing this email
                emailMap.set(user.email, user.id);
                
                try {
                    // Add credential
                    db.query('INSERT INTO federated_credentials (user_id, provider, provider_id) VALUES (?, ?, ?)').run(user.id, user.provider, user.provider_id);
                } catch (err) {
                    console.error(`Failed to migrate credential for user ${user.id}:`, err);
                }
            }
        }
    });
    
    transaction();
    console.log("Migration complete.");
}

export default db;

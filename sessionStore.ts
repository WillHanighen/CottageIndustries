import session from 'express-session';
import db from './database';

export default class BunSQLiteStore extends session.Store {
    constructor() {
        super();
        // Optional: Clean up expired sessions on startup
        this.cleanup();
        // Optional: Clean up every hour
        setInterval(() => this.cleanup(), 3600000); 
    }

    cleanup() {
        try {
            db.query('DELETE FROM sessions WHERE expired < ?').run(Date.now());
        } catch (e) {
            console.error('Failed to cleanup sessions:', e);
        }
    }

    override get = (sid: string, callback: (err: any, session?: session.SessionData | null) => void) => {
        try {
            console.log('[SessionStore] GET:', sid);
            const row = db.query('SELECT sess FROM sessions WHERE sid = ? AND expired > ?').get(sid, Date.now()) as any;
            if (row) {
                const session = JSON.parse(row.sess);
                console.log('[SessionStore] FOUND:', sid);
                callback(null, session);
            } else {
                console.log('[SessionStore] NOT FOUND or EXPIRED:', sid);
                callback(null, null);
            }
        } catch (err) {
            console.error('[SessionStore] GET error:', err);
            callback(err);
        }
    }

    override set = (sid: string, session: session.SessionData, callback?: (err?: any) => void) => {
        try {
            console.log('[SessionStore] SET:', sid);
            // Default to 1 day if no maxAge
            const maxAge = session.cookie.maxAge || 86400000; 
            const expired = Date.now() + maxAge;
            const sess = JSON.stringify(session);
            db.query('INSERT OR REPLACE INTO sessions (sid, sess, expired) VALUES (?, ?, ?)').run(sid, sess, expired);
            if (callback) callback(null);
        } catch (err) {
            console.error('[SessionStore] SET error:', err);
            if (callback) callback(err);
        }
    }

    override destroy = (sid: string, callback?: (err?: any) => void) => {
        try {
            console.log('[SessionStore] DESTROY:', sid);
            db.query('DELETE FROM sessions WHERE sid = ?').run(sid);
            if (callback) callback(null);
        } catch (err) {
            console.error('[SessionStore] DESTROY error:', err);
            if (callback) callback(err);
        }
    }

    override touch = (sid: string, session: session.SessionData, callback?: (err?: any) => void) => {
        try {
             const maxAge = session.cookie.maxAge || 86400000;
             const expired = Date.now() + maxAge;
             db.query('UPDATE sessions SET expired = ? WHERE sid = ?').run(expired, sid);
             if (callback) callback(null);
        } catch (err) {
            if (callback) callback(err);
        }
    }
}


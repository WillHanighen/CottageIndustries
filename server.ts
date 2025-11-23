import express from 'express';
import session from 'express-session';
import path from 'path';
import dotenv from 'dotenv';
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { Strategy as GitHubStrategy } from 'passport-github2';
import { marked } from 'marked';
import db from './database';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL;

// Types
interface User {
    id: number;
    provider: string;
    provider_id: string;
    username: string;
    email: string;
    avatar: string;
}

// Passport Setup
passport.serializeUser((user: any, done) => {
    done(null, user.id);
});

passport.deserializeUser((id: number, done) => {
    const user = db.query('SELECT * FROM users WHERE id = ?').get(id) as User | null;
    done(null, user);
});

if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
    passport.use(new GoogleStrategy({
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: "/auth/google/callback"
    }, (accessToken, refreshToken, profile, done) => {
        const email = profile.emails?.[0]?.value || '';
        const avatar = profile.photos?.[0]?.value || '';
        let user = db.query('SELECT * FROM users WHERE provider = ? AND provider_id = ?').get('google', profile.id) as User;
        
        if (!user) {
            db.query('INSERT INTO users (provider, provider_id, username, email, avatar) VALUES (?, ?, ?, ?, ?)').run('google', profile.id, profile.displayName, email, avatar);
            user = db.query('SELECT * FROM users WHERE provider = ? AND provider_id = ?').get('google', profile.id) as User;
        }
        return done(null, user);
    }));
}

if (process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET) {
    passport.use(new GitHubStrategy({
        clientID: process.env.GITHUB_CLIENT_ID,
        clientSecret: process.env.GITHUB_CLIENT_SECRET,
        callbackURL: "/auth/github/callback"
    }, (accessToken: string, refreshToken: string, profile: any, done: any) => {
        const email = profile.emails?.[0]?.value || ''; // GitHub might not provide email publicly
        const avatar = profile.photos?.[0]?.value || '';
        let user = db.query('SELECT * FROM users WHERE provider = ? AND provider_id = ?').get('github', profile.id) as User;
        
        if (!user) {
            db.query('INSERT INTO users (provider, provider_id, username, email, avatar) VALUES (?, ?, ?, ?, ?)').run('github', profile.id, profile.username || 'GitHub User', email, avatar);
            user = db.query('SELECT * FROM users WHERE provider = ? AND provider_id = ?').get('github', profile.id) as User;
        }
        return done(null, user);
    }));
}

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));
app.set('view engine', 'ejs');

app.use(session({
    secret: process.env.SESSION_SECRET || 'secret_key',
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

// Global Middleware for Views
app.use((req, res, next) => {
    res.locals.user = req.user;
    res.locals.isAdmin = req.user && (req.user as any).email === process.env.ADMIN_EMAIL;
    next();
});

// Helpers
const isAdmin = (req: any) => {
    return req.user && req.user.email === ADMIN_EMAIL;
};

app.locals.marked = marked;

// Routes
app.get('/', (req, res) => {
    const posts = db.query('SELECT * FROM posts ORDER BY created_at DESC LIMIT 5').all();
    const projects = db.query('SELECT * FROM projects ORDER BY featured DESC, created_at DESC LIMIT 3').all();
    res.render('index', { posts, projects, user: req.user, isAdmin: isAdmin(req) });
});

app.get('/blog', (req, res) => {
    const posts = db.query('SELECT * FROM posts ORDER BY created_at DESC').all();
    res.render('blog_list', { posts, user: req.user, isAdmin: isAdmin(req) });
});

app.get('/projects', (req, res) => {
    const projects = db.query('SELECT * FROM projects ORDER BY featured DESC, created_at DESC').all();
    res.render('project_list', { projects, user: req.user, isAdmin: isAdmin(req) });
});

// Auth Routes
app.get('/login', (req, res) => {
    res.render('login', { 
        user: req.user,
        googleEnabled: !!process.env.GOOGLE_CLIENT_ID,
        githubEnabled: !!process.env.GITHUB_CLIENT_ID,
        adminEmail: ADMIN_EMAIL
    });
});

app.get('/auth/google', (req, res, next) => {
    if (!process.env.GOOGLE_CLIENT_ID) return res.status(500).send('Google Auth not configured');
    passport.authenticate('google', { scope: ['profile', 'email'] })(req, res, next);
});

app.get('/auth/google/callback', (req, res, next) => {
    if (!process.env.GOOGLE_CLIENT_ID) return res.redirect('/login');
    passport.authenticate('google', { failureRedirect: '/login' })(req, res, next);
}, (req, res) => res.redirect('/'));

app.get('/auth/github', (req, res, next) => {
    if (!process.env.GITHUB_CLIENT_ID) return res.status(500).send('GitHub Auth not configured');
    passport.authenticate('github', { scope: ['user:email'] })(req, res, next);
});

app.get('/auth/github/callback', (req, res, next) => {
    if (!process.env.GITHUB_CLIENT_ID) return res.redirect('/login');
    passport.authenticate('github', { failureRedirect: '/login' })(req, res, next);
}, (req, res) => res.redirect('/'));

app.get('/logout', (req, res) => {
    req.logout(() => {
        res.redirect('/');
    });
});

// Content Routes
app.get('/blog/:id', (req, res) => {
    const post = db.query('SELECT * FROM posts WHERE id = ?').get(req.params.id);
    if (!post) return res.status(404).send('Post not found');
    const comments = db.query('SELECT comments.*, users.username, users.avatar FROM comments JOIN users ON comments.user_id = users.id WHERE post_id = ? ORDER BY created_at DESC').all(req.params.id);
    const reactionCount = (db.query('SELECT COUNT(*) as count FROM reactions WHERE target_id = ? AND target_type = ?').get(req.params.id, 'post') as any).count;
    res.render('post', { post, comments, reactionCount, user: req.user, isAdmin: isAdmin(req) });
});

app.get('/projects/:id', (req, res) => {
    const project = db.query('SELECT * FROM projects WHERE id = ?').get(req.params.id);
    if (!project) return res.status(404).send('Project not found');
    const comments = db.query('SELECT comments.*, users.username, users.avatar FROM comments JOIN users ON comments.user_id = users.id WHERE project_id = ? ORDER BY created_at DESC').all(req.params.id);
    const reactionCount = (db.query('SELECT COUNT(*) as count FROM reactions WHERE target_id = ? AND target_type = ?').get(req.params.id, 'project') as any).count;
    res.render('project', { project, comments, reactionCount, user: req.user, isAdmin: isAdmin(req) });
});

// Comments & Reactions
app.post('/comments', (req, res) => {
    if (!req.user) return res.status(401).send('Unauthorized');
    const { post_id, project_id, content } = req.body;
    const userId = (req.user as User).id;
    
    if (post_id) {
        db.query('INSERT INTO comments (user_id, post_id, content) VALUES (?, ?, ?)').run(userId, post_id, content);
        res.redirect(`/blog/${post_id}`);
    } else if (project_id) {
        db.query('INSERT INTO comments (user_id, project_id, content) VALUES (?, ?, ?)').run(userId, project_id, content);
        res.redirect(`/projects/${project_id}`);
    }
});

app.post('/reactions', (req, res) => {
    if (!req.user) return res.status(401).send('Unauthorized');
    const { target_id, target_type } = req.body;
    const userId = (req.user as User).id;
    
    try {
        db.query('INSERT INTO reactions (user_id, target_id, target_type, type) VALUES (?, ?, ?, ?)').run(userId, target_id, target_type, 'like');
    } catch (err) {
        // Ignore duplicate reactions (unique constraint)
    }
    
    res.redirect(target_type === 'post' ? `/blog/${target_id}` : `/projects/${target_id}`);
});

// Admin Routes
app.get('/admin', (req, res) => {
    if (!isAdmin(req)) return res.redirect('/');
    const posts = db.query('SELECT * FROM posts ORDER BY created_at DESC').all();
    const projects = db.query('SELECT * FROM projects ORDER BY created_at DESC').all();
    res.render('admin', { posts, projects, user: req.user });
});

app.post('/admin/post', (req, res) => {
    if (!isAdmin(req)) return res.status(403).send('Unauthorized');
    const { title, content, image } = req.body;
    db.query('INSERT INTO posts (title, content, image) VALUES (?, ?, ?)').run(title, content, image);
    res.redirect('/admin');
});

app.post('/admin/project', (req, res) => {
    if (!isAdmin(req)) return res.status(403).send('Unauthorized');
    const { title, description, link, image, featured } = req.body;
    const isFeatured = featured === 'on' ? 1 : 0;
    db.query('INSERT INTO projects (title, description, link, image, featured) VALUES (?, ?, ?, ?, ?)').run(title, description, link, image, isFeatured);
    res.redirect('/admin');
});

// Edit Routes
app.get('/blog/:id/edit', (req, res) => {
    if (!isAdmin(req)) return res.redirect('/');
    const post = db.query('SELECT * FROM posts WHERE id = ?').get(req.params.id);
    res.render('edit', { item: post, type: 'post', user: req.user });
});

app.post('/blog/:id/edit', (req, res) => {
    if (!isAdmin(req)) return res.status(403).send('Unauthorized');
    const { title, content, image } = req.body;
    db.query('UPDATE posts SET title = ?, content = ?, image = ? WHERE id = ?').run(title, content, image, req.params.id);
    res.redirect(`/blog/${req.params.id}`);
});

app.get('/projects/:id/edit', (req, res) => {
    if (!isAdmin(req)) return res.redirect('/');
    const project = db.query('SELECT * FROM projects WHERE id = ?').get(req.params.id);
    res.render('edit', { item: project, type: 'project', user: req.user });
});

app.post('/projects/:id/edit', (req, res) => {
    if (!isAdmin(req)) return res.status(403).send('Unauthorized');
    const { title, description, link, image, featured } = req.body;
    const isFeatured = featured === 'on' ? 1 : 0;
    db.query('UPDATE projects SET title = ?, description = ?, link = ?, image = ?, featured = ? WHERE id = ?').run(title, description, link, image, isFeatured, req.params.id);
    res.redirect(`/projects/${req.params.id}`);
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});

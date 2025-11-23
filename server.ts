import express from 'express';
import session from 'express-session';
import path from 'path';
import dotenv from 'dotenv';
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { Strategy as GitHubStrategy } from 'passport-github2';
import { marked } from 'marked';
import multer from 'multer';
import sharp from 'sharp';
import { v4 as uuidv4 } from 'uuid';
import fs from 'fs';
import helmet from 'helmet';
import compression from 'compression';
import rateLimit from 'express-rate-limit';
import db from './database';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL;

// Security & Performance Middleware
if (process.env.NODE_ENV === 'production') {
    app.set('trust proxy', 1); // Trust first proxy
}

app.use(helmet({
  contentSecurityPolicy: false, // Disabled for EJS compatibility
}));
app.use(compression());

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    limit: 100, // Limit each IP to 100 requests per `window` (here, per 15 minutes)
    standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
    legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});
app.use(limiter);

// Configure Multer
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// Ensure upload directory exists
const uploadDir = path.join(__dirname, 'public/uploads/avatars');
if (!fs.existsSync(uploadDir)){
    fs.mkdirSync(uploadDir, { recursive: true });
}

// Types
interface User {
    id: number;
    provider: string;
    provider_id: string;
    username: string;
    email: string;
    avatar: string;
    tos_accepted_at?: string;
}

// Constants
const TOS_UPDATED_AT = '2023-11-23'; // Update this date when TOS/Privacy changes

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
        const providerId = profile.id;
        const provider = 'google';

        // 1. Check for existing linked account in federated_credentials
        let credential = db.query('SELECT * FROM federated_credentials WHERE provider = ? AND provider_id = ?').get(provider, providerId) as any;
        let user = null;

        if (credential) {
            // Found existing link, get user
            user = db.query('SELECT * FROM users WHERE id = ?').get(credential.user_id) as User;
        } else {
            // No direct link found. Check for existing user by email.
            if (email) {
                 user = db.query('SELECT * FROM users WHERE email = ?').get(email) as User;
            }

            if (user) {
                // User exists with this email, link this new provider to them
                try {
                     db.query('INSERT INTO federated_credentials (user_id, provider, provider_id) VALUES (?, ?, ?)').run(user.id, provider, providerId);
                } catch (err) {
                    console.error('Error linking account:', err);
                }
            } else {
                // No user found, create new user and link
                const now = new Date().toISOString();
                
                // Insert into users table
                // Note: We populate provider/provider_id in users table for backward compatibility/legacy reasons,
                // but auth lookup relies on federated_credentials now.
                db.query('INSERT INTO users (provider, provider_id, username, email, avatar, tos_accepted_at) VALUES (?, ?, ?, ?, ?, ?)').run(provider, providerId, profile.displayName, email, avatar, now);
                
                // Fetch the newly created user (using provider/provider_id since we just inserted it)
                user = db.query('SELECT * FROM users WHERE provider = ? AND provider_id = ?').get(provider, providerId) as User;
                
                // Create entry in federated_credentials
                if (user) {
                     db.query('INSERT INTO federated_credentials (user_id, provider, provider_id) VALUES (?, ?, ?)').run(user.id, provider, providerId);
                }
            }
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
        const providerId = profile.id;
        const provider = 'github';

        // 1. Check for existing linked account in federated_credentials
        let credential = db.query('SELECT * FROM federated_credentials WHERE provider = ? AND provider_id = ?').get(provider, providerId) as any;
        let user = null;

        if (credential) {
            // Found existing link, get user
            user = db.query('SELECT * FROM users WHERE id = ?').get(credential.user_id) as User;
        } else {
            // No direct link found. Check for existing user by email.
            if (email) {
                 user = db.query('SELECT * FROM users WHERE email = ?').get(email) as User;
            }

            if (user) {
                // User exists with this email, link this new provider to them
                try {
                     db.query('INSERT INTO federated_credentials (user_id, provider, provider_id) VALUES (?, ?, ?)').run(user.id, provider, providerId);
                } catch (err) {
                    console.error('Error linking account:', err);
                }
            } else {
                // No user found, create new user and link
                const now = new Date().toISOString();
                
                db.query('INSERT INTO users (provider, provider_id, username, email, avatar, tos_accepted_at) VALUES (?, ?, ?, ?, ?, ?)').run(provider, providerId, profile.username || 'GitHub User', email, avatar, now);
                
                user = db.query('SELECT * FROM users WHERE provider = ? AND provider_id = ?').get(provider, providerId) as User;
                
                if (user) {
                     db.query('INSERT INTO federated_credentials (user_id, provider, provider_id) VALUES (?, ?, ?)').run(user.id, provider, providerId);
                }
            }
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
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));
app.use(passport.initialize());
app.use(passport.session());

// Global Middleware for Views
app.use((req, res, next) => {
    res.locals.user = req.user;
    res.locals.isAdmin = req.user && (req.user as any).email === process.env.ADMIN_EMAIL;

    // Check for TOS acceptance
    if (req.user && req.path !== '/accept-tos' && req.path !== '/delete-account' && req.path !== '/logout' && !req.path.startsWith('/css') && !req.path.startsWith('/js')) {
        const user = req.user as User;
        const acceptedAt = user.tos_accepted_at ? new Date(user.tos_accepted_at) : new Date(0);
        const tosDate = new Date(TOS_UPDATED_AT);
        
        if (acceptedAt < tosDate) {
             // If it's an API request/form submission, we might want to block it or handle differently
             // For now, we'll just pass a flag to the view to show the modal
             res.locals.showTosModal = true;
        }
    }
    
    next();
});

// Helpers
const isAdmin = (req: any) => {
    return req.user && req.user.email === ADMIN_EMAIL;
};

const requireAuth = (req: express.Request, res: express.Response, next: express.NextFunction) => {
    if (!req.user) {
        return res.status(401).send('Unauthorized');
    }
    next();
};

const requireAdmin = (req: express.Request, res: express.Response, next: express.NextFunction) => {
    if (!isAdmin(req)) {
        return res.status(403).send('Unauthorized');
    }
    next();
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
app.post('/comments', requireAuth, (req, res) => {
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

app.post('/comments/:id/delete', requireAuth, (req, res) => {
    const commentId = req.params.id;
    const userId = (req.user as User).id;
    const isAdminUser = isAdmin(req);

    const comment = db.query('SELECT * FROM comments WHERE id = ?').get(commentId) as any;
    
    if (!comment) return res.status(404).send('Comment not found');

    if (isAdminUser || comment.user_id === userId) {
        db.query('DELETE FROM comments WHERE id = ?').run(commentId);
        if (comment.post_id) {
            res.redirect(`/blog/${comment.post_id}`);
        } else if (comment.project_id) {
            res.redirect(`/projects/${comment.project_id}`);
        } else {
             res.redirect('/');
        }
    } else {
        res.status(403).send('Unauthorized');
    }
});

app.post('/comments/:id/edit', requireAuth, (req, res) => {
    const commentId = req.params.id;
    const userId = (req.user as User).id;
    const { content } = req.body;

    const comment = db.query('SELECT * FROM comments WHERE id = ?').get(commentId) as any;
    
    if (!comment) return res.status(404).send('Comment not found');

    // Only owner can edit
    if (comment.user_id === userId) {
        db.query('UPDATE comments SET content = ? WHERE id = ?').run(content, commentId);
        if (comment.post_id) {
            res.redirect(`/blog/${comment.post_id}`);
        } else if (comment.project_id) {
            res.redirect(`/projects/${comment.project_id}`);
        } else {
             res.redirect('/');
        }
    } else {
        res.status(403).send('Unauthorized');
    }
});

app.post('/reactions', requireAuth, (req, res) => {
    const { target_id, target_type } = req.body;
    const userId = (req.user as User).id;
    
    try {
        db.query('INSERT INTO reactions (user_id, target_id, target_type, type) VALUES (?, ?, ?, ?)').run(userId, target_id, target_type, 'like');
    } catch (err) {
        // Ignore duplicate reactions (unique constraint)
    }
    
    res.redirect(target_type === 'post' ? `/blog/${target_id}` : `/projects/${target_id}`);
});

// Account Routes
app.get('/account', (req, res) => {
    if (!req.user) return res.redirect('/login');
    res.render('account', { user: req.user, isAdmin: isAdmin(req) });
});

app.post('/account', requireAuth, upload.single('avatar'), async (req, res) => {
    const { username } = req.body;
    const userId = (req.user as User).id;
    let avatarUrl = (req.user as User).avatar; // Default to existing avatar

    if (req.file) {
        const filename = `${uuidv4()}.png`;
        const filepath = path.join(uploadDir, filename);

        try {
            await sharp(req.file.buffer)
                .resize(512, 512, { fit: 'cover' })
                .png()
                .toFile(filepath);
            
            avatarUrl = `/uploads/avatars/${filename}`;
        } catch (err) {
            console.error('Error processing image:', err);
            // Ideally show an error message to the user
        }
    }
    
    db.query('UPDATE users SET username = ?, avatar = ? WHERE id = ?').run(username, avatarUrl, userId);
    res.redirect('/account');
});

app.post('/accept-tos', requireAuth, (req, res) => {
    const userId = (req.user as User).id;
    const now = new Date().toISOString();
    
    db.query('UPDATE users SET tos_accepted_at = ? WHERE id = ?').run(now, userId);
    
    // Update session user object
    (req.user as User).tos_accepted_at = now;
    
    res.redirect(req.header('Referer') || '/');
});

app.post('/delete-account', requireAuth, (req, res) => {
    const userId = (req.user as User).id;
    
    // Delete user data (comments, reactions, user record)
    // In a real app, you might want to soft-delete or anonymize
    db.query('DELETE FROM comments WHERE user_id = ?').run(userId);
    db.query('DELETE FROM reactions WHERE user_id = ?').run(userId);
    db.query('DELETE FROM federated_credentials WHERE user_id = ?').run(userId);
    db.query('DELETE FROM users WHERE id = ?').run(userId);
    
    req.logout(() => {
        res.redirect('/');
    });
});

// Static Pages
app.get('/tos', (req, res) => {
    res.render('tos', { user: req.user, isAdmin: isAdmin(req) });
});

app.get('/privacy', (req, res) => {
    res.render('privacy', { user: req.user, isAdmin: isAdmin(req) });
});

app.get('/about', (req, res) => {
    res.render('about', { user: req.user, isAdmin: isAdmin(req) });
});

// Admin Routes
app.get('/admin', (req, res) => {
    if (!isAdmin(req)) return res.redirect('/');
    const posts = db.query('SELECT * FROM posts ORDER BY created_at DESC').all();
    const projects = db.query('SELECT * FROM projects ORDER BY created_at DESC').all();
    res.render('admin', { posts, projects, user: req.user });
});

app.post('/admin/post', requireAdmin, (req, res) => {
    const { title, content, image } = req.body;
    db.query('INSERT INTO posts (title, content, image) VALUES (?, ?, ?)').run(title, content, image);
    res.redirect('/admin');
});

app.post('/admin/project', requireAdmin, (req, res) => {
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

app.post('/blog/:id/edit', requireAdmin, (req, res) => {
    const { title, content, image } = req.body;
    db.query('UPDATE posts SET title = ?, content = ?, image = ? WHERE id = ?').run(title, content, image, req.params.id);
    res.redirect(`/blog/${req.params.id}`);
});

app.post('/blog/:id/delete', requireAdmin, (req, res) => {
    const postId = req.params.id;
    
    // Delete related data
    db.query('DELETE FROM comments WHERE post_id = ?').run(postId);
    db.query('DELETE FROM reactions WHERE target_type = ? AND target_id = ?').run('post', postId);
    
    // Delete post
    db.query('DELETE FROM posts WHERE id = ?').run(postId);
    
    res.redirect('/blog'); // Or /admin
});

app.get('/projects/:id/edit', (req, res) => {
    if (!isAdmin(req)) return res.redirect('/');
    const project = db.query('SELECT * FROM projects WHERE id = ?').get(req.params.id);
    res.render('edit', { item: project, type: 'project', user: req.user });
});

app.post('/projects/:id/edit', requireAdmin, (req, res) => {
    const { title, description, link, image, featured } = req.body;
    const isFeatured = featured === 'on' ? 1 : 0;
    db.query('UPDATE projects SET title = ?, description = ?, link = ?, image = ?, featured = ? WHERE id = ?').run(title, description, link, image, isFeatured, req.params.id);
    res.redirect(`/projects/${req.params.id}`);
});

app.post('/projects/:id/delete', requireAdmin, (req, res) => {
    const projectId = req.params.id;
    
    // Delete related data
    db.query('DELETE FROM comments WHERE project_id = ?').run(projectId);
    db.query('DELETE FROM reactions WHERE target_type = ? AND target_id = ?').run('project', projectId);
    
    // Delete project
    db.query('DELETE FROM projects WHERE id = ?').run(projectId);
    
    res.redirect('/projects'); // Or /admin
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});

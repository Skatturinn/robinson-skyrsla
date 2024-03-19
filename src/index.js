import express from 'express';
import session from 'express-session';
import { Strategy } from 'passport-local';
import { environment } from './environment.js';
import { dirname, join } from 'path';
import { logger } from './logger.js';
import { fileURLToPath } from 'url';
import passport from './login.js';
import { comparePasswords, una } from './users.js';
import { findById, findByUsername } from './db.js';
import { handler404, handlerError } from './handlers.js';


export const env = environment(process.env, logger);

if (!env) {
	process.exit(1);
}

const path = dirname(fileURLToPath(import.meta.url));
const { port, sessionSecret } = env;


const app = express();
app.set('views', join(path, '../views'));
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));

// Passport mun verða notað með session
const sessionOptions = {
	secret: sessionSecret,
	resave: false,
	saveUninitialized: false,
};
app.use(session(sessionOptions));

/**
 * Athugar hvort username og password sé til í notandakerfi.
 * Callback tekur við villu sem fyrsta argument, annað argument er
 * - `false` ef notandi ekki til eða lykilorð vitlaust
 * - Notandahlutur ef rétt
 *
 * @param {string} username Notandanafn til að athuga
 * @param {string} password Lykilorð til að athuga
 * @param {function} done Fall sem kallað er í með niðurstöðu
 */
async function strat(username, password, done) {
	try {
		const user = await findByUsername(username);

		if (!user) {
			return done(null, false);
		}

		// Verður annað hvort notanda hlutur ef lykilorð rétt, eða false
		const result = await comparePasswords(password, user);
		return done(null, result);
	} catch (err) {
		console.error(err);
		return done(err);
	}
}

// Notum local strategy með „strattinu“ okkar til að leita að notanda
passport.use(new Strategy(strat));

passport.serializeUser((user, done) => {
	done(null, user.id);
});

// Sækir notanda út frá id
passport.deserializeUser(async (id, done) => {
	try {
		const user = await findById(id);
		done(null, user);
	} catch (err) {
		done(err);
	}
});
function login(req, res) {
	const loggedIn = req.isAuthenticated();
	if (loggedIn) {
		return res.redirect('/');
	}

	let message = '';

	// Athugum hvort einhver skilaboð séu til í session, ef svo er birtum þau
	// og hreinsum skilaboð
	if (req.session.messages && req.session.messages.length > 0) {
		message = req.session.messages.join(', ');
		req.session.messages = [];
	}

	return res.render('login', { message, title: 'Innskráning', loggedIn });
}
async function indexRoute(req, res) {
	const loggedIn = req.isAuthenticated();
	const { username, admin } = una(req)
	return res.render('index', {
		title: 'Robinson skýrsla',
		loggedIn,
		username,
		admin
	});
}
// Látum express nota passport með session
app.use(passport.initialize());
app.use(passport.session());
app.get('/', indexRoute);
app.get('/login', login);
app.post(
	'/login',

	// Þetta notar strat að ofan til að skrá notanda inn
	passport.authenticate('local', {
		failureMessage: 'Notandanafn eða lykilorð vitlaust.',
		failureRedirect: '/login',
	}),

	// Ef við komumst hingað var notandi skráður inn, senda á /admin
	(req, res) => {
		res.redirect('/');
	},
);
app.get('/logout', (req, res) => {
	// logout hendir session cookie og session
	req.logout((err) => handlerError(err, req, res, null));
	res.redirect('/');
});
app.use(express.static(join(path, './public')));
app.use(handler404);
app.use(handlerError);

app.listen(port, () => {
	console.info(`🚀 Server running at http://localhost:${port}/`);
});
import express from 'express';
import { validationResult } from 'express-validator';
import passport from 'passport';
import { catchErrors } from '../lib/catch-errors.js';
import { createUser, getGames, insertGame, listTeams } from '../lib/db.js';
import { handlerError } from '../lib/handlers.js';
import { una } from '../lib/users.js';
import {
	gameRegistrationValidationMiddleware,
	gameXssSanitizationMiddleware,
	userRegistrationValidationMiddleware,
	userSanitizationMiddleware,
	userXssSanitizationMiddleware,
	validationCheckUpdate
} from '../lib/validation.js';
import { currentdate } from '../util/date.js';

export const adminRouter = express.Router();

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

	return res.render('login', { message, title: 'Innskráning', loggedIn, time: currentdate() });
}
async function adminRoute(req, res) {
	const teams = await listTeams();
	const games = await getGames();
	// const user = req.user ?? null;
	const time = currentdate();
	const loggedIn = req.isAuthenticated();
	const { username, admin } = una(req)
	return res.render('admin', {
		title: 'Admin upplýsingar, mjög leynilegt',
		games,
		loggedIn,
		teams,
		username,
		admin,
		time
	});
}

// TODO færa á betri stað
// Hjálpar middleware sem athugar hvort notandi sé innskráður og hleypir okkur
// þá áfram, annars sendir á /login
function ensureLoggedIn(req, res, next) {
	if (req.isAuthenticated()) {
		return next();
	}

	return res.redirect('/login');
}
async function createValidationCheck(req,) {
	const validation = validationResult(req);
	const customValidations = ['nei takk']
	if (!validation.isEmpty()) {
		throw new Error(validation.errors.concat(customValidations))
	}
}
async function createAccount(req, res) {
	const { username, password, king } = req.body
	try {
		createValidationCheck(req, res)
		await createUser(username, password, king)
	} catch (err) {
		const message = err;
		return res.render('register', { message, title: 'Nýskráning', time: currentdate() })
	}
	return res.redirect('/login')
}

async function skraRouteInsert(req, res) {
	// TODO mjög hrátt allt saman, vantar validation!
	const { when, homename, homescore, awayname, awayscore } = req.body;
	const result = await insertGame(
		new Date(when),
		Number(homename),
		Number(homescore),
		Number(awayname),
		Number(awayscore));
	if (result) {
		res.redirect('/admin');
	} else {
		const { username, admin } = una();
		const time = currentdate();
		const teams = listTeams();
		const games = getGames();
		const customValidations = ['Ekki tókst að setja gögn í gagnagrunn']
		return res.render('admin', {
			username,
			time,
			title: 'Umsjónarsíða Admin - villa í innsetningu leiks',
			when,
			homename,
			homescore,
			awayname,
			awayscore,
			errors: customValidations,
			admin,
			teams,
			games
		});
	}
	return true
}

adminRouter.get('/register',
	(req, res) => res.render('register', { message: '', title: 'Nýskráning', time: currentdate() }))
adminRouter.post('/register',
	userRegistrationValidationMiddleware(),
	userXssSanitizationMiddleware(),
	userSanitizationMiddleware(),
	(catchErrors(createAccount)))
adminRouter.get('/login', login);
adminRouter.get('/admin', ensureLoggedIn, adminRoute);
adminRouter.post('/skra',
	gameRegistrationValidationMiddleware(),
	gameXssSanitizationMiddleware(),
	(catchErrors(validationCheckUpdate)),
	(catchErrors(skraRouteInsert)));

adminRouter.post(
	'/login',

	// Þetta notar strat að ofan til að skrá notanda inn
	passport.authenticate('local', {
		failureMessage: 'Notandanafn eða lykilorð vitlaust.',
		failureRedirect: '/login',
	}),

	// Ef við komumst hingað var notandi skráður inn, senda á /admin
	(req, res) => {
		res.redirect('/admin');
	},
);
adminRouter.get('/logout', (req, res) => {
	// logout hendir session cookie og session
	req.logout((err) => handlerError(err, req, res, null));
	res.redirect('/');
});

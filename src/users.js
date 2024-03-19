import bcrypt from 'bcrypt';

export async function comparePasswords(password, user) {
	const ok = await bcrypt.compare(password, user.password);

	if (ok) {
		return user;
	}

	return false;
}

export function una(req) {
	const { user: { username, admin } = {} } = req || {};
	return { username, admin };
}
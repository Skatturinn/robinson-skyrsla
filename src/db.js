import bcrypt from 'bcrypt';
import { readFile } from 'fs/promises';
import pg from 'pg';
import { environment } from './environment.js';
import { logger } from './logger.js';

const SCHEMA_FILE = './src/sql/schema.sql';
const DROP_SCHEMA_FILE = './src/sql/drop.sql';

const env = environment(process.env, logger);


if (!env?.connectionString) {
	process.exit(-1);
}

const { connectionString } = env;

const pool = new pg.Pool({ connectionString });

pool.on('error', (err) => {
	console.error('Villa í tengingu við gagnagrunn, forrit hættir', err);
	process.exit(-1);
});

/**
 * 
 * @param {String} q 
 * @param {Array<Number | String | Boolean | Date>} values 
 * @returns 
 */
export async function query(q, values = []) {
	let client;
	try {
		client = await pool.connect();
	} catch (e) {
		console.error('unable to get client from pool', e);
		return null;
	}

	try {
		const result = values.length === 0 ? await client.query(q) : await client.query(q, values);
		return result;
	} catch (e) {
		console.error('unable to query', e);
		console.info(q, values);
		return null;
	} finally {
		client.release();
	}
}

export async function getGames() {
	const q = `
    SELECT
		date,
		home_team.name AS home_name,
		home_score,
		away_team.name AS away_name,
		away_score
    FROM
    	games
    LEFT JOIN
    	teams AS home_team ON home_team.id = games.home
    LEFT JOIN
    	teams AS away_team ON away_team.id = games.away
	ORDER BY
  		date
		DESC;
  `;

	const result = await query(q);

	const games = [];
	if (result && (result.rows?.length ?? 0) > 0) {
		for (const row of result.rows) {
			const game = {
				date: row.date,
				home: {
					name: row.home_name,
					score: row.home_score,
				},
				away: {
					name: row.away_name,
					score: row.away_score,
				},
			};
			games.push(game);
		}
		return games;
	}
	return null
}
/**
 * 
 * @param {Date} gamedate 
 * @param {Number} homename 
 * @param {Number} homescore 
 * @param {Number} awayname 
 * @param {Number} awayscore 
 * @returns
 */
export async function insertGame(gamedate, homename, homescore, awayname, awayscore) {
	const q =
		'insert into games (date, home, home_score, away, away_score) values ($1, $2, $3, $4, $5);';

	const result = await query(q, [gamedate, homename, homescore, awayname, awayscore]);
	return result;
}
/**
 * 
 * @param {String} teamname 
 * @returns 
 */
export async function insertTeam(teamname) {
	const q =
		'insert into teams (name) values ($1);';

	const result = await query(q, [teamname]);
	return result
}

export async function end() {
	await pool.end();
}

export async function dropSchema(dropFile = DROP_SCHEMA_FILE) {
	const data = await readFile(dropFile);

	return query(data.toString('utf-8'));
}

export async function createSchema(schemaFile = SCHEMA_FILE) {
	const data = await readFile(schemaFile);
	return query(data.toString('utf-8'));
}

export async function listTeams() {
	const q = `
	  SELECT
		*
	  FROM
		teams
	`;

	const result = await query(q);

	if (result) {
		return result.rows;
	}

	return null;
}
export async function getTeamBySlug(slug) {
	const q = `
	  SELECT
		*
	  FROM
		teams
		WHERE 
		slug = $1
	`;

	const result = await query(q, [slug]);

	if (result) {
		return result.rows;
	}

	return null;
}


export async function findByUsername(username) {
	const q = 'SELECT * FROM users WHERE username = $1';

	try {
		const result = await query(q, [username]);

		if (result.rowCount === 1) {
			return result.rows[0];
		}
	} catch (e) {
		console.error('Gat ekki fundið notanda eftir notendnafni');
	}

	return null;
}

export async function findById(id) {
	const q = 'SELECT * FROM users WHERE id = $1';

	try {
		const result = await query(q, [id]);

		if (result.rowCount === 1) {
			return result.rows[0];
		}
	} catch (e) {
		console.error('Gat ekki fundið notanda eftir id');
	}

	return null;
}

export async function createUser(username, password, admin) {
	const user = await findByUsername(username);
	if (user) {
		throw new Error('Notendanafn frátekið/ Notandi nú þegar skráður')
	} else {
		const booleanAdmin = !!admin;
		// Geymum hashað password!
		const hashedPassword = await bcrypt.hash(password, 11);

		const q = `
		INSERT INTO
      		users (username, password, admin)
    	VALUES ($1, $2, $3)
    	RETURNING *
  		`;

		try {
			const result = await query(q, [username, hashedPassword, booleanAdmin]);
			return result.rows[0];
		} catch (e) {
			console.error('Gat ekki búið til notanda');
		}
	}

	return null;
}
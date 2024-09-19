'use strict';

(function (module) {

/*
		Welcome to the SSO OAuth plugin! If you're inspecting this code, you're probably looking to
		hook up NodeBB with your existing OAuth endpoint.

		Step 1: Fill in the "constants" section below with the requisite informaton. Either the "oauth"
				or "oauth2" section needs to be filled, depending on what you set "type" to.

		Step 2: Give it a whirl. If you see the congrats message, you're doing well so far!

		Step 3: Customise the `parseUserReturn` method to normalise your user route's data return into
				a format accepted by NodeBB. Instructions are provided there. (Line 146)

		Step 4: If all goes well, you'll be able to login/register via your OAuth endpoint credentials.
	*/

const User = require.main.require('./src/user');
const Groups = require.main.require('./src/groups');
const db = require.main.require('./src/database');
const authenticationController = require.main.require('./src/controllers/authentication');
const async = require('async');
const passport = require.main.require('passport');
const nconf = require.main.require('nconf');
const winston = require.main.require('winston');
const MongoClient = require('mongodb').MongoClient;

// Define MongoDB connection
const mongoUrl = 'mongodb://localhost:27017'; // Replace with your MongoDB URL
const dbName = 'nodebb';
let dbClient = null;


/**
	 * REMEMBER
	 *   Never save your OAuth Key/Secret or OAuth2 ID/Secret pair in code! It could be published and leaked accidentally.
	 *   Save it into your config.json file instead:
	 *
	 *   {
	 *     ...
	 *     "oauth": {
	 *       "id": "someoauthid",
	 *       "secret": "youroauthsecret"
	 *     }
	 *     ...
	 *   }
	 *
	 *   ... or use environment variables instead:
	 *
	 *   `OAUTH__ID=someoauthid OAUTH__SECRET=youroauthsecret node app.js`
	 */
const tenant = nconf.get('oauth2:tenant');

const constants = Object.freeze({
	type: 'oauth2', // Either 'oauth' or 'oauth2'
	name: 'aad', // Something unique to your OAuth provider in lowercase, like "github", or "nodebb"
	admin: {
		route: '/plugins/sso-oauth',
		icon: 'fa-brands fa-microsoft',
	},
	oauth: {
		requestTokenURL: '',  // Replace {tenant} with your tenant ID
		accessTokenURL: '',  // Replace {tenant} with your tenant ID
		userAuthorizationURL: '',
		consumerKey: nconf.get('oauth:key'), // don't change this line
		consumerSecret: nconf.get('oauth:secret'), // don't change this line
	},
	oauth2: {
		authorizationURL:  nconf.get('oauth:authorizationURL') ,
		tokenURL:  nconf.get('oauth:tokenURL') , // Replace {tenant} with your tenant ID
		clientID: nconf.get('oauth:id'), // don't change this line
		clientSecret: nconf.get('oauth:secret'), // don't change this line
	},
	scope: ['openid', 'profile', 'User.Read'],  // Scopes for Azure ADope 
	userRoute: 'https://graph.microsoft.com/v1.0/me',  // Use Microsoft Graph API to get user profile data
});

// Connect to MongoDB
async function connectMongo() {
    if (!dbClient) {
        dbClient = await MongoClient.connect(mongoUrl, { useUnifiedTopology: true });
    }
    return dbClient.db(dbName);
}

const OAuth = {};
let configOk = false;
let passportOAuth;
let opts;

if (!constants.name) {
	winston.error('[sso-oauth] Please specify a name for your OAuth provider (library.js:32)');
} else if (!constants.type || (constants.type !== 'oauth' && constants.type !== 'oauth2')) {
	winston.error('[sso-oauth] Please specify an OAuth strategy to utilise (library.js:31)');
} else if (!constants.userRoute) {
	winston.error('[sso-oauth] User Route required (library.js:31)');
} else {
	configOk = true;
}

OAuth.getStrategy = function (strategies, callback) {
	if (configOk) {
		passportOAuth = require('passport-oauth')[constants.type === 'oauth' ? 'OAuthStrategy' : 'OAuth2Strategy'];

		if (constants.type === 'oauth') {
			// OAuth options
			opts = constants.oauth;
			opts.callbackURL = `${nconf.get('url')}/auth/${constants.name}/callback`;

			passportOAuth.Strategy.prototype.userProfile = function (token, secret, params, done) {
				// If your OAuth provider requires the access token to be sent in the query  parameters
				// instead of the request headers, comment out the next line:
				this._oauth._useAuthorizationHeaderForGET = true;

				this._oauth.get(constants.userRoute, token, secret, (err, body/* , res */) => {
					if (err) {
						return done(err);
					}

					try {
						const json = JSON.parse(body);
						OAuth.parseUserReturn(json, (err, profile) => {
							if (err) return done(err);
							profile.provider = constants.name;

							done(null, profile);
						});
					} catch (e) {
						done(e);
					}
				});
			};
		} else if (constants.type === 'oauth2') {
			// OAuth 2 options
			opts = constants.oauth2;
			opts.callbackURL = `${nconf.get('url')}/auth/${constants.name}/callback`;

			passportOAuth.Strategy.prototype.userProfile = function (accessToken, done) {
				// If your OAuth provider requires the access token to be sent in the query  parameters
				// instead of the request headers, comment out the next line:
				this._oauth2._useAuthorizationHeaderForGET = true;

				this._oauth2.get(constants.userRoute, accessToken, (err, body , res ) => {
					if (err) {
						return done(err);
					}

					try {
						const json = JSON.parse(body);
						OAuth.parseUserReturn(json, (err, profile) => {
							if (err) return done(err);
							profile.provider = constants.name;

							done(null, profile);
						});
					} catch (e) {
						done(e);
					}
				});
			};
		}

		opts.passReqToCallback = true;

		passport.use(constants.name, new passportOAuth(opts, async (req, token, secret, profile, done) => {
			const user = await OAuth.login({
				oAuthid: profile.id,
				handle: profile.displayName,
				email: profile.emails[0].value,
				isAdmin: profile.isAdmin,
			});

			authenticationController.onSuccessfulLogin(req, user.uid);
			done(null, user);
		}));

		strategies.push({
			name: constants.name,
			url: `/auth/${constants.name}`,
			callbackURL: `/auth/${constants.name}/callback`,
			icon: 'fa-check-square',
			icons: {
				normal: 'fa-brands fa-google',
				square: 'fa-brands fa-google',
				svg: `<svg version="1.1" xmlns="http://www.w3.org/2000/svg" height="16px" viewBox="0 0 48 48" class="LgbsSe-Bz112c"><g><path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"></path><path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"></path><path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"></path><path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"></path><path fill="none" d="M0 0h48v48H0z"></path></g></svg>`,
			},
			labels: {
				login: '[[social:sign-in-with-google]]',
				register: '[[social:sign-up-with-google]]',
			},
			scope: (constants.scope || '').split(','),
		});

		callback(null, strategies);
	} else {
		callback(new Error('OAuth Configuration is invalid'));
	}
};

OAuth.parseUserReturn = function (data, callback) {
	// Alter this section to include whatever data is necessary
	// NodeBB *requires* the following: id, displayName, emails.
	// Everything else is optional.

	// Find out what is available by uncommenting this line:
	console.log(data);

	const profile = {};
	profile.id = data.id;
	profile.displayName = data.displayName;  // User display name
	profile.emails = [{ value: data.mail || data.userPrincipalName }];  // Use `mail` or `userPrincipalName` as fallback

	// Do you want to automatically make somebody an admin? This line might help you do that...
	// profile.isAdmin = data.isAdmin ? true : false;

	// Delete or comment out the next TWO (2) lines when you are ready to proceed
	// process.stdout.write('===\nAt this point, you\'ll need to customise the above section to id, displayName, and emails into the "profile" object.\n===');
	// return callback(new Error('Congrats! So far so good -- please see server log for details'));

	// eslint-disable-next-line
	callback(null, profile);
};

OAuth.login = async (payload) => {
    const db = await connectMongo();
    const usersCollection = db.collection('ssoUsers');

    let uid = await OAuth.getUidByOAuthid(payload.oAuthid);
    if (uid !== null) {
        // Existing User
        return {
            uid: uid,
        };
    }

    // Check for user via email fallback
    uid = await User.getUidByEmail(payload.email);
    if (!uid) {
        const { email } = payload;

        // New user
        uid = await User.create({
            username: payload.handle,
            email,
        });

        // Automatically confirm user email (if needed)
        // await User.setUserField(uid, 'email', email);
        // await UserEmail.confirmByUid(uid);

        // Save SSO user data into MongoDB
        const ssoUserData = {
            uid,
            oAuthid: payload.oAuthid,
            handle: payload.handle,
            email: payload.email,
            createdAt: new Date(),
        };

        await usersCollection.insertOne(ssoUserData);
    }

    // Save provider-specific information to the user
    await User.setUserField(uid, `${constants.name}Id`, payload.oAuthid);
    await db.setObjectField(`${constants.name}Id:uid`, payload.oAuthid, uid);

    if (payload.isAdmin) {
        await Groups.join('administrators', uid);
    }

    return {
        uid: uid,
    };
};

OAuth.getUidByOAuthid = async oAuthid => db.getObjectField(`${constants.name}Id:uid`, oAuthid);

OAuth.deleteUserData = function (data, callback) {
	async.waterfall([
		async.apply(User.getUserField, data.uid, `${constants.name}Id`),
		function (oAuthIdToDelete, next) {
			db.deleteObjectField(`${constants.name}Id:uid`, oAuthIdToDelete, next);
		},
	], (err) => {
		if (err) {
			winston.error(`[sso-oauth] Could not remove OAuthId data for uid ${data.uid}. Error: ${err}`);
			return callback(err);
		}

		callback(null, data);
	});
};


OAuth.addMenuItem = function (custom_header, callback) {
	custom_header.authentication.push({
		route: constants.admin.route,
		icon: constants.admin.icon,
		name: constants.name,
	});

	callback(null, custom_header);
};
// If this filter is not there, the deleteUserData function will fail when getting the oauthId for deletion.
OAuth.whitelistFields = function (params, callback) {
	params.whitelist.push(`${constants.name}Id`);
	callback(null, params);
};



module.exports = OAuth;
}(module));

/* globals LDAP, slug, getLdapUsername, getLdapUserUniqueID, syncUserData, addLdapUser */
/* eslint new-cap: [2, {"capIsNewExceptions": ["SHA256"]}] */

const logger = new Logger('LDAPHandler', {});

function fallbackDefaultAccountSystem(bind, username, password) {
        if (typeof username === 'string') {
                if (username.indexOf('@') === -1) {
                        username = {username};
                } else {
                        username = {email: username};
                }
        }

        logger.info('Fallback to default account system', username);

        const loginRequest = {
                user: username,
                password: {
                        digest: SHA256(password),
                        algorithm: 'sha-256'
                }
        };

        return Accounts._runLoginHandlers(bind, loginRequest);
}

function findLdapUser(username, password){
        ldap.connectSync();
        const users = ldap.searchUsersSync(username);

        if (users.length !== 1) {
                logger.info('Search returned', users.length, 'record(s) for', username);
                return;
        }
        return users[0];
}

function bind(ldapUser, username, password){
        if (ldap.authSync(ldapUser.dn, password) === true) {
                if (ldap.isUserInGroup (username)) {
                        // success
                        return true;
                } else {
                        logger.info('User not in a valid group');
                }
        } else {
                logger.info('Wrong password for', username);
        }
        return false;
}

function findUserInDB(username){
        // Look to see if user already exists

        // TODO
        // const Unique_Identifier_Field = getLdapUserUniqueID(ldapUser);
        // let user;

        // if (Unique_Identifier_Field) {
        //      userQuery = {
        //              'services.ldap.id': Unique_Identifier_Field.value
        //      };

        //      logger.info('Querying user');
        //      logger.debug('userQuery', userQuery);

        //      user = Meteor.users.findOne(userQuery);
        // }

        let userQuery = {
                username
        };

        logger.debug('userQuery', userQuery);

        user = Meteor.users.findOne(userQuery);
        return user;
}

function createLocalAccount(ldapUser, username, password){
        if (RocketChat.settings.get('LDAP_Login_Fallback') === true) {
                return addLdapUser(ldapUser, username, password);
        }
        else{
                return addLdapUser(ldapUser, username, '');
        }
}

Accounts.registerLoginHandler('ldap', function(loginRequest) {
	if (!loginRequest.ldap || !loginRequest.ldapOptions) {
			return undefined;
	}

	const self = this;

	logger.info('Init LDAP login', loginRequest.username);

	if (RocketChat.settings.get('LDAP_Enable') !== true) {
			return fallbackDefaultAccountSystem(self, loginRequest.username, loginRequest.ldapPass);
	}

	const ldap = new LDAP();

	try {
			let ldapUser;
			try {
					ldapUser = findLdapUser(loginRequest.username, loginRequest.ldapPass);
			} catch (error) {
					logger.error(error);
					if (RocketChat.settings.get('LDAP_Login_Fallback') === true) {
							// Fallback only on ldap connection errors
							user = findUserInDB(loginRequest.username)
							if(user){
									return fallbackDefaultAccountSystem(self, loginRequest.username, loginRequest.ldapPass);
							}
							else{
									return undefined; // unauthorized
							}
					}
			}

			if (ldapUser === undefined) {
					user = findUserInDB(loginRequest.username)
					if(user){
							if(user.ldap === true){
									logger.info('User exists in mongodb with ldap: true, but could not be found in ldap directory.');
									return undefined; // unauthorized
							}
							return fallbackDefaultAccountSystem(self, loginRequest.username, loginRequest.ldapPass);
					}
					else{
							// TODO: When to return Error() and when to return undefined ?!
							throw new Meteor.Error('LDAP-login-error', `LDAP Authentication failed with provided username [${ loginRequest.username }]`);
					}
			}

			if(bind(ldapUser, loginRequest.username, loginRequest.ldapPass)){
					user = findUserInDB(loginRequest.username);
					if(user){
							if(user.ldap !== true && RocketChat.settings.get('LDAP_Merge_Existing_Users') !== true){
									logger.info('User exists without "ldap: true"');
											throw new Meteor.Error('LDAP-login-error', `LDAP Authentication succeded, but there's already an existing user with provided username [${ username }] in Mongo.`);
							}
							const stampedToken = Accounts._generateStampedLoginToken();

							Meteor.users.update(user._id, {
									$push: {
											'services.resume.loginTokens': Accounts._hashStampedToken(stampedToken)
									}
							});

							syncUserData(user, ldapUser);
							if (RocketChat.settings.get('LDAP_Login_Fallback') === true) {
									Accounts.setPassword(user._id, loginRequest.ldapPass, {logout: false});
							}
							// authorized
							return {
									userId: user._id,
									token: stampedToken.token
							};
					}
					else{
							// authorized
							return createLocalAccount(ldapUser, loginRequest.username, loginRequest.ldapPass);
					}
			}
	}
	finally {
			ldap.disconnect();
	}
	// unauthorized
});


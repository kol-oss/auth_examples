const {AuthenticationClient} = require('auth0');

const DOMAIN = process.env.DOMAIN;
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const AUDIENCE = process.env.AUDIENCE;
const REALM = process.env.REALM;

const auth0 = new AuthenticationClient({
    domain: DOMAIN,
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
});

async function register(email, password) {
    try {
        return await auth0.database.signUp({
            email,
            password,
            connection: REALM,
        });
    } catch (error) {
        throw new Error(error.message);
    }
}

async function login(email, password) {
    try {
        return await auth0.oauth.passwordGrant({
            username: email,
            password,
            realm: REALM,
            audience: AUDIENCE,
            scope: 'openid profile email offline_access',
        });
    } catch (error) {
        throw new Error(error.message);
    }
}

async function logout(refreshToken) {
    try {
        await auth0.oauth.revokeRefreshToken({
            client_id: CLIENT_ID,
            client_secret: CLIENT_SECRET,
            token: refreshToken,
        });
    } catch (error) {
        throw new Error(error.message);
    }
}

async function refresh(refreshToken) {
    try {
        return await auth0.oauth.refreshTokenGrant({
            refresh_token: refreshToken,
            scope: 'openid profile email offline_access',
        });
    } catch (error) {
        throw new Error(error.message);
    }
}

module.exports = {
    register, login, logout, refresh,
};

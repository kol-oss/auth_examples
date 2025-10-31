const {AuthenticationClient} = require('auth0');

const DOMAIN = process.env.DOMAIN;
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const AUDIENCE = process.env.AUDIENCE;
const REALM = process.env.REALM;

const REDIRECT_URI = process.env.REDIRECT_URI;
const HOME_URI = process.env.HOME_URI;

const auth0 = new AuthenticationClient({
    domain: DOMAIN,
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
});

function getLoginUri() {
    const uri = new URL('/authorize', `https://${DOMAIN}`);

    uri.searchParams.set('response_type', 'code');
    uri.searchParams.set('client_id', CLIENT_ID);
    uri.searchParams.set('redirect_uri', REDIRECT_URI);
    uri.searchParams.set('scope', 'openid profile email offline_access');
    uri.searchParams.set('audience', AUDIENCE);
    uri.searchParams.set('connection', REALM);

    return uri;
}

function getLogoutUri() {
    const uri = new URL('/v2/logout', `https://${DOMAIN}`);
    uri.searchParams.set('client_id', CLIENT_ID);
    uri.searchParams.set('returnTo', HOME_URI);

    return uri;
}

async function exchangeCode(code) {
    return await auth0.oauth.authorizationCodeGrant({
        code,
        redirect_uri: REDIRECT_URI,
        audience: AUDIENCE,
        scope: 'openid profile email offline_access',
    });
}

async function refresh(refreshToken) {
    return await auth0.oauth.refreshTokenGrant({
        refresh_token: refreshToken,
    });
}

module.exports = {
    getLoginUri, getLogoutUri,
    exchangeCode, refresh,
};

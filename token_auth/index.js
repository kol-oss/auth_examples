const express = require('express');

const dotenv = require('dotenv');
dotenv.config();

const {
    refresh,
    getLoginUri,
    getLogoutUri,
    exchangeCode
} = require('./handlers');
const {authenticated, decrypt, decodeToken} = require('./auth');
const cookieParser = require('cookie-parser');

const PORT = 3000;
const REFRESH_TOKEN_COOKIE = 'refresh_token';
const HOME_URI = process.env.HOME_URI;

const app = express();
app.use(express.json());
app.use(cookieParser());

app.get('/', (req, res) => {
    res.sendFile(`${__dirname}/index.html`);
});

app.get('/api/login', async (req, res) => {
    const loginUri = getLoginUri();
    console.log('Redirecting login to ' + loginUri);

    res.redirect(loginUri.toString());
});

app.get('/api/login/callback', async (req, res) => {
    const {code} = req.query;
    console.log("Received code " + code);

    let apiResponse;
    try {
        apiResponse = await exchangeCode(code);
    } catch (error) {
        res.status(401).json({message: 'Exchange failed: ' + error.message});
        return;
    }

    const {access_token, refresh_token, expires_in, id_token} = apiResponse.data;
    console.log("Exchanged code for token " + access_token);

    const url = new URL(HOME_URI);
    url.searchParams.set('access_token', access_token);
    url.searchParams.set('expires_in', JSON.stringify(expires_in));

    if (id_token) {
        const user = await decodeToken(id_token);
        url.searchParams.set('username', JSON.stringify(user.nickname));
    }

    res.cookie(REFRESH_TOKEN_COOKIE, refresh_token, {httpOnly: true, secure: true});
    res.redirect(url.toString());
});

app.get('/api/logout', async (req, res) => {
    const logoutUri = getLogoutUri();
    console.log('Redirecting logout to ' + logoutUri);

    res.clearCookie(REFRESH_TOKEN_COOKIE, {httpOnly: true, secure: true});
    res.redirect(logoutUri.toString());
});

app.post('/api/refresh', async (req, res) => {
    const {refreshToken} = req.body;

    let apiResponse;
    try {
        apiResponse = refresh(refreshToken);
    } catch (error) {
        res.status(401).json({message: 'Refresh failed: ' + error.message});
        return;
    }

    const {access_token, refresh_token, expires_in} = apiResponse.data;
    if (!access_token || !refresh_token) {
        return res.status(401).send({message: 'accessTokenFromParams or refresh_token value after refreshing is empty'});
    }

    res.cookie(REFRESH_TOKEN_COOKIE, refresh_token, {httpOnly: true, secure: true});
    return res.status(200).send({access_token, expires_in});
});

app.get('/api/validate', decrypt(), authenticated(), async (req, res) => {
    res.status(200).json({message: 'Authenticated successfully'});
});

app.listen(PORT, () => {
    console.log(`Example app listening on port ${PORT}`);
});

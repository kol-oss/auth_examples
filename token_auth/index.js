const express = require('express');

const dotenv = require('dotenv');
dotenv.config();

const {register, login, refresh, logout, getCurrentUser} = require('./handlers');
const {authenticated, decrypt} = require('./auth');
const cookieParser = require('cookie-parser');

const PORT = 3000;
const REFRESH_TOKEN_COOKIE = 'refresh_token';

const app = express();
app.use(express.json());
app.use(cookieParser());

app.get('/', (req, res) => {
    if (req.user) {
        return res.json({
            username: req.user.username,
            logout: 'http://localhost:3000/logout'
        });
    }

    res.sendFile(`${__dirname}/index.html`);
});

app.post('/logout', decrypt(), authenticated(), async (req, res) => {
    const refreshToken = req.cookies?.refresh_token;
    if (!refreshToken) {
        return res.status(401).send('refresh_token cookie is empty');
    }

    await logout(refreshToken);
    res.clearCookie(REFRESH_TOKEN_COOKIE, {httpOnly: true, secure: true});

    res.status(204).end();
});

app.post('/api/register', async (req, res) => {
    const {login: email, password} = req.body;
    if (!email || !password) {
        return res.status(400).send('Invalid email or password');
    }

    const apiResponse = await register(email, password);
    return res.status(200).send(apiResponse.data);
});

app.post('/api/login', async (req, res) => {
    const {login: email, password} = req.body;
    if (!email || !password) {
        return res.status(400).send('Invalid email or password');
    }

    let apiResponse;
    try {
        apiResponse = await login(email, password);
    } catch (err) {
        return res.status(401).send(err.message);
    }

    const {access_token, refresh_token, expires_in} = apiResponse.data;
    if (!access_token || !refresh_token) {
        return res.status(401).send('access_token or refresh_token value is empty');
    }

    res.cookie(REFRESH_TOKEN_COOKIE, refresh_token, {httpOnly: true, secure: true});
    return res.status(200).send({access_token, expires_in});
});

app.post('/api/refresh', async (req, res) => {
    const oldRefreshToken = req.cookies?.refresh_token;
    if (!oldRefreshToken) {
        return res.status(401).send('refresh_token cookie is empty');
    }

    const apiResponse = await refresh(oldRefreshToken);
    const {access_token, refresh_token, expires_in} = apiResponse.data;

    if (!access_token || !refresh_token) {
        return res.status(401).send('access_token or refresh_token value after refreshing is empty');
    }

    res.cookie(REFRESH_TOKEN_COOKIE, refresh_token, {httpOnly: true, secure: true});
    return res.status(200).send({access_token, expires_in});
});

app.get('/api/me', decrypt(), authenticated(), async (req, res) => {
    const authHeader = req.headers.authorization;
    const accessToken = authHeader.split(' ')[1];

    try {
        const userInfo = await getCurrentUser(accessToken);
        return res.status(200).json(userInfo);
    } catch (err) {
        console.log(err);

        return res.status(401).send(err.message);
    }
});

app.listen(PORT, () => {
    console.log(`Example app listening on port ${PORT}`);
});

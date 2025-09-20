const express = require('express');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

dotenv.config();

const PORT = 3000;
const TOKEN_HEADER_KEY = 'Authorization';

const BCRYPT_SALT_ROUNDS = parseInt(process.env.BCRYPT_SALT_ROUNDS) || 10;
const JWT_SECRET_KEY = process.env.JWT_SECRET_KEY;
const JWT_EXPIRATION_TIME = process.env.JWT_EXPIRATION_TIME || '10m';

const USERS = [
    {
        login: 'Login',
        password: bcrypt.hashSync('Password', BCRYPT_SALT_ROUNDS),
        username: 'Username',
    },
    {
        login: 'Login1',
        password: bcrypt.hashSync('Password1', BCRYPT_SALT_ROUNDS),
        username: 'Username1',
    }
];

const app = express();
app.use(express.json());

app.use((req, _, next) => {
    const token = req.header(TOKEN_HEADER_KEY);
    if (!token) return next();

    req.user = jwt.verify(token, JWT_SECRET_KEY);
    next();
});

app.get('/', (req, res) => {
    if (req.user) {
        return res.json({
            username: req.user.username,
            logout: 'http://localhost:3000/logout'
        });
    }

    res.sendFile(`${__dirname}/index.html`);
});

app.get('/logout', (_, res) => {
    res.redirect('/');
});

app.post('/api/login', async (req, res) => {
    const {login, password} = req.body;
    const user = USERS.find(user => user.login === login);

    if (user) {
        const match = await bcrypt.compare(password, user.password);

        if (match) {
            const payload = {login: user.login, username: user.username};
            const token = jwt.sign(payload, JWT_SECRET_KEY, {expiresIn: JWT_EXPIRATION_TIME});

            return res.json({token});
        }
    }

    res.status(401).send();
});

app.listen(PORT, () => {
    console.log(`Example app listening on port ${PORT}`);
});
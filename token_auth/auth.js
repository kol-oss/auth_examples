const {auth} = require('express-oauth2-jwt-bearer');
const {readFileSync} = require('node:fs');

const DOMAIN = process.env.DOMAIN;
const AUDIENCE = process.env.AUDIENCE;

const TOKEN_PREFIX = 'Bearer ';
const PRIVATE_KEY_PEM = readFileSync('./keys/key.pem', 'utf8');
const ALGORITHM = 'RSA-OAEP-512';

function authenticated() {
    return auth({
        audience: AUDIENCE,
        issuerBaseURL: `https://${DOMAIN}/`,
    });
}

async function decryptToken(encryptedToken) {
    const {importPKCS8, compactDecrypt} = await import('jose');

    const privateKey = await importPKCS8(PRIVATE_KEY_PEM, ALGORITHM);
    const {plaintext} = await compactDecrypt(encryptedToken, privateKey);

    return new TextDecoder().decode(plaintext);
}

function decrypt() {
    return async (req, res, next) => {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith(TOKEN_PREFIX)) {
            return res.status(401).send('Provided token format is not valid');
        }

        try {
            const encryptedToken = authHeader.split(' ')[1];

            const decrypted = await decryptToken(encryptedToken);
            req.headers.authorization = TOKEN_PREFIX + decrypted;

            next();
        } catch (error) {
            console.error('Token can not be decrypted: ', error);
            return res.status(401).send('Provided encrypted token is not valid');
        }
    };
}

async function decodeToken(token) {
    const {decodeJwt} = await import('jose');
    return decodeJwt(token);
}

module.exports = {authenticated, decrypt, decodeToken};

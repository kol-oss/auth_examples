const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

const DOMAIN = process.env.DOMAIN;
const AUDIENCE = process.env.AUDIENCE;

const client = jwksClient({
    jwksUri: `https://${DOMAIN}/.well-known/jwks.json`,
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 5
});

function getKey(header, callback) {
    client.getSigningKey(header.kid, (err, key) => {
        if (err) return callback(err);
        const signingKey = key.publicKey || key.rsaPublicKey;
        callback(null, signingKey);
    });
}

function authenticated(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({message: 'No token provided'});
    }

    jwt.verify(token, getKey, {
        audience: AUDIENCE,
        issuer: `https://${DOMAIN}/`,
        algorithms: ['RS256']
    }, (err, decoded) => {
        if (err) {
            return res.status(401).json({message: 'Invalid token', error: err.message});
        }

        req.user = decoded;
        next();
    });
}

module.exports = {authenticated};

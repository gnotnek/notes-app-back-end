const Jwt = require('@hapi/jwt');
const InvariantError = require('../exceptions/InvariantError');

const TokenManager = {
    generateAccesToken: (payload) => Jwt.token.generate(payload, process.env.ACCESS_TOKEN_KEY),
    generateRefreshToken: (payload) => Jwt.token.generate(payload, process.env.REFRESH_TOKEN_KEY),
    verifyAccessToken: (token) => {
        try {
            const artifacts = Jwt.token.decode(token);
            Jwt.token.verifySignature(artifacts, process.env.ACCESS_TOKEN_KEY);
            const { payload } = artifacts.decoded;
            return payload;
        } catch (error) {
            throw new InvariantError('Access token tidak valid');
        }
    }
};

module.exports = TokenManager;

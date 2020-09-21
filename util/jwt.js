const nJwt = require('njwt')
const secret = process.env.JWT_SECRET

const create = (claims) => {

    // set expiration date to 30 days
    const expires = new Date().getTime() + 2592000000
    const jwt_token = nJwt.create(claims, secret)
    jwt_token.setExpiration(expires)

    return jwt_token.compact()
}

const verify = (token) => {
    return new Promise((resolve, reject) => {
        nJwt.verify(token, secret, (err, verifiedJwt) => {
            if (err) {
                reject(err)
            } else {
                resolve(verifiedJwt)
            }
        })
    })
}

module.exports = {
    create,
    verify
}

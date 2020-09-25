const JWT = require('../util/jwt')

const getUsers = (req, res, connection) => {

    // validate parameters
    const { jwt, security } = req.body

    if (typeof jwt === 'undefined' || typeof security === 'undefined') {
        res.status(400).json({ 'error':'Missing parameters.'})
    } else {

        // verify token
        JWT.verify(jwt)
        .then((jwtData) => {
            const user = jwtData.body

            // verify security
            if (user.security < 2) {
                res.status(403).json({'error':'Forbidden.'})
            } else {

                if (security === 'all') {
                    connection.query('SELECT id, username, email, security FROM users ORDER BY username, security', (err, results) => {
                        if (err) {
                            console.error(err)
                            res.status(500).json({'error':'Server error.'})
                        } else {
                            res.status(200).json(results)
                        }
                    })
                } else {
                    connection.execute('SELECT id, username, email, security FROM users WHERE security = ? ORDER BY username, security', [security], (err, results) => {
                        if (err) {
                            console.error(err)
                            res.status(500).json({'error':'Server error.'})
                        } else {
                            res.status(200).json(results)
                        }
                    })
                }
            }
        })
        .catch(err => {
            res.status(400).json({'error':'Invalid token.'})
        })
    }
}

module.exports = {
    getUsers
}

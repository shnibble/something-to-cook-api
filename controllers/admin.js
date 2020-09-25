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
                    connection.query('SELECT id, username, email, security FROM users ORDER BY security DESC, username', (err, results) => {
                        if (err) {
                            console.error(err)
                            res.status(500).json({'error':'Server error.'})
                        } else {
                            res.status(200).json(results)
                        }
                    })
                } else {
                    connection.execute('SELECT id, username, email, security FROM users WHERE security = ? ORDER BY security DESC, username', [security], (err, results) => {
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

const promoteUser = (req, res, connection) => {

    // validate parameters
    const { jwt, user_id } = req.body

    if (typeof jwt === 'undefined' || typeof user_id === 'undefined') {
        res.status(400).json({ 'error':'Missing parameters.'})
    } else {

        // verify token
        JWT.verify(jwt)
        .then((jwtData) => {
            const user = jwtData.body
                
            // verify user exists
            connection.execute('SELECT security FROM users WHERE id = ?', [user_id], (err, results) => {
                if (err) {
                    console.error(err)
                    res.status(500).json({'error':'Server error.'})
                } else if (!results.length) {
                    res.status(400).json({'error':'Invalid user.'})
                } else {

                    // verify security
                    const current_user_security = results[0].security
                    const new_user_security = current_user_security + 1
                    if (user.security < 2 || user.security <= current_user_security) {
                        res.status(403).json({'error':'Forbidden.'})
                    } else {

                        // promote user
                        connection.execute('UPDATE users SET security = ? WHERE id = ?', [new_user_security, user_id], (err) => {
                            if (err) {
                                console.error(err)
                                res.status(500).json({'error':'Server error.'})
                            } else {
                                res.status(200).send('Success.')
                            }
                        })
                    }
                }
            })
        })
        .catch(err => {
            res.status(400).json({'error':'Invalid token.'})
        })
    }
}

const demoteUser = (req, res, connection) => {

    // validate parameters
    const { jwt, user_id } = req.body

    if (typeof jwt === 'undefined' || typeof user_id === 'undefined') {
        res.status(400).json({ 'error':'Missing parameters.'})
    } else {

        // verify token
        JWT.verify(jwt)
        .then((jwtData) => {
            const user = jwtData.body
                
            // verify user exists
            connection.execute('SELECT security FROM users WHERE id = ?', [user_id], (err, results) => {
                if (err) {
                    console.error(err)
                    res.status(500).json({'error':'Server error.'})
                } else if (!results.length) {
                    res.status(400).json({'error':'Invalid user.'})
                } else {

                    // verify security
                    const current_user_security = results[0].security
                    const new_user_security = current_user_security - 1

                    if (new_user_security === 0 || user.security < 2 || user.security <= current_user_security) {
                        res.status(403).json({'error':'Forbidden.'})
                    } else {

                        // demote user
                        connection.execute('UPDATE users SET security = ? WHERE id = ?', [new_user_security, user_id], (err) => {
                            if (err) {
                                console.error(err)
                                res.status(500).json({'error':'Server error.'})
                            } else {
                                res.status(200).send('Success.')
                            }
                        })
                    }
                }
            })
        })
        .catch(err => {
            res.status(400).json({'error':'Invalid token.'})
        })
    }
}

module.exports = {
    getUsers,
    promoteUser,
    demoteUser
}

const bcrypt = require('bcryptjs')
const nodemailer = require('nodemailer')
const JWT = require('../util/jwt')

const validateEmail = (email) => {
    const re = /\S+@\S+\.\S+/
    return re.test(email)
}

const register = (req, res, connection) => {

    // validate parameters
    const { email, username, password, repeat_password } = req.body

    if (typeof email === 'undefined' || typeof username === 'undefined' || typeof password === 'undefined' || typeof repeat_password === 'undefined') {
        res.status(400).send('Invalid user registration parameters.')
    } else {

        // validate email format
        if (!validateEmail(email)) {
            res.status(400).send('Invalid email format.')
        } else {

            // validate passwords match
            if (password !== repeat_password) {
                res.status(400).send('Passwords do not match.')
            } else {

                // validate unique email
                connection.execute('SELECT * FROM users WHERE email = ?', [email], (err, results, fields) => {
                    if (err) {
                        res.status(500).send('Server error.')
                    } else if (results.length) {
                        res.status(400).send('Email already used.')
                    } else {

                        // validate unique username
                        connection.execute('SELECT * FROM users WHERE username = ?', [username], (err, results, fields) => {
                            if (err) {
                                res.status(500).send('Server error.')
                            } else if (results.length) {
                                res.status(400).send('Username already exists.')
                            } else {

                                // hash password
                                const hashed_password = bcrypt.hashSync(password, 10)

                                // register user
                                connection.execute('INSERT INTO users (email, username, password) VALUES (?, ?, ?)', [email, username, hashed_password], (err, result, fields) => {
                                    if (err) {
                                        res.status(500).send('Server error.')
                                    } else {
                                        res.status(200).send('Success')
                                    }
                                })
                            }
                        })
                    }
                })
            }
        }
    }
}

const login = (req, res, connection) => {
    
    // validate parameters
    const { email, password } = req.body

    if (typeof email === 'undefined' || typeof password === 'undefined') {
        res.status(400).send('Invalid user login parameters.')
    } else {

        // get user
        connection.execute('SELECT username, email, password, security FROM users WHERE email = ?', [email], (err, results, fields) => {
            if (err) {
                res.status(500).send('Server error.')
            } else if (!results.length) {
                res.status(400).send('Invalid email or password.')
            } else {
                const user = results[0]

                // check password
                if (!bcrypt.compareSync(password, user.password)) {
                    res.status(400).send('Invalid email or password.')
                } else {
                    
                    // create jwt
                    const claims = {
                        username: user.username,
                        email: user.email,
                        security: user.security
                    }
                    const jwt = JWT.create(claims)

                    // return jwt
                    res.status(200).json(jwt)
                }
            }
        })
    }
}

const reset = (req, res) => {
    const { email } = req.body

    if (typeof email === 'undefined') {
        res.status(400).send('Invalid parameters.')
    } else {

        // validate email format
        if (!validateEmail(email)) {
            res.status(400).send('Invalid email format.')
        } else {

            let transporter = nodemailer.createTransport({
                host: 'localhost',
                port: 465,
                secure: true,
                auth: {
                    user: process.env.EMAIL_USER,
                    pass: process.env.EMAIL_PASSWORD
                }
            })

            transporter.sendMail({
                
            from: 'noreploy@somethingtocook-api.com',
            to: email,
            subject: 'Password Reset',
            text: 'Your password was requested to be reset... (more to come in future commits).'

            }, (error, info) => {
                if (error) {
                    return console.log(error);
                }
                console.log('Message %s sent: %s', info.messageId, info.response);
            })
        }
    }
}


module.exports = {
    register,
    login,
    reset
}

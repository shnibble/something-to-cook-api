const bcrypt = require('bcryptjs')
const nodemailer = require('nodemailer')
const axios = require('axios')
const uniqueString = require('unique-string')
const JWT = require('../util/jwt')

const validateEmail = (email) => {
    const re = /\S+@\S+\.\S+/
    return re.test(email)
}

const register = (req, res, connection) => {

    // validate parameters
    const { email, username, password, repeat_password, recaptcha_response } = req.body

    console.log('Receiving new user registration:', email)

    if (typeof email === 'undefined' || typeof username === 'undefined' || typeof password === 'undefined' || typeof repeat_password === 'undefined' || typeof recaptcha_response === 'undefined') {
        console.log('Registration rejected: missing parameters.')
        res.status(400).json({ 'error':'Missing parameters.'})
    } else {

        // validate email format
        if (!validateEmail(email)) {
            console.log('Registration rejected: invalid email format.')
            res.status(400).json({'error':'Invalid email format.'})
        } else {

            // validate passwords match
            if (password !== repeat_password) {
                console.log('Registration rejected: passwords do not match.')
                res.status(400).json({'error':'Passwords do not match.'})
            } else {

                // validate unique email
                connection.execute('SELECT * FROM users WHERE email = ?', [email], (err, results, fields) => {
                    if (err) {
                        console.log('Registration rejected: server error.')
                        console.error(err)
                        res.status(500).json({'error':'Server error.'})
                    } else if (results.length) {
                        console.log('Registration rejected: email already in use.')
                        res.status(400).json({'error':'Email already in use.'})
                    } else {

                        // validate unique username
                        connection.execute('SELECT * FROM users WHERE username = ?', [username], (err, results, fields) => {
                            if (err) {
                                console.log('Registration rejected: server error.')
                                console.error(err)
                                res.status(500).json({'error':'Server error.'})
                            } else if (results.length) {
                                console.log('Registration rejected: email already in use.')
                                res.status(400).json({'error':'Username already exists.'})
                            } else {

                                // verify google recaptcha
                                axios.get('https://www.google.com/recaptcha/api/siteverify', {
                                    params: {
                                        secret: process.env.GOOGLE_RECAPTCHA_SECRET || null,
                                        response: recaptcha_response,
                                        remoteip: req.connection.remoteAddress
                                    }
                                }).then(response => {

                                    if (typeof response.data.success === 'undefined' || !response.data.success) {
                                        res.status(400).json({'error':'Recaptcha failed.'})
                                    } else if (response.data.score < 0.1) {
                                        res.status(400).json({'error':'You appear to be a bot.'})
                                    } else {

                                        // hash password
                                        const hashed_password = bcrypt.hashSync(password, 10)

                                        // register user
                                        connection.execute('INSERT INTO users (email, username, password) VALUES (?, ?, ?)', [email, username, hashed_password], (err, result, fields) => {
                                            if (err) {
                                                console.log('Registration rejected: server error.')
                                                console.error(err)
                                                res.status(500).json({'error':'Server error.'})
                                            } else {
                                                console.log('Registration successful.')
                                                res.status(200).send('Success.')
                                            }
                                        })
                                    }
                                }).catch(err => {
                                    console.error(err)
                                    res.status(500).json({'error':'Server error 1.'})
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

    console.log('Receiving user login:', email)

    if (typeof email === 'undefined' || typeof password === 'undefined') {
        console.log('Login rejected: invalid parameters.')
        res.status(400).json({'error':'Invalid user login parameters.'})
    } else {

        // get user
        connection.execute('SELECT id, username, email, password, security, banned FROM users WHERE email = ?', [email], (err, results, fields) => {
            if (err) {
                console.log('Login rejected: server error.')
                console.error(err)
                res.status(500).json({'error':'Server error.'})
            } else if (!results.length) {
                console.log('Login rejected: invalid email.')
                res.status(400).json({'error':'Invalid email or password.'})
            } else if (results[0].banned) {
                res.status(403).json({'error':'Banned account.'})            
            } else {
                const user = results[0]

                // check password
                if (!bcrypt.compareSync(password, user.password)) {
                    console.log('Login rejected: incorrect password.')
                    res.status(400).json({'error':'Invalid email or password.'})
                } else {
                    
                    // create jwt
                    const claims = {
                        id: user.id,
                        username: user.username,
                        email: user.email,
                        security: user.security
                    }
                    const jwt = JWT.create(claims)

                    // return jwt
                    console.log('Login successful.')
                    res.status(200).json({'token':jwt})
                }
            }
        })
    }
}

const authenticate = (req, res) => {

    // validate parameters
    const { jwt } = req.body

    console.log('Receiving user authentication request')

    if (typeof jwt === 'undefined') {
        console.log('Authentication rejected: invalid parameters.')
        res.status(400).json({'error':'Invalid parameters.'})
    } else {

        // verify jwt
        JWT.verify(jwt)
        .then(() => {
            console.log('Authentication successful.')
            res.status(200).send('Success.')
        })
        .catch(err => {
            console.log('Authentication rejected: invalid token.')
            res.status(400).json({'error':'Invalid token.'})
        })
    }
}

const reset = (req, res, connection) => {
    
    // validate parameters
    const { email } = req.body

    console.log('Receiving user reset request:', email)

    if (typeof email === 'undefined') {
        console.log('Reset rejected: invalid parameters.')
        res.status(400).json({'error':'Invalid parameters.'})
    } else {

        // validate email format
        if (!validateEmail(email)) {
            console.log('Reset rejected: invalid email format.')
            res.status(400).json({'error':'Invalid email format.'})
        } else {

            // generate reset link
            const reset_string = uniqueString()
            const reset_link = `https://somethingtocook.com/account/reset/${reset_string}`

            // get user
            connection.execute('SELECT id FROM users WHERE email = ?', [email], (err, results, fields) => {
                if (err) {
                    console.log('Reset rejected: server error.')
                    console.error(err)
                    res.status(500).json({'error':'Server error.'})
                } else if (!results.length) {

                    // if email not found then return success anyway for security purposes
                    console.log('Reset rejected: email not found.')
                    res.status(200).send('Success.')
                } else {

                    // store reset link
                    const user_id = results[0].id
                    connection.execute('UPDATE users SET reset_link = ? WHERE id = ?', [reset_string, user_id], (err, results, fields) => {
                        if (err) {
                            console.log('Reset rejected: server error.')
                            console.error(err)
                            res.status(500).json({'error':'Server error.'})
                        } else {

                            // setup transporter
                            const transporter = nodemailer.createTransport({
                                service: 'gmail',
                                auth: {
                                    user: process.env.EMAIL_USER,
                                    pass: process.env.EMAIL_PASSWORD
                                },
                                tls: {
                                    rejectUnauthorized: false
                                }
                            })

                            // setup message
                            const message = {
                                from: 'noreplysomethingtocook@gmail.com',
                                to: email,
                                subject: 'Password Reset',
                                html: `
                                    <p>Please follow the below link to reset your password with somethingtocook.com:</p>
                                    <div stlye='padding: 15px; text-align: center;'>
                                        <a href='${reset_link}' target='_BLANK'>${reset_link}</a>
                                    </div>
                                    <p>If you did not request a password reset please take steps to secure your account as someone else is likely trying to crack it!</p>
                                    `
                            }

                            // send email
                            transporter.sendMail(message, (error, info) => {
                                if (error) {
                                    res.status(500).json({'error':'Server error.'})
                                    console.log('Reset rejected: server error.')
                                    return console.error(error)
                                }
                                console.log('Reset request accepted, email link sent.');
                                res.status(200).send('Success.')
                            })
                        }
                    })
                }
            })
        }
    }
}

const updatePassword = (req, res, connection) => {

    // validate parameters
    const { email, reset_link, new_password, repeat_new_password } = req.body 

    console.log('Receiving user password update request:', email)

    if (typeof email === 'undefined' || typeof reset_link === 'undefined' || typeof new_password === 'undefined' || typeof repeat_new_password === 'undefined') {
        res.status(400).json({'error':'Invalid parameters.'})
        console.log('Update rejected: invalid parameters.')
    } else {

        // validate reset link
        connection.execute('SELECT id FROM users WHERE email = ? AND reset_link = ?', [email, reset_link], (err, results, fields) => {
            if (err) {
                console.log('Update rejected: server error.')
                console.error(err)
                res.status(500).json({'error':'Server error.'})
            } else if (!results.length) {
                console.log('Update rejected: invalid email or reset link.')
                res.status(400).json({'error':'Invalid email or link.'})
            } else {
                const user_id = results[0].id

                // validate passwords match
                if (new_password !== repeat_new_password) {
                    console.log('Update rejected: passwords do not match.')
                    res.status(400).json({'error':'Passwords do not match.'})
                } else {

                    // hash password
                    const hashed_password = bcrypt.hashSync(new_password, 10)

                    // update user
                    connection.execute('UPDATE users SET password = ?, reset_link = NULL WHERE id = ?', [hashed_password, user_id], (err, result, fields) => {
                        if (err) {
                            console.log('Update rejected: server error.')
                            console.error(err)
                            res.status(500).json({'error':'Server error.'})
                        } else {
                            console.log('Update successful.')
                            res.status(200).send('Success.')
                        }
                    })
                }
            }
        })
    }
}


module.exports = {
    register,
    login,
    authenticate,
    reset,
    updatePassword
}

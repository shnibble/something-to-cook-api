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

            // verify security
            connection.execute('SELECT security FROM users WHERE id = ?', [jwtData.body.id], (err, results) => {
                if (err) {
                    console.error(err)
                    res.status(500).json({'error':'Server error.'})
                } else if (!results.length) {
                    res.status(400).json({ 'error':'User does not exist.'})
                } else if (results[0].security < 2) {
                    res.status(403).json({'error':'Forbidden.'})
                } else {

                    if (security === 'all') {
                        connection.query('SELECT id, username, email, security, banned, ban_reason FROM users ORDER BY security DESC, username', (err, results) => {
                            if (err) {
                                console.error(err)
                                res.status(500).json({'error':'Server error.'})
                            } else {
                                res.status(200).json(results)
                            }
                        })
                    } else {
                        connection.execute('SELECT id, username, email, security, banned, ban_reason FROM users WHERE security = ? ORDER BY security DESC, username', [security], (err, results) => {
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
                            
            // verify user exists
            connection.execute('SELECT security, banned FROM users WHERE id = ?', [user_id], (err, results) => {
                if (err) {
                    console.error(err)
                    res.status(500).json({'error':'Server error.'})
                } else if (!results.length) {
                    res.status(400).json({'error':'Invalid user.'})
                } else if (results[0].banned) {
                    res.status(400).json({'error':'User is banned.'})
                } else {

                    // verify security
                    const current_user_security = results[0].security
                    const new_user_security = current_user_security + 1

                    connection.execute('SELECT security FROM users WHERE id = ?', [jwtData.body.id], (err, results) => {
                        if (err) {
                            console.error(err)
                            res.status(500).json({'error':'Server error.'})
                        } else if (!results.length) {
                            res.status(400).json({ 'error':'User does not exist.'})
                        } else if (results[0].security < 2 || results[0].security <= current_user_security) {
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
                    })
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

                    connection.execute('SELECT security FROM users WHERE id = ?', [jwtData.body.id], (err, results) => {
                        if (err) {
                            console.error(err)
                            res.status(500).json({'error':'Server error.'})
                        } else if (!results.length) {
                            res.status(400).json({ 'error':'User does not exist.'})
                        } else if (new_user_security === -1 || results[0].security < 2 || results[0].security <= current_user_security) {
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
                    })
                }
            })
        })
        .catch(err => {
            res.status(400).json({'error':'Invalid token.'})
        })
    }
}

const banUser = (req, res, connection) => {

    // validate parameters
    const { jwt, user_id, ban_reason } = req.body

    if (typeof jwt === 'undefined' || typeof user_id === 'undefined' || typeof ban_reason === 'undefined') {
        res.status(400).json({ 'error':'Missing parameters.'})
    } else {
        
        // verify token
        JWT.verify(jwt)
        .then((jwtData) => {
                
            // verify user exists
            connection.execute('SELECT security, banned FROM users WHERE id = ?', [user_id], (err, results) => {
                if (err) {
                    console.error(err)
                    res.status(500).json({'error':'Server error.'})
                } else if (!results.length) {
                    res.status(400).json({'error':'Invalid user.'})
                } else if (results[0].banned) {
                    res.status(400).json({'error':'User already banned.'})
                } else {

                    // verify security
                    const current_user_security = results[0].security

                    connection.execute('SELECT security FROM users WHERE id = ?', [jwtData.body.id], (err, results) => {
                        if (err) {
                            console.error(err)
                            res.status(500).json({'error':'Server error.'})
                        } else if (!results.length) {
                            res.status(400).json({ 'error':'User does not exist.'})
                        } else if (results[0].security < 2 || results[0].security <= current_user_security) {
                            res.status(403).json({'error':'Forbidden.'})
                        } else {

                            // ban user
                            connection.execute('UPDATE users SET security = 0, banned = TRUE, ban_reason = ? WHERE id = ?', [ban_reason, user_id], (err) => {
                                if (err) {
                                    console.error(err)
                                    res.status(500).json({'error':'Server error.'})
                                } else {
                                    res.status(200).send('Success.')
                                }
                            })
                        }
                    })
                }
            })
        })
        .catch(err => {
            res.status(400).json({'error':'Invalid token.'})
        })
    }
}

const unbanUser = (req, res, connection) => {

    // validate parameters
    const { jwt, user_id } = req.body

    if (typeof jwt === 'undefined' || typeof user_id === 'undefined') {
        res.status(400).json({ 'error':'Missing parameters.'})
    } else {
        
        // verify token
        JWT.verify(jwt)
        .then((jwtData) => {
                
            // verify user exists
            connection.execute('SELECT security, banned FROM users WHERE id = ?', [user_id], (err, results) => {
                if (err) {
                    console.error(err)
                    res.status(500).json({'error':'Server error.'})
                } else if (!results.length) {
                    res.status(400).json({'error':'Invalid user.'})
                } else if (!results[0].banned) {
                    res.status(400).json({'error':'User is not banned.'})
                } else {

                    // verify security
                    const current_user_security = results[0].security

                    connection.execute('SELECT security FROM users WHERE id = ?', [jwtData.body.id], (err, results) => {
                        if (err) {
                            console.error(err)
                            res.status(500).json({'error':'Server error.'})
                        } else if (!results.length) {
                            res.status(400).json({ 'error':'User does not exist.'})
                        } else if (results[0].security < 2 || results[0].security <= current_user_security) {
                            res.status(403).json({'error':'Forbidden.'})
                        } else {

                            // unban user
                            connection.execute('UPDATE users SET banned = FALSE, ban_reason = NULL WHERE id = ?', [user_id], (err) => {
                                if (err) {
                                    console.error(err)
                                    res.status(500).json({'error':'Server error.'})
                                } else {
                                    res.status(200).send('Success.')
                                }
                            })
                        }
                    })
                }
            })
        })
        .catch(err => {
            res.status(400).json({'error':'Invalid token.'})
        })
    }
}

const getTags = (req, res, connection) => {

    // validate parameters
    const { jwt } = req.body

    if (typeof jwt === 'undefined') {
        res.status(400).json({ 'error':'Missing parameters.'})
    } else {

        // verify token
        JWT.verify(jwt)
        .then((jwtData) => {

            // verify security
            connection.execute('SELECT security FROM users WHERE id = ?', [jwtData.body.id], (err, results) => {
                if (err) {
                    console.error(err)
                    res.status(500).json({'error':'Server error.'})
                } else if (!results.length) {
                    res.status(400).json({ 'error':'User does not exist.'})
                } else if (results[0].security < 1) {
                    res.status(403).json({'error':'Forbidden.'})
                } else {

                    connection.query('SELECT id, enabled, name FROM tags ORDER BY name', (err, results) => {
                        if (err) {
                            console.error(err)
                            res.status(500).json({'error':'Server error.'})
                        } else {
                            res.status(200).json(results)
                        }
                    })
                }
            })
        })
        .catch(err => {
            res.status(400).json({'error':'Invalid token.'})
        })
    }
}

const addTag = (req, res, connection) => {

    // validate parameters
    const { jwt, name } = req.body

    if (typeof jwt === 'undefined' || typeof name === 'undefined') {
        res.status(400).json({ 'error':'Missing parameters.'})
    } else {

        // verify token
        JWT.verify(jwt)
        .then((jwtData) => {

            // verify security
            connection.execute('SELECT security FROM users WHERE id = ?', [jwtData.body.id], (err, results) => {
                if (err) {
                    console.error(err)
                    res.status(500).json({'error':'Server error.'})
                } else if (!results.length) {
                    res.status(400).json({ 'error':'User does not exist.'})
                } else if (results[0].security < 2) {
                    res.status(403).json({'error':'Forbidden.'})
                } else {

                    connection.execute('INSERT INTO tags (enabled, name) VALUES (TRUE, ?)', [name], (err, results) => {
                        if (err) {
                            console.error(err)
                            res.status(500).json({'error':'Server error.'})
                        } else {
                            res.status(200).send('Success.')
                        }
                    })
                }
            })
        })
        .catch(err => {
            res.status(400).json({'error':'Invalid token.'})
        })
    }
}

const disableTag = (req, res, connection) => {

    // validate parameters
    const { jwt, tag_id } = req.body

    if (typeof jwt === 'undefined' || typeof tag_id === 'undefined') {
        res.status(400).json({ 'error':'Missing parameters.'})
    } else {

        // verify token
        JWT.verify(jwt)
        .then((jwtData) => {

            // verify security
            connection.execute('SELECT security FROM users WHERE id = ?', [jwtData.body.id], (err, results) => {
                if (err) {
                    console.error(err)
                    res.status(500).json({'error':'Server error.'})
                } else if (!results.length) {
                    res.status(400).json({ 'error':'User does not exist.'})
                } else if (results[0].security < 2) {
                    res.status(403).json({'error':'Forbidden.'})
                } else {

                    connection.execute('UPDATE tags SET enabled = FALSE WHERE id = ?', [tag_id], (err, results) => {
                        if (err) {
                            console.error(err)
                            res.status(500).json({'error':'Server error.'})
                        } else {
                            res.status(200).send('Success.')
                        }
                    })
                }
            })
        })
        .catch(err => {
            res.status(400).json({'error':'Invalid token.'})
        })
    }
}

const enableTag = (req, res, connection) => {

    // validate parameters
    const { jwt, tag_id } = req.body

    if (typeof jwt === 'undefined' || typeof tag_id === 'undefined') {
        res.status(400).json({ 'error':'Missing parameters.'})
    } else {

        // verify token
        JWT.verify(jwt)
        .then((jwtData) => {

            // verify security
            connection.execute('SELECT security FROM users WHERE id = ?', [jwtData.body.id], (err, results) => {
                if (err) {
                    console.error(err)
                    res.status(500).json({'error':'Server error.'})
                } else if (!results.length) {
                    res.status(400).json({ 'error':'User does not exist.'})
                } else if (results[0].security < 2) {
                    res.status(403).json({'error':'Forbidden.'})
                } else {

                    connection.execute('UPDATE tags SET enabled = TRUE WHERE id = ?', [tag_id], (err, results) => {
                        if (err) {
                            console.error(err)
                            res.status(500).json({'error':'Server error.'})
                        } else {
                            res.status(200).send('Success.')
                        }
                    })
                }
            })
        })
        .catch(err => {
            res.status(400).json({'error':'Invalid token.'})
        })
    }
}

const getTypes = (req, res, connection) => {

    // validate parameters
    const { jwt } = req.body

    if (typeof jwt === 'undefined') {
        res.status(400).json({ 'error':'Missing parameters.'})
    } else {

        // verify token
        JWT.verify(jwt)
        .then((jwtData) => {

            // verify security
            connection.execute('SELECT security FROM users WHERE id = ?', [jwtData.body.id], (err, results) => {
                if (err) {
                    console.error(err)
                    res.status(500).json({'error':'Server error.'})
                } else if (!results.length) {
                    res.status(400).json({ 'error':'User does not exist.'})
                } else if (results[0].security < 1) {
                    res.status(403).json({'error':'Forbidden.'})
                } else {

                    connection.query('SELECT id, enabled, name FROM types ORDER BY name', (err, results) => {
                        if (err) {
                            console.error(err)
                            res.status(500).json({'error':'Server error.'})
                        } else {
                            res.status(200).json(results)
                        }
                    })
                }
            })
        })
        .catch(err => {
            res.status(400).json({'error':'Invalid token.'})
        })
    }
}

const addType = (req, res, connection) => {

    // validate parameters
    const { jwt, name } = req.body

    if (typeof jwt === 'undefined' || typeof name === 'undefined') {
        res.status(400).json({ 'error':'Missing parameters.'})
    } else {

        // verify token
        JWT.verify(jwt)
        .then((jwtData) => {

            // verify security
            connection.execute('SELECT security FROM users WHERE id = ?', [jwtData.body.id], (err, results) => {
                if (err) {
                    console.error(err)
                    res.status(500).json({'error':'Server error.'})
                } else if (!results.length) {
                    res.status(400).json({ 'error':'User does not exist.'})
                } else if (results[0].security < 2) {
                    res.status(403).json({'error':'Forbidden.'})
                } else {

                    connection.execute('INSERT INTO types (enabled, name) VALUES (TRUE, ?)', [name], (err, results) => {
                        if (err) {
                            console.error(err)
                            res.status(500).json({'error':'Server error.'})
                        } else {
                            res.status(200).send('Success.')
                        }
                    })
                }
            })
        })
        .catch(err => {
            res.status(400).json({'error':'Invalid token.'})
        })
    }
}

const disableType = (req, res, connection) => {

    // validate parameters
    const { jwt, type_id } = req.body

    if (typeof jwt === 'undefined' || typeof type_id === 'undefined') {
        res.status(400).json({ 'error':'Missing parameters.'})
    } else {

        // verify token
        JWT.verify(jwt)
        .then((jwtData) => {

            // verify security
            connection.execute('SELECT security FROM users WHERE id = ?', [jwtData.body.id], (err, results) => {
                if (err) {
                    console.error(err)
                    res.status(500).json({'error':'Server error.'})
                } else if (!results.length) {
                    res.status(400).json({ 'error':'User does not exist.'})
                } else if (results[0].security < 2) {
                    res.status(403).json({'error':'Forbidden.'})
                } else {

                    connection.execute('UPDATE types SET enabled = FALSE WHERE id = ?', [type_id], (err, results) => {
                        if (err) {
                            console.error(err)
                            res.status(500).json({'error':'Server error.'})
                        } else {
                            res.status(200).send('Success.')
                        }
                    })
                }
            })
        })
        .catch(err => {
            res.status(400).json({'error':'Invalid token.'})
        })
    }
}

const enableType = (req, res, connection) => {

    // validate parameters
    const { jwt, type_id } = req.body

    if (typeof jwt === 'undefined' || typeof type_id === 'undefined') {
        res.status(400).json({ 'error':'Missing parameters.'})
    } else {

        // verify token
        JWT.verify(jwt)
        .then((jwtData) => {

            // verify security
            connection.execute('SELECT security FROM users WHERE id = ?', [jwtData.body.id], (err, results) => {
                if (err) {
                    console.error(err)
                    res.status(500).json({'error':'Server error.'})
                } else if (!results.length) {
                    res.status(400).json({ 'error':'User does not exist.'})
                } else if (results[0].security < 2) {
                    res.status(403).json({'error':'Forbidden.'})
                } else {

                    connection.execute('UPDATE types SET enabled = TRUE WHERE id = ?', [type_id], (err, results) => {
                        if (err) {
                            console.error(err)
                            res.status(500).json({'error':'Server error.'})
                        } else {
                            res.status(200).send('Success.')
                        }
                    })
                }
            })
        })
        .catch(err => {
            res.status(400).json({'error':'Invalid token.'})
        })
    }
}

const getMealTags = (meal_id, connection) => {
    return new Promise((resolve, reject) => {
        connection.execute(
            `
            SELECT mt.*, t.name as tag_name 
            FROM meal_tags mt 
                INNER JOIN tags t
                ON t.id = mt.tag_id
            WHERE mt.meal_id = ? AND t.enabled = TRUE ORDER BY tag_name
            `, [meal_id], async (err, results) => {
            if (err) {
                reject(err)
            } else {
                resolve(results)
            }
        })
    })
}

const getMealTypes = (meal_id, connection) => {
    return new Promise((resolve, reject) => {
        connection.execute(
            `
            SELECT mt.*, t.name as type_name 
            FROM meal_types mt 
                INNER JOIN types t
                ON t.id = mt.type_id
            WHERE mt.meal_id = ? AND t.enabled = TRUE ORDER BY type_name
            `, [meal_id], async (err, results) => {
            if (err) {
                reject(err)
            } else {
                resolve(results)
            }
        })
    })
}

const getMeals = (req, res, connection) => {
    // validate parameters
    const { jwt, filter } = req.body

    if (typeof jwt === 'undefined' || typeof filter === 'undefined') {
        res.status(400).json({ 'error':'Missing parameters.'})
    } else {

        // verify token
        JWT.verify(jwt)
        .then((jwtData) => {

            // verify security
            connection.execute('SELECT security FROM users WHERE id = ?', [jwtData.body.id], (err, results) => {
                if (err) {
                    console.error(err)
                    res.status(500).json({'error':'Server error.'})
                } else if (!results.length) {
                    res.status(400).json({ 'error':'User does not exist.'})
                } else if (results[0].security < 1) {
                    res.status(403).json({'error':'Forbidden.'})
                } else {

                    let sql = ''
                    switch(filter) {
                        case 'review':
                            sql = `
                                SELECT m.*, u1.username as created_by_username, u2.username as reviewed_by_username 
                                FROM meals m 
                                    LEFT JOIN users u1
                                    ON u1.id = m.created_by
                                    LEFT JOIN users u2
                                    ON u2.id = m.reviewed_by
                                WHERE m.reviewed IS NULL ORDER BY m.created DESC
                                `
                            break
                        case 'all':
                            sql = `
                                SELECT m.*, u1.username as created_by_username, u2.username as reviewed_by_username 
                                FROM meals m 
                                    LEFT JOIN users u1
                                    ON u1.id = m.created_by
                                    LEFT JOIN users u2
                                    ON u2.id = m.reviewed_by
                                ORDER BY m.name
                                `
                            break
                        case 'disabled':
                            sql = `
                                SELECT m.*, u1.username as created_by_username, u2.username as reviewed_by_username 
                                FROM meals m 
                                    LEFT JOIN users u1
                                    ON u1.id = m.created_by
                                    LEFT JOIN users u2
                                    ON u2.id = m.reviewed_by
                                WHERE m.enabled = FALSE ORDER BY m.name
                                `
                            break
                        default: // enabled
                            sql = `
                                SELECT m.*, u1.username as created_by_username, u2.username as reviewed_by_username 
                                FROM meals m 
                                    LEFT JOIN users u1
                                    ON u1.id = m.created_by
                                    LEFT JOIN users u2
                                    ON u2.id = m.reviewed_by
                                WHERE m.enabled = TRUE ORDER BY m.name
                                `
                            break
                    }

                    connection.query(sql, async (err, results) => {
                        if (err) {
                            console.error(err)
                            res.status(500).json({'error':'Server error.'})
                        } else {

                            let meals = results
                            if (!meals.length) {
                                res.status(200).json(meals)
                            } else {

                                // get meal tags
                                for (let i = 0; i < meals.length; i++) {
                                    try {
                                        meals[i].tags = await getMealTags(meals[i].id, connection)
                                    } catch (err) {
                                        res.status(500).json({'error':'Server error.'})
                                    }
                                }

                                // get meal types
                                for (let i = 0; i < meals.length; i++) {
                                    try {
                                        meals[i].types = await getMealTypes(meals[i].id, connection)
                                    } catch (err) {
                                        res.status(500).json({'error':'Server error.'})
                                    }
                                }

                                // return results
                                res.status(200).json(meals)
                            }
                        }
                    })
                }
            })
        })
        .catch(err => {
            res.status(400).json({'error':'Invalid token.'})
        })
    }
}

const approveMeal = (req, res, connection) => {

    // validate parameters
    const { jwt, meal_id } = req.body

    if (typeof jwt === 'undefined' || typeof meal_id === 'undefined') {
        res.status(400).json({ 'error':'Missing parameters.'})
    } else {

        // verify token
        JWT.verify(jwt)
        .then((jwtData) => {

            // verify security
            connection.execute('SELECT id, security FROM users WHERE id = ?', [jwtData.body.id], (err, results) => {
                if (err) {
                    console.error(err)
                    res.status(500).json({'error':'Server error.'})
                } else if (!results.length) {
                    res.status(400).json({ 'error':'User does not exist.'})
                } else if (results[0].security < 1) {
                    res.status(403).json({'error':'Forbidden.'})
                } else {

                    const user = results[0]

                    // verify meal exists and isn't already reviewed
                    connection.execute('SELECT id, reviewed FROM meals WHERE id = ?', [meal_id], (err, results) => {
                        if (err) {
                            console.error(err)
                            res.status(500).json({'error':'Server error.'})
                        } else if (!results.length) {
                            res.status(400).json({'error':'Meal does not exist.'})
                        } else if (results[0].reviewed) {
                            res.status(400).json({'error':'Meal already reviewed.'})
                        } else {

                            // approve meal
                            connection.execute('UPDATE meals SET reviewed = CURRENT_TIMESTAMP, reviewed_by = ?, enabled = TRUE WHERE id = ?', [user.id, meal_id], (err) => {
                                if (err) {
                                    console.error(err)
                                    res.status(500).json({'error':'Server error.'})
                                } else {
                                    res.status(200).send('Success.')
                                }
                            })
                        }
                    })
                }
            })
        })
        .catch(err => {
            res.status(400).json({'error':'Invalid token.'})
        })
    }
}

const rejectMeal = (req, res, connection) => {

    // validate parameters
    const { jwt, meal_id } = req.body

    if (typeof jwt === 'undefined' || typeof meal_id === 'undefined') {
        res.status(400).json({ 'error':'Missing parameters.'})
    } else {

        // verify token
        JWT.verify(jwt)
        .then((jwtData) => {

            // verify security
            connection.execute('SELECT id, security FROM users WHERE id = ?', [jwtData.body.id], (err, results) => {
                if (err) {
                    console.error(err)
                    res.status(500).json({'error':'Server error.'})
                } else if (!results.length) {
                    res.status(400).json({ 'error':'User does not exist.'})
                } else if (results[0].security < 1) {
                    res.status(403).json({'error':'Forbidden.'})
                } else {

                    const user = results[0]

                    // verify meal exists and isn't already reviewed
                    connection.execute('SELECT id, reviewed FROM meals WHERE id = ?', [meal_id], (err, results) => {
                        if (err) {
                            console.error(err)
                            res.status(500).json({'error':'Server error.'})
                        } else if (!results.length) {
                            res.status(400).json({'error':'Meal does not exist.'})
                        } else if (results[0].reviewed) {
                            res.status(400).json({'error':'Meal already reviewed.'})
                        } else {

                            // reject meal
                            connection.execute('UPDATE meals SET reviewed = CURRENT_TIMESTAMP, reviewed_by = ?, enabled = FALSE WHERE id = ?', [user.id, meal_id], (err) => {
                                if (err) {
                                    console.error(err)
                                    res.status(500).json({'error':'Server error.'})
                                } else {
                                    res.status(200).send('Success.')
                                }
                            })
                        }
                    })
                }
            })
        })
        .catch(err => {
            res.status(400).json({'error':'Invalid token.'})
        })
    }
}

const disableMeal = (req, res, connection) => {

    // validate parameters
    const { jwt, meal_id } = req.body

    if (typeof jwt === 'undefined' || typeof meal_id === 'undefined') {
        res.status(400).json({ 'error':'Missing parameters.'})
    } else {

        // verify token
        JWT.verify(jwt)
        .then((jwtData) => {

            // verify security
            connection.execute('SELECT id, security FROM users WHERE id = ?', [jwtData.body.id], (err, results) => {
                if (err) {
                    console.error(err)
                    res.status(500).json({'error':'Server error.'})
                } else if (!results.length) {
                    res.status(400).json({ 'error':'User does not exist.'})
                } else if (results[0].security < 1) {
                    res.status(403).json({'error':'Forbidden.'})
                } else {

                    // verify meal exists and isn't already disabled
                    connection.execute('SELECT id, enabled FROM meals WHERE id = ?', [meal_id], (err, results) => {
                        if (err) {
                            console.error(err)
                            res.status(500).json({'error':'Server error.'})
                        } else if (!results.length) {
                            res.status(400).json({'error':'Meal does not exist.'})
                        } else if (!results[0].enabled) {
                            res.status(400).json({'error':'Meal already disabled.'})
                        } else {

                            // disable meal
                            connection.execute('UPDATE meals SET enabled = FALSE WHERE id = ?', [meal_id], (err) => {
                                if (err) {
                                    console.error(err)
                                    res.status(500).json({'error':'Server error.'})
                                } else {
                                    res.status(200).send('Success.')
                                }
                            })
                        }
                    })
                }
            })
        })
        .catch(err => {
            res.status(400).json({'error':'Invalid token.'})
        })
    }
}

const enableMeal = (req, res, connection) => {

    // validate parameters
    const { jwt, meal_id } = req.body

    if (typeof jwt === 'undefined' || typeof meal_id === 'undefined') {
        res.status(400).json({ 'error':'Missing parameters.'})
    } else {

        // verify token
        JWT.verify(jwt)
        .then((jwtData) => {

            // verify security
            connection.execute('SELECT id, security FROM users WHERE id = ?', [jwtData.body.id], (err, results) => {
                if (err) {
                    console.error(err)
                    res.status(500).json({'error':'Server error.'})
                } else if (!results.length) {
                    res.status(400).json({ 'error':'User does not exist.'})
                } else if (results[0].security < 1) {
                    res.status(403).json({'error':'Forbidden.'})
                } else {

                    // verify meal exists and isn't already enabled
                    connection.execute('SELECT id, enabled FROM meals WHERE id = ?', [meal_id], (err, results) => {
                        if (err) {
                            console.error(err)
                            res.status(500).json({'error':'Server error.'})
                        } else if (!results.length) {
                            res.status(400).json({'error':'Meal does not exist.'})
                        } else if (results[0].enabled) {
                            res.status(400).json({'error':'Meal already enabled.'})
                        } else {

                            // enable meal
                            connection.execute('UPDATE meals SET enabled = TRUE WHERE id = ?', [meal_id], (err) => {
                                if (err) {
                                    console.error(err)
                                    res.status(500).json({'error':'Server error.'})
                                } else {
                                    res.status(200).send('Success.')
                                }
                            })
                        }
                    })
                }
            })
        })
        .catch(err => {
            res.status(400).json({'error':'Invalid token.'})
        })
    }
}


const addMealType = (req, res, connection) => {

    // validate parameters
    const { jwt, meal_id, type_id } = req.body

    if (typeof jwt === 'undefined' || typeof meal_id === 'undefined' || typeof type_id === 'undefined') {
        res.status(400).json({ 'error':'Missing parameters.'})
    } else {

        // verify token
        JWT.verify(jwt)
        .then((jwtData) => {

            // verify security
            connection.execute('SELECT id, security FROM users WHERE id = ?', [jwtData.body.id], (err, results) => {
                if (err) {
                    console.error(err)
                    res.status(500).json({'error':'Server error.'})
                } else if (!results.length) {
                    res.status(400).json({ 'error':'User does not exist.'})
                } else if (results[0].security < 1) {
                    res.status(403).json({'error':'Forbidden.'})
                } else {

                    // verify meal exists
                    connection.execute('SELECT id, enabled FROM meals WHERE id = ?', [meal_id], (err, results) => {
                        if (err) {
                            console.error(err)
                            res.status(500).json({'error':'Server error.'})
                        } else if (!results.length) {
                            res.status(400).json({'error':'Meal does not exist.'})
                        } else {

                            // verify type isn't already applied
                            connection.execute('SELECT * FROM meal_types WHERE meal_id = ? AND type_id = ?', [meal_id, type_id], (err, results) => {
                                if (err) {
                                    console.error(err)
                                    res.status(500).json({'error':'Server error.'})
                                } else if (results.length) {
                                    res.status(400).json({'error':'Meal already has this type.'})
                                } else {

                                    // add type
                                    connection.execute('INSERT INTO meal_types (meal_id, type_id) VALUES (?, ?)', [meal_id, type_id], (err) => {
                                        if (err) {
                                            console.error(err)
                                            res.status(500).json({'error':'Server error.'})
                                        } else {
                                            res.status(200).send('Success.')
                                        }
                                    })
                                }
                            })
                        }
                    })
                }
            })
        })
        .catch(err => {
            res.status(400).json({'error':'Invalid token.'})
        })
    }
}

const addMealTag = (req, res, connection) => {

    // validate parameters
    const { jwt, meal_id, tag_id } = req.body

    if (typeof jwt === 'undefined' || typeof meal_id === 'undefined' || typeof tag_id === 'undefined') {
        res.status(400).json({ 'error':'Missing parameters.'})
    } else {

        // verify token
        JWT.verify(jwt)
        .then((jwtData) => {

            // verify security
            connection.execute('SELECT id, security FROM users WHERE id = ?', [jwtData.body.id], (err, results) => {
                if (err) {
                    console.error(err)
                    res.status(500).json({'error':'Server error.'})
                } else if (!results.length) {
                    res.status(400).json({ 'error':'User does not exist.'})
                } else if (results[0].security < 1) {
                    res.status(403).json({'error':'Forbidden.'})
                } else {

                    // verify meal exists
                    connection.execute('SELECT id, enabled FROM meals WHERE id = ?', [meal_id], (err, results) => {
                        if (err) {
                            console.error(err)
                            res.status(500).json({'error':'Server error.'})
                        } else if (!results.length) {
                            res.status(400).json({'error':'Meal does not exist.'})
                        } else {

                            // verify tag isn't already applied
                            connection.execute('SELECT * FROM meal_tags WHERE meal_id = ? AND tag_id = ?', [meal_id, tag_id], (err, results) => {
                                if (err) {
                                    console.error(err)
                                    res.status(500).json({'error':'Server error.'})
                                } else if (results.length) {
                                    res.status(400).json({'error':'Meal already has this tag.'})
                                } else {

                                    // add tag
                                    connection.execute('INSERT INTO meal_tags (meal_id, tag_id) VALUES (?, ?)', [meal_id, tag_id], (err) => {
                                        if (err) {
                                            console.error(err)
                                            res.status(500).json({'error':'Server error.'})
                                        } else {
                                            res.status(200).send('Success.')
                                        }
                                    })
                                }
                            })
                        }
                    })
                }
            })
        })
        .catch(err => {
            res.status(400).json({'error':'Invalid token.'})
        })
    }
}

const removeMealType = (req, res, connection) => {

    // validate parameters
    const { jwt, id } = req.body

    if (typeof jwt === 'undefined' || typeof id === 'undefined') {
        res.status(400).json({ 'error':'Missing parameters.'})
    } else {

        // verify token
        JWT.verify(jwt)
        .then((jwtData) => {

            // verify security
            connection.execute('SELECT id, security FROM users WHERE id = ?', [jwtData.body.id], (err, results) => {
                if (err) {
                    console.error(err)
                    res.status(500).json({'error':'Server error.'})
                } else if (!results.length) {
                    res.status(400).json({ 'error':'User does not exist.'})
                } else if (results[0].security < 1) {
                    res.status(403).json({'error':'Forbidden.'})
                } else {

                    // verify meal type exists
                    connection.execute('SELECT * FROM meal_types WHERE id = ?', [id], (err, results) => {
                        if (err) {
                            console.error(err)
                            res.status(500).json({'error':'Server error.'})
                        } else if (!results.length) {
                            res.status(400).json({'error':'Meal type does not exist.'})
                        } else {

                            // remove meal type
                            connection.execute('DELETE FROM meal_types WHERE id = ?', [id], (err) => {
                                if (err) {
                                    console.error(err)
                                    res.status(500).json({'error':'Server error.'})
                                } else {
                                    res.status(200).send('Success.')
                                }
                            })
                        }
                    })
                }
            })
        })
        .catch(err => {
            res.status(400).json({'error':'Invalid token.'})
        })
    }
}

const removeMealTag = (req, res, connection) => {

    // validate parameters
    const { jwt, id } = req.body

    if (typeof jwt === 'undefined' || typeof id === 'undefined') {
        res.status(400).json({ 'error':'Missing parameters.'})
    } else {

        // verify token
        JWT.verify(jwt)
        .then((jwtData) => {

            // verify security
            connection.execute('SELECT id, security FROM users WHERE id = ?', [jwtData.body.id], (err, results) => {
                if (err) {
                    console.error(err)
                    res.status(500).json({'error':'Server error.'})
                } else if (!results.length) {
                    res.status(400).json({ 'error':'User does not exist.'})
                } else if (results[0].security < 1) {
                    res.status(403).json({'error':'Forbidden.'})
                } else {

                    // verify meal tag exists
                    connection.execute('SELECT * FROM meal_tags WHERE id = ?', [id], (err, results) => {
                        if (err) {
                            console.error(err)
                            res.status(500).json({'error':'Server error.'})
                        } else if (!results.length) {
                            res.status(400).json({'error':'Meal tag does not exist.'})
                        } else {

                            // remove meal tag
                            connection.execute('DELETE FROM meal_tags WHERE id = ?', [id], (err) => {
                                if (err) {
                                    console.error(err)
                                    res.status(500).json({'error':'Server error.'})
                                } else {
                                    res.status(200).send('Success.')
                                }
                            })
                        }
                    })
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
    demoteUser,
    banUser,
    unbanUser,
    getTags,
    addTag,
    disableTag,
    enableTag,
    getTypes,
    addType,
    disableType,
    enableType,
    getMeals,
    approveMeal,
    rejectMeal,
    disableMeal,
    enableMeal,
    addMealType,
    addMealTag,
    removeMealType,
    removeMealTag
}

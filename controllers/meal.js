const JWT = require('../util/jwt')

const addMeal = (req, res, connection) => {

    // validate parameters
    const { jwt, name, description, tags, types } = req.body

    if (typeof jwt === 'undefined' || typeof name === 'undefined' || typeof description === 'undefined' || typeof tags === 'undefined' || typeof types === 'undefined') {
        res.status(400).json({ 'error':'Missing parameters.'})
    } else {

        // verify at least one tag and one type
        if (!Array.isArray(tags) || !tags.length || !Array.isArray(types) || !types.length) {
            res.status(400).json({ 'error':'Invalid parameters.'})
        } else {

            // verify token
            JWT.verify(jwt)
            .then((jwtData) => {

                // verify not banned
                connection.execute('SELECT id, banned FROM users WHERE id = ?', [jwtData.body.id], (err, results) => {
                    if (err) {
                        console.error(err)
                        res.status(500).json({'error':'Server error.'})
                    } else if (!results.length) {
                        res.status(400).json({ 'error':'User does not exist.'})
                    } else if (results[0].banned) {
                        res.status(403).json({'error':'Account is banned.'})
                    } else {

                        const user = results[0]

                        // begin transaction
                        connection.beginTransaction((err) => {
                            if (err) {
                                console.error(err)
                                res.status(500).json({'error':'Server error.'})
                            } else {

                                // add meal
                                connection.execute('INSERT INTO meals (name, description, created_by) VALUES (?, ?, ?)', [name, description, user.id], (err, result) => {
                                    if (err) {
                                        console.error(err)
                                        connection.rollback()
                                        res.status(500).json({'error':'Server error.'})
                                    } else {

                                        // get meal id
                                        const meal_id = result.insertId

                                        // add meal tags
                                        let sql = 'INSERT INTO meal_tags (meal_id, tag_id) VALUES ?'
                                        let params = tags.map(tag => {
                                            return [meal_id, tag]
                                        })
                                        connection.query(sql, [params], (err) => {
                                            if (err) {
                                                console.error(err)
                                                connection.rollback()
                                                res.status(500).json({'error':'Server error.'})
                                            } else {

                                                // add meal types
                                                let sql = 'INSERT INTO meal_types (meal_id, type_id) VALUES ?'
                                                let params = types.map(type => {
                                                    return [meal_id, type]
                                                })
                                                connection.query(sql, [params], (err) => {
                                                    if (err) {
                                                        console.error(err)
                                                        connection.rollback()
                                                        res.status(500).json({'error':'Server error.'})
                                                    } else {

                                                        // commit transaction
                                                        connection.commit((err) => {
                                                            if (err) {
                                                                console.error(err)
                                                                connection.rollback()
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
}

module.exports = {
    addMeal
}

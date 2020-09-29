const JWT = require('../util/jwt')

const getTags = (req, res, connection) => {

    // validate parameters
    const { jwt } = req.body

    if (typeof jwt === 'undefined') {
        res.status(400).json({ 'error':'Missing parameters.'})
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

                    // get tags
                    connection.query('SELECT t.*, (SELECT COUNT(*) FROM meal_tags WHERE tag_id = t.id AND meal_id IN (SELECT id FROM meals WHERE enabled = TRUE)) as count FROM tags t WHERE t.enabled = TRUE ORDER BY t.name', (err, results) => {
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

module.exports = {
    getTags
}

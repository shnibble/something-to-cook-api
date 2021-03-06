require('dotenv').config()
const cors = require('cors')
const express = require('express')
const bodyParser = require('body-parser')
const childProcess = require('child_process')
const GITHUB_WEBHOOK_SECRET = process.env.GITHUB_WEBHOOK_SECRET
const port = 3000
const version = process.env.npm_package_version || 'unknown'

// controllers
const userController = require('./controllers/user')
const adminController = require('./controllers/admin')
const mealController = require('./controllers/meal')
const typesController = require('./controllers/types')
const tagsController = require('./controllers/tags')

// initialize db connection
const connection = require('./db/connect')

// initialize github webhook
const GithubWebHook = require('express-github-webhook')
const webhookHandler = GithubWebHook({ path: '/webhooks/github', secret: GITHUB_WEBHOOK_SECRET })

// initialize express
const app = express()
app.use(cors())
app.use(bodyParser.urlencoded({
    extended: true
}))
app.use(bodyParser.json())
app.use(webhookHandler)

webhookHandler.on('*', (event, repo, data) => {
    console.log('Incoming webhook event from Github.')

    if (event === 'push' && data.ref === 'refs/heads/master') {
        deploy()
    }
})

const deploy = () => {
    childProcess.exec('cd ~/scripts && ./deploy.sh', (err, stdout, stderr) => {
        if (err) {
            console.error(err)
        } else {
            console.log('Successfully updated repo')
        }
        
    })
}

app.get('/', (req, res) => res.send(`Something to Cook API version ${version}`))
app.post('/user/register', (req, res) => userController.register(req, res, connection))
app.post('/user/login', (req, res) => userController.login(req, res, connection))
app.post('/user/authenticate', (req, res) => userController.authenticate(req, res))
app.post('/user/reset', (req, res) => userController.reset(req, res, connection))
app.post('/user/update/password', (req, res) => userController.updatePassword(req, res, connection))

app.post('/admin/get/users', (req, res) => adminController.getUsers(req, res, connection))
app.post('/admin/user/promote', (req, res) => adminController.promoteUser(req, res, connection))
app.post('/admin/user/demote', (req, res) => adminController.demoteUser(req, res, connection))
app.post('/admin/user/ban', (req, res) => adminController.banUser(req, res, connection))
app.post('/admin/user/unban', (req, res) => adminController.unbanUser(req, res, connection))
app.post('/admin/get/tags', (req, res) => adminController.getTags(req, res, connection))
app.post('/admin/tag/add', (req, res) => adminController.addTag(req, res, connection))
app.post('/admin/tag/disable', (req, res) => adminController.disableTag(req, res, connection))
app.post('/admin/tag/enable', (req, res) => adminController.enableTag(req, res, connection))
app.post('/admin/get/types', (req, res) => adminController.getTypes(req, res, connection))
app.post('/admin/type/add', (req, res) => adminController.addType(req, res, connection))
app.post('/admin/type/disable', (req, res) => adminController.disableType(req, res, connection))
app.post('/admin/type/enable', (req, res) => adminController.enableType(req, res, connection))
app.post('/admin/get/meals', (req, res) => adminController.getMeals(req, res, connection))
app.post('/admin/meal/approve', (req, res) => adminController.approveMeal(req, res, connection))
app.post('/admin/meal/reject', (req, res) => adminController.rejectMeal(req, res, connection))
app.post('/admin/meal/disable', (req, res) => adminController.disableMeal(req, res, connection))
app.post('/admin/meal/enable', (req, res) => adminController.enableMeal(req, res, connection))
app.post('/admin/meal/add/type', (req, res) => adminController.addMealType(req, res, connection))
app.post('/admin/meal/add/tag', (req, res) => adminController.addMealTag(req, res, connection))
app.post('/admin/meal/remove/type', (req, res) => adminController.removeMealType(req, res, connection))
app.post('/admin/meal/remove/tag', (req, res) => adminController.removeMealTag(req, res, connection))

app.post('/meal/add', (req, res) => mealController.addMeal(req, res, connection))

app.post('/types/get', (req, res) => typesController.getTypes(req, res, connection))

app.post('/tags/get', (req, res) => tagsController.getTags(req, res, connection))

app.listen(port, () => console.log(`Something to Cook API version ${version} is listening on port ${port}.`))

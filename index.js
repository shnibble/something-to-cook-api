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

app.listen(port, () => console.log(`Something to Cook API version ${version} is listening on port ${port}.`))

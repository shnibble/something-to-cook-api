require('dotenv').config()
const cors = require('cors')
const express = require('express')
const bodyParser = require('body-parser')
const childProcess = require('child_process')
const GITHUB_WEBHOOK_SECRET = process.env.GITHUB_WEBHOOK_SECRET
const port = 3000
const version = process.env.npm_package_version || 'unknown'

// controllers

// initialize db connection
// const connection = require('./db/connect')

// initialize github webhook
const GithubWebHook = require('express-github-webhook')
const webhookHandler = GithubWebHook({ path: '/webhooks/github', secret: GITHUB_WEBHOOK_SECRET })

// initialize express
const app = express()
app.use(cors())
app.use(bodyParser.urlencoded())
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

app.listen(port, () => console.log(`Something to Cook API version ${version} is listening on port ${port}.`))

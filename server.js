require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser')

const jwt = require('jsonwebtoken');
const crypto = require('crypto')

const fs = require('fs') //logging
const morgan = require('morgan'); //logging

const helmet = require('helmet'); //security
const cors = require('cors'); //cross origin resource security

const User = require('./user.json')

const app = express();

var accessLogStream = fs.createWriteStream('access.log', { flags: 'a' })
app.use(morgan('combined', { stream: accessLogStream }));

app.use(helmet())
app.use(cors());

app.use(bodyParser.urlencoded({ extended: true }));
app.set('view engine', 'ejs');

const REDIRECT_URI = process.env.REDIRECT_URI;
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const USER_EMAIL = User.email;
const USER_PASSWORD = User.password;

let codes = [];
let tokens = [];

app.get('/login', (req, res) => {
    if (!REDIRECT_URI.includes(req.query.redirect_uri))
        return res.status(401).send({ "message": "Invalid redirect URL" })

    if (req.query.client_id != CLIENT_ID)
        return res.status(400).send({ "message": "Invalid client ID" })

    res.render('index', {
        client_id: req.query.client_id,
        redirect_uri: req.query.redirect_uri,
        state: req.query.state ? req.query.state : ""
    })
})

app.post('/login', async (req, res) => {
    if (!REDIRECT_URI.includes(req.body.redirect_uri))
        return res.status(401).send({ "message": "Invalid redirect URL" })

    if (req.body.client_id != CLIENT_ID)
        return res.status(400).send({ "message": "Invalid client ID" })

    if (req.body.email != USER_EMAIL || req.body.password != USER_PASSWORD)
        return res.status(401).send({ "message": "Invalid email or password" })

    const code = crypto.randomBytes(12).toString('hex');
    codes.push(code);

    const responseurl = `${req.body.redirect_uri}?code=${code}&state=${req.body.state}`
    console.log(`Redirecting ${responseurl}`)
    return res.redirect(responseurl)
})

app.get('/authorize', (req, res) => {
    if (!REDIRECT_URI.includes(req.query.redirect_uri))
        return res.status(401).send({ "message": "Invalid redirect URL" })

    if (req.query.client_id != CLIENT_ID)
        return res.status(400).send({ "message": "Invalid client ID" })

    const responseurl = `/login?redirect_uri=${req.query.redirect_uri}&client_id=${req.query.client_id}&state=${req.query.state}`

    console.log("Redirecting " + `${responseurl}`)
    return res.redirect(`${responseurl}`)
})

app.post('/token', async (req, res) => {
    if (req.body.client_id != CLIENT_ID)
        return res.status(400).send({ "message": "Invalid Client ID" });

    if (req.body.grant_type != 'authorization_code' && req.body.grant_type != 'refresh_token')
        return res.status(400).send({ "message": "Invalid grant type" });

    const secondsInDay = 86400; // 60 * 60 * 24
    console.log(`Grant type ${req.body.grant_type}`);

    let obj;
    if (req.body.grant_type === 'authorization_code') {

        if (!codes.includes(req.body.code))
            return res.status(401).send({ "message": "Invalid Code" });

        console.log("Code verified.");
        console.log("Issueing access and refresh tokens");

        const data = crypto.createHash('md5').update(USER_EMAIL).digest('hex');
        const access_token = jwt.sign({ "sub": data }, CLIENT_SECRET, { expiresIn: secondsInDay });
        const refresh_token = crypto.randomBytes(20).toString('hex');

        tokens.push({
            access_token: access_token,
            refresh_token: refresh_token
        })
        codes.splice(codes.indexOf(req.body.code), 1);

        obj = {
            token_type: 'bearer',
            access_token: access_token,
            refresh_token: refresh_token,
            expires_in: secondsInDay,
        }

    } else if (req.body.grant_type === 'refresh_token') {

        const index = tokens.findIndex(token => token.refresh_token == req.body.refresh_token);

        if (index == -1)
            return res.status(401).send({ "message": "Invalid refresh token" });

        console.log("Issueing access token using refresh tokens");

        const data = crypto.createHash('md5').update(USER_EMAIL).digest('hex');
        const access_token = jwt.sign({ "sub": data }, CLIENT_SECRET, { expiresIn: secondsInDay });

        tokens[index].access_token = access_token;

        obj = {
            token_type: 'bearer',
            access_token: access_token,
            expires_in: secondsInDay,
        }
    }
    res.status(200).send(obj);
})

app.get('/userinfo', async (req, res) => {
    try {
        const token = req.headers.authorization.substr(7);
        jwt.verify(token, CLIENT_SECRET);

        if (!tokens.some(tok => tok.access_token === token))
            throw Error

        console.log("UserInfo Fetched")
        return res.send({ "email": USER_EMAIL })
    } catch{
        return res.send({ "message": "Invalid Token" })
    }
})

app.post('/revoke', async (req, res) => {
    try {
        const token = req.headers.authorization.substr(7);
        jwt.verify(token, CLIENT_SECRET)

        if (!tokens.some(tok => tok.refresh_token === req.body.refresh_token))
            throw Error

        console.log("Refresh Token Revoked");

        tokens = tokens.filter(token => token.refresh_token != req.body.refresh_token)
        res.sendStatus(200)
    } catch{
        res.sendStatus(200)
    }
})

const PORT = process.env.PORT;

app.listen(PORT, () => {
    console.log("Server started at " + PORT)
})
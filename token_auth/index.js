const uuid = require('uuid');
const express = require('express');
const onFinished = require('on-finished');
const bodyParser = require('body-parser');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const port = process.env.PORT || 3000;
const app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));

const SESSION_KEY = 'Authorization';

class Session {
  #sessions = {}

  constructor() {
    try {
      this.#sessions = fs.readFileSync('./sessions.json', 'utf8');
      this.#sessions = JSON.parse(this.#sessions.trim());
      console.log(this.#sessions);
    } catch (e) {
      this.#sessions = {};
    }
  }

  #storeSessions() {
    fs.writeFileSync('./sessions.json', JSON.stringify(this.#sessions), 'utf-8');
  }

  set(key, value) {
    if (!value) value = {};
    this.#sessions[key] = value;
    this.#storeSessions();
  }

  get(key) {
    return this.#sessions[key];
  }

  init(res) {
    const sessionId = uuid.v4();
    this.set(sessionId);
    return sessionId;
  }

  destroy(req, res) {
    const sessionId = req.sessionId;
    delete this.#sessions[sessionId];
    this.#storeSessions();
  }
}

const sessions = new Session();

app.use((req, res, next) => {
  let currentSession = {};
  let sessionId = req.get(SESSION_KEY);

  if (sessionId) {
    currentSession = sessions.get(sessionId);
    if (!currentSession) {
      currentSession = {};
      sessionId = sessions.init(res);
    }
  } else {
    sessionId = sessions.init(res);
  }

  req.session = currentSession;
  req.sessionId = sessionId;

  onFinished(req, () => {
    const currentSession = req.session;
    const sessionId = req.sessionId;
    sessions.set(sessionId, currentSession);
  });

  next();
});

app.get('/', (req, res) => {
  if (req.session.username) {
    return res.json({
      username: req.session.username,
      logout: 'http://localhost:3000/logout'
    })
  }
  res.sendFile(path.join(__dirname + '/index.html'));
})

app.get('/logout', (req, res) => {
  sessions.destroy(req, res);
  res.redirect('/');
});

app.post('/api/login', async (req, res) => {
  const {login, password} = req.body;

  try {
    const response = await fetch(`https://${process.env.AUTH0_DOMAIN}/oauth/token`, {
      method: 'POST',
      headers: {'content-type': 'application/json'},
      body: JSON.stringify({
        grant_type: 'http://auth0.com/oauth/grant-type/password-realm',
        username: login,
        password: password,
        client_id: process.env.AUTH0_CLIENT_ID,
        client_secret: process.env.AUTH0_CLIENT_SECRET,
        realm: process.env.AUTH0_REALM,
        scope: 'openid profile email offline_access',
        audience: process.env.AUTH0_AUDIENCE
      })
    });

    if (!response.ok) return res.status(401).json({error: 'Invalid credentials'});

    const data = await response.json();
    const {access_token, id_token, refresh_token} = data;

    req.session.username = login;
    req.session.access_token = access_token;

    res.json({
      message: 'Login successful',
      sessionId: req.sessionId,
      username: login,
      token: access_token,
      refresh_token,
      id_token
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({error: 'Internal server error'});
  }
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
});

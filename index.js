const cors = require('cors')
const express = require('express')
const mysql = require('mysql2/promise')
const jwt = require('jsonwebtoken')
const cookieParser = require('cookie-parser')
const session = require('express-session')
const bcrypt = require('bcrypt')

const app = express()
const port = 8000
const secret = 'mysecret'

let conn = null

// Global middleware

// Parse JSON request bodies
app.use(express.json())

// configuring the CORS to allow request from localhost:8888
app.use(cors({
  credentials: true,
  origin: ['http://localhost:8888']
}))

// middleware allows you to access and manipulate cookies from the incoming HTTP requests.
app.use(cookieParser())

// enable session management
app.use(session({
  secret: 'secret',
  resave: false,
  saveUninitialized: true
}))

// function init connection MySQL
const initMySQL = async () => {
  conn = await mysql.createConnection({
    host: 'localhost',
    port: '3307',
    user: 'root',
    password: 'root',
    database: 'tutorial'
  })
}

const authenticateTokenWithHeader = (req, res, next) => {
  // user headers authorization
  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(' ')[1]

  if (token == null) return res.sendStatus(401) // if there isn't any token

  try {
    const user = jwt.verify(token, secret)
    req.user = user
    console.log('verify with headers token')
    console.log('user', user)
    next()
  } catch (error) {
    return res.sendStatus(403)
  }
}

const authenticateTokenWithCookies = (req, res, next) => {
  // user cookie token authorization
  const token = req.cookies.token
  console.log('cookies', req.cookies)

  if (token == null) return res.sendStatus(401) // if there isn't any token

  try {
    const user = jwt.verify(token, secret)
    req.user = user
    console.log('verify with cookies token')
    console.log('user', user)
    next()
  } catch (error) {
    return res.sendStatus(403)
  }
}

app.post('/api/register', async (req, res) => {
  const { email, password } = req.body
  
  const [rows] = await conn.query('SELECT * FROM users WHERE email = ?', email)
  if (rows.length) {
      return res.status(400).send({ message: 'Email is already registered' })
  }

  // Hash the password
  // 10 is salt (a random number for encryption)
  const hash = await bcrypt.hash(password, 10)

  // Store the user data
  const userData = { email, password: hash }

  try {
    await conn.query('INSERT INTO users SET ?', userData)
  } catch (error) {
    console.error(error)
    res.status(400).json({
      message: 'insert fail',
      error
    })
  }

  res.status(201).send({ message: 'User registered successfully' })
})

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body

  const [result] = await conn.query('SELECT * from users WHERE email = ?', email)
  const user = result[0]
  // check password
  const isMatch = await bcrypt.compare(password, user.password)
  if (!isMatch) {
    return res.status(400).send({ message: 'Invalid email or password' })
  }
  // Create a token
  const token = jwt.sign({ email, role: 'user' }, secret, { expiresIn: '1h' })

  // 2. response back to save cookie token to key 'token'
  res.cookie('token', token, {
    maxAge: 300000, // expire time in millisecond
    secure: true,
    httpOnly: true,
    sameSite: "none",
  })
  
  // 3. save session
  req.session.userId = user.id
  console.log('save session', req.session.userId)
  console.log('sessionID', req.sessionID)

  // 1. send token to frontend to manage it
  res.send({ message: 'Login successful', token })
})

// 1. use authenticate Token With request Header
app.get('/api/users-localStorage', authenticateTokenWithHeader, async (req, res) => {
  try {
    // Get the users
    const [results] = await conn.query('SELECT email FROM users')
    const users = results.map(row => row.email)

    res.send(users)
  } catch (err) {
    console.error(err)
    res.status(500).send({ message: 'Server error' })
  }
})

// 2. use authenticate Token With cookies
app.get('/api/users-cookies', authenticateTokenWithCookies, async (req, res) => {
    try {
      // Get the users
      const [results] = await conn.query('SELECT email FROM users')
      const users = results.map(row => row.email)

      res.send(users)
    } catch (err) {
      console.error(err)
      res.status(500).send({ message: 'Server error' })
    }
})

// 3. use authenticate with session
app.get('/api/users-session', async (req, res) => {
  try {
    if (!req.session.userId) {
      throw { message: 'Auth fail: user have no session'}
    }
    console.log('verify with session')
    console.log(req.session)

    const [results] = await conn.query('SELECT email FROM users')
    const users = results.map(row => row.email)

    res.send(users)
  } catch (err) {
    console.error(err)
    res.status(500).send({ message: 'Server error' })
  }
})

// Listen
app.listen(port, async () => {
  await initMySQL()
  console.log('Server started at port 8000')
})
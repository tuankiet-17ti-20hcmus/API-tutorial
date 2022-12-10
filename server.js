const express = require('express')
const path = require('path')
const bodyParser = require('body-parser')
const exphbs  = require('express-handlebars');
const mongoose = require('mongoose')
const User = require('./model/user')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')

async function connect() {
    try {
        await mongoose.connect('mongodb://localhost:27017/login-app-db');
        console.log('connect database success');
    }
    catch (error) {
        console.log('connect fail');

    }
}

connect()

const JWT_SECRET = 'sdjkfh8923yhjdksbfma@#*(&@*!^#&@bhjb2qiuhesdbhjdsfg839ujkdhfjk'

const app = express()
// app.use(express.static(path.join(__dirname, 'static')))
app.use(bodyParser.json())

app.engine('.hbs', exphbs.engine({ extname: '.hbs', defaultLayout: "main"}));
app.set('view engine', '.hbs');

app.get('/', (reg, res) => {
	res.render('home')
})

app.post('/', (reg, res) => {
	res.render('home')
})

app.get('/register', (reg, res) => {
	res.render('register')
})

app.post('/register', async (req, res) => {
	const { username, password: plainTextPassword } = req.body

	if (!username || typeof username !== 'string') {
		return res.json({ status: 'error', error: 'Invalid username' })
	}

	if (!plainTextPassword || typeof plainTextPassword !== 'string') {
		return res.json({ status: 'error', error: 'Invalid password' })
	}

	if (plainTextPassword.length < 5) {
		return res.json({
			status: 'error',
			error: 'Password too small. Should be atleast 6 characters'
		})
	}

	const password = await bcrypt.hash(plainTextPassword, 10)

	try {
		const response = await User.create({
			username,
			password
		})
		console.log('User created successfully: ', response)
	} catch (error) {
		if (error.code === 11000) {
			// duplicate key
			return res.json({ status: 'error', error: 'Username already in use' })
		}
		throw error
	}

	res.json({ status: 'ok' })
})

app.listen(3000, () => {
	console.log('Server up at http://localhost:3000/')
})
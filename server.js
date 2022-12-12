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

app.get('/api/register', (req, res) => {
	User.find({}, function(err, users) {
		if(!err) res.json(users)
		res.status(400).json({error: 'ERROR!'})
	})
})

app.get('/', (reg, res) => {
	res.render('register')
})

app.get('/login', (reg, res) => {
	res.render('login')
})

app.get('/change-password', (reg, res) => {
	res.render('change-password')
})

app.post('/', (reg, res) => {
	res.render('home')
})

app.post('/api/change-password', async (req, res) => {
	const { token, newpassword: plainTextPassword } = req.body

	if (!plainTextPassword || typeof plainTextPassword !== 'string') {
		return res.json({ status: 'error', error: 'Invalid password' })
	}

	if (plainTextPassword.length < 5) {
		return res.json({
			status: 'error',
			error: 'Password too small. Should be atleast 6 characters'
		})
	}

	try {
		const user = jwt.verify(token, JWT_SECRET)

		const _id = user.id

		const password = await bcrypt.hash(plainTextPassword, 10)

		await User.updateOne(
			{ _id },
			{
				$set: { password }
			}
		)
		res.json({ status: 'ok' })
	} catch (error) {
		console.log(error)
		res.json({ status: 'error', error: ';))' })
	}
})

app.post('/api/login', async (req, res) => {
	const { username, password } = req.body
	const user = await User.findOne({ username }).lean()

	if (!user) {
		return res.json({ status: 'error', error: 'Invalid username/password' })
	}

	if (await bcrypt.compare(password, user.password)) {
		// the username, password combination is successful

		const token = jwt.sign(
			{
				id: user._id,
				username: user.username
			},
			JWT_SECRET
		)

		return res.json({ status: 'ok', data: token })
	}

	res.json({ status: 'error', error: 'Wrong username or password' })
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

const port = process.env.PORT || 3000
app.listen(port, () => {
	console.log('Server up at http://localhost:3000/')
})
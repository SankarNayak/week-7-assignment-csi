const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();
const port = 3000;

const secretKey = 'your_secret_key';

app.use(bodyParser.json());

let users = [];

// Helper function to authenticate token
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (token == null) return res.sendStatus(401);

  jwt.verify(token, secretKey, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Register a new user
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const user = { id: users.length + 1, username, password: hashedPassword };
  users.push(user);
  res.status(201).send(user);
});

// Login a user and generate a JWT
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);

  if (user && await bcrypt.compare(password, user.password)) {
    const accessToken = jwt.sign({ username: user.username, id: user.id }, secretKey);
    res.json({ accessToken });
  } else {
    res.status(401).send({ message: 'Username or password incorrect' });
  }
});

// Create a user (protected route)
app.post('/users', authenticateToken, (req, res) => {
  const user = req.body;
  users.push(user);
  res.status(201).send(user);
});

// Read all users (protected route)
app.get('/users', authenticateToken, (req, res) => {
  res.send(users);
});

// Read a user by ID (protected route)
app.get('/users/:id', authenticateToken, (req, res) => {
  const userId = parseInt(req.params.id, 10);
  const user = users.find(u => u.id === userId);
  if (user) {
    res.send(user);
  } else {
    res.status(404).send({ message: 'User not found' });
  }
});

// Update a user by ID (protected route)
app.put('/users/:id', authenticateToken, (req, res) => {
  const userId = parseInt(req.params.id, 10);
  const userIndex = users.findIndex(u => u.id === userId);
  if (userIndex !== -1) {
    users[userIndex] = req.body;
    res.send(users[userIndex]);
  } else {
    res.status(404).send({ message: 'User not found' });
  }
});

// Delete a user by ID (protected route)
app.delete('/users/:id', authenticateToken, (req, res) => {
  const userId = parseInt(req.params.id, 10);
  const userIndex = users.findIndex(u => u.id === userId);
  if (userIndex !== -1) {
    users.splice(userIndex, 1);
    res.send({ message: 'User deleted' });
  } else {
    res.status(404).send({ message: 'User not found' });
  }
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}/`);
});

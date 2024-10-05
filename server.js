import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const { hashSync, compareSync } = bcrypt;
const { sign, verify } = jwt;

const app = express();
app.use(express.json());

const users = [
  {
    id: 1,
    email: 'user@example.com',
    password: hashSync('password123', 8)
  }
];

const secretKey = '12345678';

// Route de login
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;

  const user = users.find(user => user.email === email);
  if (!user) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  const passwordIsValid = compareSync(password, user.password);
  if (!passwordIsValid) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  const token = sign({ id: user.id }, secretKey, { expiresIn: 86400 }); // 24 heures

  return res.json({ message: 'Login successful', token });
});

// Middleware pour vérifier le JWT
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization'];

  if (!token) {
    return res.status(403).json({ message: 'No token provided' });
  }

  verify(token.split(' ')[1], secretKey, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: 'Unauthorized' });
    }
    req.userId = decoded.id;
    next();
  });
};

// Route protégée
app.get('/api/new-private-data', verifyToken, (req, res) => {
  res.json({ message: 'Welcome to the private data', userId: req.userId });
});

// Lancer le serveur
app.listen(3000, () => {
  console.log('Server is running on port 3000');
});

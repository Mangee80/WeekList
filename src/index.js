const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const dotenv = require('dotenv');

dotenv.config();

const app = express();

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());


// Routes
const authRoutes = require('./routes/authRoutes');
const weekListRoutes = require('./routes/weekListRoutes');

// Use Routes
app.use('/authr', authRoutes);
app.use('/weeklists', weekListRoutes);

// Health API
app.get('/health', (req, res) => {
  res.json({
    serverName: 'Week List Server',
    currentTime: new Date(),
    state: 'active'
  });
});

// Route Not Found Middleware
app.use((req, res, next) => {
  res.status(404).json({ message: 'Route not found' });
});

app.listen(process.env.PORT, () => {
  mongoose.connect(process.env.MONGODB_URL, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() =>  console.log(`Server running on http://localhost:${process.env.PORT}`))
    .catch((error) => console.log(error))
});
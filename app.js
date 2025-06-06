require('dotenv').config();
const express = require('express');
const cors = require('cors');
const authRoutes = require('./routes/auth');
const fileRoutes = require('./routes/files');
const { authenticateToken, decryptRequest, encryptResponse } = require('./middleware/authMiddleware');
const { sequelize } = require('./models');

const app = express();
app.use(cors());
app.use(express.json());

// app.use(encryptResponse);

app.use('/api/auth',
  //  decryptRequest,
   authRoutes);
app.use('/api/files',
  // decryptRequest,
   authenticateToken, fileRoutes);

const PORT = process.env.PORT || 1089;

sequelize.sync().then(() => {
  app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
});
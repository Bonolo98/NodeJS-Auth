import express from 'express';
import bodyParser from 'body-parser';
import authRoutes from './routes/authRoutes.js';

const app = express();
const port = 3000;

app.use(bodyParser.json());

app.use('/api/auth', authRoutes);

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
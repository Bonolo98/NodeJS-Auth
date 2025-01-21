import pkg from 'pg';
const { Pool } = pkg; 

const pool = new Pool({
  user: "postgres",
  host: "localhost",
  database: "nodejs-auth",
  password: "123456",
  port: 5433,
});

export default pool;

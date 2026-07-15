
import { Sequelize } from 'sequelize';
import mysql2 from 'mysql2'; // Force Vercel to bundle mysql2
import 'dotenv/config';

const sequelize = new Sequelize({
  dialect: 'mysql',
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT) || 3306,
  username: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'etherealkreatif',
  logging: false, // Turned off to improve performance and keep terminal clean
  dialectOptions: (process.env.DB_HOST && process.env.DB_HOST.includes('tidbcloud.com')) ? {
    ssl: {
      minVersion: 'TLSv1.2',
      rejectUnauthorized: false
    }
  } : {},
  define: {
    underscored: true,
    freezeTableName: false,
    timestamps: true,
  },
  pool: {
    max: 10,
    min: 0,
    acquire: 30000,
    idle: 10000,
  },
});

export default sequelize;

// src/config/database.js
import sequelize from './sequelize.js';

const connectDB = async () => {
  try {
    await sequelize.authenticate();
    console.log('✅ Database MySQL connected and running');
  } catch (error) {
    console.error('❌ Database connection error:', error.message);
    console.error('Detail:', error.original?.message || error.parent?.message || error);
    // Do not run process.exit(1) to avoid crashing serverless startup on Vercel
  }
};

export { sequelize };
export default connectDB;
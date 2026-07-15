import dotenv from 'dotenv';
import app from './app.js';
import connectDB from './config/database.js';
import { syncDB } from './models/index.js';  // Import semua model & sync helper

// Load environment variables
dotenv.config();

// ========================================
// STARTUP SEQUENCE
// ========================================
const PORT = process.env.PORT || 5000;
const NODE_ENV = process.env.NODE_ENV || 'development';

const startServer = async () => {
  try {
    // 1. Test koneksi MySQL
    await connectDB();

    // 2. Sync semua tabel (alter: true aman untuk dev — hanya ALTER jika perlu)
    //    Untuk production, ganti dengan migrasi manual via sequelize-cli
    if (NODE_ENV !== 'production') {
      await syncDB({ alter: true });
    }

    // 3. Start server
    const server = app.listen(PORT, () => {
      console.log(`🚀 Server running in ${NODE_ENV} mode on port ${PORT}`);
      console.log(`🌐 Server URL: http://localhost:${PORT}`);
    });

    // ========================================
    // GRACEFUL SHUTDOWN
    // ========================================
    const shutdown = (signal) => {
      console.log(`\n${signal} received: closing HTTP server`);
      server.close(() => {
        console.log('HTTP server closed');
        process.exit(0);
      });
    };

    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT',  () => shutdown('SIGINT'));

    // Handle unhandled promise rejections
    process.on('unhandledRejection', (err) => {
      console.error('UNHANDLED REJECTION! Shutting down...');
      console.error(err.name, err.message);
      server.close(() => process.exit(1));
    });

    return server;
  } catch (err) {
    console.error('❌ Failed to start server:', err.message);
    process.exit(1);
  }
};

startServer();
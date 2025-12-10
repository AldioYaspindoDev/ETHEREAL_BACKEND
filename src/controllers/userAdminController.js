import UserAdmin from "../models/userAdminModel.js";
import UserCustomer from "../models/userCustomerModel.js";
import jwt from "jsonwebtoken";

const userAdminController = {
  // Ambil semua user
  getAllUsers: async (req, res) => {
    try {
      const users = await UserAdmin.find();
      res.status(200).json({
        success: true,
        message: "Berhasil mengambil semua data user",
        data: users,
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: "Gagal mengambil data user",
        error: error.message,
      });
    }
  },

  // Register
  register: async (req, res) => {
    const { username, password, role } = req.body;

    if (!username || !password) {
      return res
        .status(400)
        .json({ message: "Username dan password wajib diisi" });
    }

    try {
      const existingUser = await UserAdmin.findOne({
        username: username.toLowerCase().trim(),
      });

      if (existingUser) {
        return res.status(400).json({ message: "Username sudah terdaftar" });
      }

      const newUser = new UserAdmin({
        username: username.toLowerCase().trim(),
        password: password.trim(),
        role: role || "admin",
      });

      await newUser.save();

      res.status(201).json({
        success: true,
        message: "User berhasil didaftarkan",
        data: {
          _id: newUser._id,
          username: newUser.username,
          role: newUser.role,
        },
      });
    } catch (error) {
      console.error("SERVER 500 ERROR IN REGISTER:", error.message, error.stack);
      res.status(500).json({
        success: false,
        message: "Server error saat registrasi",
        error: error.message,
      });
    }
  },

  //  Login - FIXED untuk Production
  login: async (req, res) => {
    const { username, password } = req.body;

    console.log("📥 Admin login attempt:", { username });
    console.log("🌍 Environment:", process.env.NODE_ENV);

    if (!username || !password) {
      return res
        .status(400)
        .json({ message: "Username dan password wajib diisi" });
    }

    try {
      const user = await UserAdmin.findOne({
        username: username.toLowerCase().trim(),
      }).select("+password");

      if (!user) {
        console.log("❌ Admin not found:", username);
        return res.status(400).json({ message: "User tidak ditemukan." });
      }

      const valid = await user.comparePassword(password);
      if (!valid) {
        console.log("❌ Password incorrect");
        return res.status(400).json({ message: "Password salah." });
      }

      //  Buat JWT token
      const token = jwt.sign(
        { id: user._id, role: "admin" },
        process.env.JWT_SECRET,
        { expiresIn: "1d" }
      );

      console.log("🔑 Admin token generated successfully");
      console.log("🔑 Token preview:", token.substring(0, 30) + "...");

      //  PERBAIKAN: Cookie configuration untuk production
      const isProduction = process.env.NODE_ENV === "production";
      
      const cookieOptions = {
        httpOnly: true,
        secure: isProduction, // true di production (HTTPS)
        sameSite: isProduction ? "none" : "lax", // 🔥 PENTING untuk cross-domain
        path: "/",
        maxAge: 24 * 60 * 60 * 1000, // 1 hari
      };

      console.log("🍪 Admin cookie options:", cookieOptions);

      res.cookie("adminToken", token, cookieOptions);

      console.log(" Admin cookie set successfully");

      //  Response dengan token di body juga (fallback)
      res.status(200).json({ 
        success: true,
        message: "Admin login success",
        token: token, //  Kirim token sebagai fallback
        user: {
          id: user._id,
          username: user.username,
          role: user.role,
        }
      });

      console.log(" Admin login successful for:", username);
    } catch (error) {
      console.error("❌ Admin login error:", error);
      res.status(500).json({
        success: false,
        message: "Server error saat login",
        error: error.message,
      });
    }
  },

  userDelete: async (req, res) => {
    try {
      const { id } = req.params;
      const currentAdminId = req.user._id.toString();

      if (id === currentAdminId) {
        return res.status(400).json({
          success: false,
          message:
            "Akses Ditolak: Anda tidak dapat menghapus akun Admin Anda sendiri.",
        });
      }

      const user = await UserAdmin.findByIdAndDelete(id);

      if (!user) {
        return res.status(404).json({ message: "User tidak ditemukan" });
      }
      
      res.status(200).json({
        success: true,
        message: "User berhasil dihapus",
        data: user,
      });
    } catch (error) {
      console.error("Error delete user:", error.message);
      res.status(500).json({
        success: false,
        message: "Gagal menghapus user",
        error: error.message,
      });
    }
  },

  deleteCustomer: async (req, res) => {
    try {
      const { id } = req.params;

      const customer = await UserCustomer.findByIdAndDelete(id);

      if (!customer) {
        return res.status(404).json({
          success: false,
          message: "User customer tidak ditemukan",
        });
      }

      res.status(200).json({
        success: true,
        message: "Berhasil menghapus user customer",
        data: customer,
      });
    } catch (error) {
      console.error("Error delete customer:", error.message);
      res.status(500).json({
        success: false,
        message: "Gagal menghapus user customer",
        error: error.message,
      });
    }
  },

  getAllCustomer: async (req, res) => {
    try {
      const customer = await UserCustomer.find();
      res.status(200).json({
        success: true,
        message: "Berhasil Mengambil semua data user Customer",
        data: customer,
      });
    } catch (error) {
      console.error("error Get all", error.message);
      res.status(500).json({
        success: false,
        message: "Gagal Mengambil semua data user Customer",
        error: error.message,
      });
    }
  },
};

export default userAdminController;
// middleware/adminAuth.js
import jwt from "jsonwebtoken";
import UserAdmin from "../models/userAdminModel.js";

export const adminAuth = async (req, res, next) => {
  try {
    const token = req.cookies?.adminToken;

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Tidak ada token. Silakan login kembali.",
      });
    }

    // Verifikasi token
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (verifyError) {
      console.error("JWT VERIFY ERROR:", verifyError);

      return res.status(401).json({
        success: false,
        message:
          verifyError.name === "TokenExpiredError"
            ? "Token kedaluwarsa. Silakan login kembali."
            : "Token tidak valid. Silakan login ulang.",
        error: verifyError.message,
      });
    }

    // Ambil data admin dari database
    const admin = await UserAdmin.findById(decoded.id);
    if (!admin) {
      return res.status(401).json({
        success: false,
        message: "Admin tidak ditemukan. Silakan login kembali.",
      });
    }

    req.user = admin;
    next();
  } catch (error) {
    console.error("ADMIN AUTH ERROR:", error);

    return res.status(401).json({
      success: false,
      message: "Otorisasi gagal. Silakan login kembali.",
      error: error.message,
    });
  }
};

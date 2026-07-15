// controllers/catalogController.js
import Catalog, {
  CatalogVariant,
  VariantImage,
} from "../models/catalogModel.js";
import { Op } from "sequelize";
import { uploadImage, deleteImage, deleteMultipleImages } from "../services/mediaService.js";

// ─── Helper: normalize catalog Sequelize instance → plain JSON ───────────────
const normalizeCatalog = (catalog) => {
  if (!catalog) return null;
  const plain = typeof catalog.toJSON === "function" ? catalog.toJSON() : catalog;
  if (plain.variants) {
    plain.variants = plain.variants.map((v) => ({
      ...v,
      sizes: (() => {
        if (Array.isArray(v.sizes)) return v.sizes;
        if (!v.sizes) return [];
        if (typeof v.sizes === "object") return v.sizes;
        try {
          const parsed = JSON.parse(v.sizes);
          return Array.isArray(parsed) ? parsed : [];
        } catch {
          return typeof v.sizes === "string" ? v.sizes.split(",").map(s => s.trim()) : [];
        }
      })(),
    }));
  }
  return plain;
};

const catalogController = {
  // ─── CREATE CATALOG WITH FIRST VARIANT ───────────────────────────────────────
  async createCatalog(req, res) {
    try {
      const {
        productName,
        productDescription,
        category,
        productPrice,
        color,
        sizes,
        stock,
      } = req.body;

      if (!productName || !productPrice) {
        return res.status(400).json({
          success: false,
          message: "Nama produk dan harga wajib diisi",
        });
      }
      if (!color || color.trim() === "") {
        return res
          .status(400)
          .json({ success: false, message: "Warna wajib diisi" });
      }

      let parsedSizes = [];
      try {
        parsedSizes = Array.isArray(sizes) ? sizes : JSON.parse(sizes || "[]");
      } catch {
        return res
          .status(400)
          .json({ success: false, message: "Format sizes tidak valid" });
      }
      if (parsedSizes.length === 0) {
        return res.status(400).json({
          success: false,
          message: "Minimal 1 ukuran harus ditambahkan",
        });
      }

      const productImages = [];
      if (req.files?.length > 0) {
        for (let i = 0; i < req.files.length; i++) {
          const file = req.files[i];
          const base64Str = `data:${file.mimetype};base64,${file.buffer.toString("base64")}`;
          const uploadResult = await uploadImage(base64Str, { folder: "ethereal/catalogs" });
          productImages.push({
            url: uploadResult.url,
            publicId: uploadResult.public_id,
            isPrimary: i === 0,
          });
        }
      }
      if (productImages.length === 0) {
        return res.status(400).json({
          success: false,
          message: "Minimal 1 gambar produk harus diupload",
        });
      }

      // Buat catalog + variant + images dalam 1 transaction logic
      const newCatalog = await Catalog.create({
        productName,
        productDescription,
        category,
        isActive: true,
      });
      const variant = await CatalogVariant.create({
        catalogId: newCatalog.id,
        color: color.trim(),
        productPrice: Number(productPrice),
        stock: Number(stock) || 0,
        sizes: parsedSizes,
      });
      await VariantImage.bulkCreate(
        productImages.map((img) => ({ ...img, variantId: variant.id })),
      );

      // Return dengan relasi lengkap
      const result = await Catalog.findByPk(newCatalog.id, {
        include: [
          {
            model: CatalogVariant,
            as: "variants",
            include: [{ model: VariantImage, as: "productImages" }],
          },
        ],
      });

      res.status(201).json({
        success: true,
        message: "Catalog berhasil ditambahkan",
        data: normalizeCatalog(result),
      });
    } catch (error) {
      console.error("❌ Create Catalog Error:", error);
      if (productImages && productImages.length > 0) {
        await deleteMultipleImages(productImages.map((img) => img.publicId));
      }
      res.status(500).json({
        success: false,
        message: error.message || "Gagal menambahkan catalog",
      });
    }
  },

  // ─── ADD VARIANT TO EXISTING CATALOG ─────────────────────────────────────────
  async addVariant(req, res) {
    try {
      const { id } = req.params;
      const { productPrice, color, sizes, stock } = req.body;

      const catalog = await Catalog.findByPk(id);
      if (!catalog)
        return res
          .status(404)
          .json({ success: false, message: "Catalog tidak ditemukan" });

      if (!color || color.trim() === "") {
        return res
          .status(400)
          .json({ success: false, message: "Warna wajib diisi" });
      }

      let parsedSizes = Array.isArray(sizes)
        ? sizes
        : JSON.parse(sizes || "[]");
      if (parsedSizes.length === 0)
        return res
          .status(400)
          .json({ success: false, message: "Sizes wajib diisi" });

      const variant = await CatalogVariant.create({
        catalogId: catalog.id,
        color: color.trim(),
        productPrice: Number(productPrice),
        stock: Number(stock) || 0,
        sizes: parsedSizes,
      });

      const uploadedImages = [];
      if (req.files?.length > 0) {
        for (let i = 0; i < req.files.length; i++) {
          const file = req.files[i];
          const base64Str = `data:${file.mimetype};base64,${file.buffer.toString("base64")}`;
          const uploadResult = await uploadImage(base64Str, { folder: "ethereal/catalogs" });
          uploadedImages.push({
            variantId: variant.id,
            url: uploadResult.url,
            publicId: uploadResult.public_id,
            isPrimary: i === 0,
          });
        }
        await VariantImage.bulkCreate(uploadedImages);
      }

      const result = await Catalog.findByPk(id, {
        include: [
          {
            model: CatalogVariant,
            as: "variants",
            include: [{ model: VariantImage, as: "productImages" }],
          },
        ],
      });

      res.status(201).json({
        success: true,
        message: "Variant berhasil ditambahkan",
        data: normalizeCatalog(result),
      });
    } catch (error) {
      console.error("❌ Add Variant Error:", error);
      if (uploadedImages && uploadedImages.length > 0) {
        await deleteMultipleImages(uploadedImages.map((img) => img.publicId));
      }
      res.status(500).json({ success: false, message: error.message });
    }
  },

  // ─── GET ALL ──────────────────────────────────────────────────────────────────
  async getAllCatalog(req, res) {
    try {
      const { category, isActive, page = 1, limit = 20 } = req.query;
      const where = {};
      if (category) where.category = category;
      if (isActive !== undefined) where.isActive = isActive === "true";

      const offset = (parseInt(page) - 1) * parseInt(limit);
      const { count, rows } = await Catalog.findAndCountAll({
        where,
        include: [
          {
            model: CatalogVariant,
            as: "variants",
            include: [{ model: VariantImage, as: "productImages" }],
          },
        ],
        order: [["createdAt", "DESC"]],
        limit: parseInt(limit),
        offset,
        distinct: true,
        subQuery: false, // Prevents slow nested subqueries in MySQL
      });

      res.status(200).json({
        success: true,
        message: "Berhasil mengambil semua catalog",
        count: rows.length,
        data: rows.map(normalizeCatalog),
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total: count,
          pages: Math.ceil(count / parseInt(limit)),
        },
      });
    } catch (error) {
      res.status(500).json({ success: false, message: error.message });
    }
  },

  // ─── GET BY ID ────────────────────────────────────────────────────────────────
  async getCatalogById(req, res) {
    try {
      const catalog = await Catalog.findByPk(req.params.id, {
        include: [
          {
            model: CatalogVariant,
            as: "variants",
            include: [{ model: VariantImage, as: "productImages" }],
          },
        ],
      });
      if (!catalog)
        return res
          .status(404)
          .json({ success: false, message: "Catalog tidak ditemukan" });

      res.status(200).json({ success: true, data: normalizeCatalog(catalog) });
    } catch (error) {
      res.status(500).json({ success: false, message: error.message });
    }
  },

  // ─── GET VARIANT BY ID ────────────────────────────────────────────────────────
  async getVariantById(req, res) {
    try {
      const { id, variantId } = req.params;
      const catalog = await Catalog.findByPk(id);
      if (!catalog)
        return res
          .status(404)
          .json({ success: false, message: "Catalog tidak ditemukan" });

      const variant = await CatalogVariant.findOne({
        where: { id: variantId, catalogId: id },
        include: [{ model: VariantImage, as: "productImages" }],
      });
      if (!variant)
        return res
          .status(404)
          .json({ success: false, message: "Variant tidak ditemukan" });

      res.status(200).json({
        success: true,
        data: {
          productId: catalog.id,
          productName: catalog.productName,
          variant: {
            ...variant.toJSON(),
            sizes: (() => {
              const s = variant.sizes;
              if (Array.isArray(s)) return s;
              try { return JSON.parse(s || "[]"); }
              catch { return typeof s === "string" ? s.split(",") : []; }
            })(),
          },
        },
      });
    } catch (error) {
      res.status(500).json({ success: false, message: error.message });
    }
  },

  // ─── SEARCH CATALOG ───────────────────────────────────────────────────────────
  async searchCatalog(req, res) {
    try {
      const { q } = req.query;
      if (!q)
        return res
          .status(400)
          .json({ success: false, message: "Query harus diisi" });

      const catalogs = await Catalog.findAll({
        where: { productName: { [Op.like]: `%${q}%` } },
        include: [
          {
            model: CatalogVariant,
            as: "variants",
            include: [{ model: VariantImage, as: "productImages" }],
          },
        ],
      });
      res.json({ success: true, data: catalogs.map(normalizeCatalog) });
    } catch (error) {
      res.status(500).json({ success: false, message: error.message });
    }
  },

  // ─── UPDATE CATALOG (basic info) ─────────────────────────────────────────────
  async updateCatalog(req, res) {
    try {
      const catalog = await Catalog.findByPk(req.params.id);
      if (!catalog)
        return res
          .status(404)
          .json({ success: false, message: "Catalog tidak ditemukan" });

      const { productName, productDescription, category, isActive } = req.body;
      await catalog.update({
        productName: productName ?? catalog.productName,
        productDescription: productDescription ?? catalog.productDescription,
        category: category ?? catalog.category,
        isActive:
          isActive !== undefined
            ? isActive === "true" || isActive === true
            : catalog.isActive,
      });

      res.status(200).json({
        success: true,
        message: "Catalog berhasil diupdate",
        data: catalog,
      });
    } catch (error) {
      res.status(400).json({ success: false, message: error.message });
    }
  },

  // ─── UPDATE VARIANT ───────────────────────────────────────────────────────────
  async updateVariant(req, res) {
    try {
      const { id, variantId } = req.params;

      const catalog = await Catalog.findByPk(id);
      if (!catalog)
        return res
          .status(404)
          .json({ success: false, message: "Catalog tidak ditemukan" });

      const variant = await CatalogVariant.findOne({
        where: { id: variantId, catalogId: id },
        include: [{ model: VariantImage, as: "productImages" }],
      });
      if (!variant)
        return res
          .status(404)
          .json({ success: false, message: "Variant tidak ditemukan" });

      const {
        productPrice,
        stock,
        color,
        sizes,
        deletedImages,
        existingImages,
      } = req.body;

      await variant.update({
        productPrice:
          productPrice !== undefined
            ? Number(productPrice)
            : variant.productPrice,
        stock: stock !== undefined ? Number(stock) : variant.stock,
        color: color ? color.trim() : variant.color,
        sizes: sizes
          ? Array.isArray(sizes)
            ? sizes
            : JSON.parse(sizes)
          : variant.sizes,
      });

      // Handle deleted images (explicitly requested to be removed)
      if (deletedImages) {
        try {
          const deleteList = Array.isArray(deletedImages) ? deletedImages : JSON.parse(deletedImages);
          for (const publicId of deleteList) {
            if (!publicId) continue;
            await VariantImage.destroy({
              where: { variantId: variant.id, publicId },
            });
            await deleteImage(publicId);
          }
        } catch (e) {
          console.error("Error parsing deletedImages:", e);
        }
      }

      // Handle existing images (keep-list: anything not in this list should be removed)
      if (existingImages) {
        try {
          const kept = Array.isArray(existingImages) ? existingImages : JSON.parse(existingImages);
          const keepPublicIds = kept
            .map((img) => img.publicId || img.public_id || img)
            .filter(Boolean);

          if (keepPublicIds.length > 0) {
            const toDelete = await VariantImage.findAll({
              where: {
                variantId: variant.id,
                publicId: { [Op.notIn]: keepPublicIds },
              },
            });
            if (toDelete.length > 0) {
              await deleteMultipleImages(toDelete.map((img) => img.publicId));
              await VariantImage.destroy({
                where: {
                  variantId: variant.id,
                  publicId: { [Op.notIn]: keepPublicIds },
                },
              });
            }
          }
        } catch (e) {
          console.error("Error parsing existingImages:", e);
        }
      }

      // Handle new images upload
      const uploadedNewImages = [];
      if (req.files?.length) {
        for (let i = 0; i < req.files.length; i++) {
          const file = req.files[i];
          const base64Str = `data:${file.mimetype};base64,${file.buffer.toString("base64")}`;
          const uploadResult = await uploadImage(base64Str, { folder: "ethereal/catalogs" });
          uploadedNewImages.push({
            variantId: variant.id,
            url: uploadResult.url,
            publicId: uploadResult.public_id,
            isPrimary: variant.productImages?.length === 0 && i === 0,
          });
        }
        await VariantImage.bulkCreate(uploadedNewImages);
      }

      const result = await Catalog.findByPk(id, {
        include: [
          {
            model: CatalogVariant,
            as: "variants",
            include: [{ model: VariantImage, as: "productImages" }],
          },
        ],
      });

      res.status(200).json({
        success: true,
        message: "Variant berhasil diupdate",
        data: normalizeCatalog(result),
      });
    } catch (error) {
      console.error("Update Variant Error:", error);
      if (uploadedNewImages && uploadedNewImages.length > 0) {
        await deleteMultipleImages(uploadedNewImages.map((img) => img.publicId));
      }
      res.status(400).json({ success: false, message: error.message });
    }
  },

  // ─── DELETE VARIANT ───────────────────────────────────────────────────────────
  async deleteVariant(req, res) {
    try {
      const { id, variantId } = req.params;

      const catalog = await Catalog.findByPk(id, {
        include: [{ model: CatalogVariant, as: "variants" }],
      });
      if (!catalog)
        return res
          .status(404)
          .json({ success: false, message: "Catalog tidak ditemukan" });

      if (catalog.variants.length <= 1) {
        return res.status(400).json({
          success: false,
          message:
            "Tidak dapat menghapus variant terakhir. Hapus catalog jika ingin menghapus seluruh produk.",
        });
      }

      const variant = await CatalogVariant.findOne({
        where: { id: variantId, catalogId: id },
        include: [{ model: VariantImage, as: "productImages" }],
      });
      if (!variant)
        return res
          .status(404)
          .json({ success: false, message: "Variant tidak ditemukan" });

      // Hapus gambar-gambar variant dari Cloudinary
      if (variant.productImages?.length > 0) {
        await deleteMultipleImages(variant.productImages.map((img) => img.publicId));
      }

      await variant.destroy(); // cascade delete images

      const result = await Catalog.findByPk(id, {
        include: [
          {
            model: CatalogVariant,
            as: "variants",
            include: [{ model: VariantImage, as: "productImages" }],
          },
        ],
      });

      res.status(200).json({
        success: true,
        message: "Variant berhasil dihapus",
        data: normalizeCatalog(result),
      });
    } catch (error) {
      res.status(500).json({ success: false, message: error.message });
    }
  },

  // ─── DELETE CATALOG ───────────────────────────────────────────────────────────
  async deleteCatalog(req, res) {
    try {
      const catalog = await Catalog.findByPk(req.params.id, {
        include: [
          {
            model: CatalogVariant,
            as: "variants",
            include: [{ model: VariantImage, as: "productImages" }],
          },
        ],
      });
      if (!catalog)
        return res
          .status(404)
          .json({ success: false, message: "Catalog tidak ditemukan" });

      // Hapus semua gambar dari Cloudinary
      const cloudPublicIds = [];
      for (const variant of catalog.variants) {
        for (const img of variant.productImages) {
          if (img.publicId) cloudPublicIds.push(img.publicId);
        }
      }
      if (cloudPublicIds.length > 0) {
        await deleteMultipleImages(cloudPublicIds);
      }

      await catalog.destroy(); // cascade ke variants & images

      res
        .status(200)
        .json({ success: true, message: "Catalog berhasil dihapus" });
    } catch (error) {
      res.status(500).json({ success: false, message: error.message });
    }
  },

  // ─── CHECK STOCK ──────────────────────────────────────────────────────────────
  async checkStock(req, res) {
    try {
      const { id, variantId } = req.params;

      const catalog = await Catalog.findByPk(id);
      if (!catalog)
        return res
          .status(404)
          .json({ success: false, message: "Catalog tidak ditemukan" });

      if (variantId) {
        const variant = await CatalogVariant.findOne({
          where: { id: variantId, catalogId: id },
        });
        if (!variant)
          return res
            .status(404)
            .json({ success: false, message: "Variant tidak ditemukan" });
        return res.status(200).json({
          success: true,
          data: {
            variantId: variant.id,
            stock: variant.stock,
            available: variant.stock > 0,
          },
        });
      }

      const variants = await CatalogVariant.findAll({
        where: { catalogId: id },
      });
      const stockInfo = variants.map((v) => ({
        variantId: v.id,
        stock: v.stock,
        available: v.stock > 0,
        color: v.color,
        sizes: v.sizes,
      }));

      res.status(200).json({ success: true, data: stockInfo });
    } catch (error) {
      res.status(500).json({ success: false, message: error.message });
    }
  },

  // ─── GET PRODUCT COLORS ───────────────────────────────────────────────────────
  async getProductColors(req, res) {
    try {
      const variants = await CatalogVariant.findAll({
        where: { catalogId: req.params.id },
        attributes: ["color"],
      });
      if (!variants.length)
        return res.status(404).json({
          success: false,
          message: "Catalog tidak ditemukan atau tidak ada variant",
        });

      const colors = [...new Set(variants.map((v) => v.color))];
      res.status(200).json({ success: true, data: colors });
    } catch (error) {
      res.status(500).json({ success: false, message: error.message });
    }
  },
};

export default catalogController;

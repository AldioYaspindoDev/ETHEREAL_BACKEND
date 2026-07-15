import cloudinary from '../config/cloudinary.js';

const DEFAULT_TRANSFORM = [
  { quality: 'auto' },
  { fetch_format: 'auto' },
];

/**
 * Upload gambar dari buffer/base64/path/URL ke Cloudinary.
 * source bisa berupa: base64 string, path file sementara, atau URL eksternal.
 */
export const uploadImage = async (source, options = {}) => {
  const {
    folder = 'uploads/misc',
    transformation = DEFAULT_TRANSFORM,
    publicId,           // opsional, biarkan Cloudinary generate jika kosong
    overwrite = false,
  } = options;

  const result = await cloudinary.uploader.upload(source, {
    folder,
    transformation,
    public_id: publicId,
    overwrite,
  });

  return {
    url: result.secure_url,
    public_id: result.public_id,
    width: result.width,
    height: result.height,
    format: result.format,
    bytes: result.bytes,
  };
};

/**
 * Upload banyak gambar sekaligus.
 */
export const uploadMultipleImages = async (sources, options = {}) => {
  const uploads = sources.map((source) => uploadImage(source, options));
  return Promise.all(uploads);
};

/**
 * Hapus satu gambar berdasarkan public_id.
 */
export const deleteImage = async (publicId) => {
  if (!publicId) return null;
  const result = await cloudinary.uploader.destroy(publicId);
  return result; // { result: 'ok' | 'not found' }
};

/**
 * Hapus banyak gambar sekaligus.
 */
export const deleteMultipleImages = async (publicIds = []) => {
  if (!publicIds.length) return [];
  return Promise.all(publicIds.map((id) => deleteImage(id)));
};

/**
 * Ganti gambar lama dengan yang baru: upload baru dulu, baru hapus lama.
 */
export const replaceImage = async (oldPublicId, newSource, options = {}) => {
  const uploaded = await uploadImage(newSource, options);
  if (oldPublicId) {
    try {
      await deleteImage(oldPublicId);
    } catch (err) {
      console.error(`Gagal menghapus gambar lama (${oldPublicId}):`, err.message);
    }
  }
  return uploaded;
};

/**
 * Generate URL transformasi on-the-fly tanpa upload ulang.
 */
export const getTransformedUrl = (publicId, transformOptions = {}) => {
  return cloudinary.url(publicId, {
    secure: true,
    ...transformOptions,
  });
};

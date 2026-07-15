# CLOUDINARY.md — Logika Inti Penyimpanan Gambar (Framework-Agnostic)

> File ini adalah instruksi baku (system reference) untuk agentic AI/coding assistant.
> Fokus file ini adalah **logika/pattern penyimpanan gambar**, bukan sintaks satu
> framework tertentu. Gunakan sebagai acuan saat mengimplementasikan Cloudinary
> di backend apa pun — Express, Fastify, NestJS, Hono, Koa, dsb — dan sesuaikan
> sintaksnya dengan konvensi framework yang sedang dipakai di proyek.
>
> Default penulisan contoh kode di bawah menggunakan **JavaScript ESM**
> (`import`/`export`). Jika proyek menggunakan CommonJS, TypeScript, atau bahasa
> lain, terjemahkan pola yang sama ke sintaks tersebut — logikanya tetap identik.

---

## 1. Prinsip Dasar (Berlaku di Framework Apapun)

1. Cloudinary hanya boleh diakses lewat **satu layer khusus** (Storage/Media Service),
   bukan langsung dari Controller/Handler/Resolver.
2. Config Cloudinary (credentials) selalu **terpisah** dari logika upload/delete.
3. Middleware/parser upload file (mis. Multer, Fastify-multipart, Busboy) hanya
   bertugas menangkap file — **tidak boleh** berisi business logic.
4. Setiap record di database yang menyimpan gambar **wajib** menyimpan dua hal:
   - `url` — untuk ditampilkan
   - `public_id` — untuk keperluan delete/update/transformasi
5. Saat resource dihapus atau gambar diganti, **wajib** hapus asset lama di Cloudinary
   agar storage tidak menumpuk (orphaned assets).
6. Selalu gunakan `quality: "auto"` dan `fetch_format: "auto"` sebagai default
   transformasi untuk hemat kuota & bandwidth.
7. Validasi tipe & ukuran file dilakukan **sebelum** file sampai ke Cloudinary,
   bukan sesudah upload gagal di tengah jalan.

---

## 2. Struktur Layer (Adaptasi ke Pola Arsitektur Proyek)

Struktur di bawah mengikuti pola **Model → Controller → Route** (lihat `REDIS.md`
untuk konteks arsitektur yang sama), tapi bagian yang wajib ada hanyalah
**layer terpisah untuk Cloudinary**, apa pun nama foldernya di framework lain.

```
src/
├── config/
│   └── cloudinary.js         # inisialisasi & kredensial (WAJIB, semua framework)
├── services/  (atau "providers", "media", tergantung konvensi framework)
│   └── media.service.js      # SEMUA logika upload/delete/transform ada di sini
├── middlewares/ (atau "plugins", "interceptors")
│   └── upload.js             # parser multipart, TIDAK ada business logic
├── models/
│   └── <resource>.model.js   # simpan { url, public_id } sebagai field gambar
├── controllers/  (atau "handlers", "resolvers")
│   └── <resource>.controller.js
└── routes/       (atau "router", "endpoints")
    └── <resource>.route.js
```

Pemetaan istilah antar framework:

| Konsep | Express | Fastify | NestJS | Hono |
|---|---|---|---|---|
| Route handler | Controller function | route handler | Controller (`@Controller`) | Handler |
| Middleware upload | Multer | `@fastify/multipart` | `FileInterceptor` (multer-based) | `hono/multipart` helper |
| Service layer | Plain JS class/module | Plain JS class/module | `@Injectable()` Service | Plain JS module |

---

## 3. Config Layer (Inti, Wajib di Semua Proyek)

`config/cloudinary.js`

```js
import { v2 as cloudinary } from 'cloudinary';

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
  secure: true,
});

export default cloudinary;
```

`.env` (wajib ada di semua proyek, jangan pernah hardcode):

```env
CLOUDINARY_CLOUD_NAME=your_cloud_name
CLOUDINARY_API_KEY=your_api_key
CLOUDINARY_API_SECRET=your_api_secret
```

Tambahkan `.env` ke `.gitignore`. Sediakan `.env.example` tanpa nilai asli.

---

## 4. Media Service — Inti Logika (Reusable, Tidak Terikat Framework)

Layer ini adalah bagian terpenting file ini. Ditulis sebagai fungsi murni
(pure functions) supaya bisa dipanggil dari Controller Express, Handler Fastify,
Service NestJS, atau Resolver GraphQL — tanpa perubahan logika.

`services/media.service.js`

```js
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
 * Upload banyak gambar sekaligus (dipanggil dari Controller/Handler
 * yang sudah punya array of files/buffers/base64).
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
 * Hapus banyak gambar sekaligus (mis. saat resource dengan gallery dihapus).
 */
export const deleteMultipleImages = async (publicIds = []) => {
  if (!publicIds.length) return [];
  return Promise.all(publicIds.map((id) => deleteImage(id)));
};

/**
 * Ganti gambar lama dengan yang baru: upload baru dulu, baru hapus lama.
 * Urutan ini penting supaya tidak ada state "tanpa gambar" jika upload gagal.
 */
export const replaceImage = async (oldPublicId, newSource, options = {}) => {
  const uploaded = await uploadImage(newSource, options);
  if (oldPublicId) await deleteImage(oldPublicId);
  return uploaded;
};

/**
 * Generate URL transformasi on-the-fly tanpa upload ulang.
 * Dipakai untuk thumbnail, resize, watermark, dsb.
 */
export const getTransformedUrl = (publicId, transformOptions = {}) => {
  return cloudinary.url(publicId, {
    secure: true,
    ...transformOptions,
  });
};
```

**Kenapa disebut "reusable"?**
Fungsi-fungsi di atas tidak menyentuh `req`/`res`, tidak tahu apa itu Express atau
Fastify. Jadi service ini bisa dipanggil dari Controller REST, Resolver GraphQL,
CLI script, atau cron job — tanpa perubahan.

---

## 5. Upload Middleware/Parser — Adaptasi per Framework

Bagian ini **boleh berbeda** tergantung framework, karena tugasnya hanya menangkap
file dari request dan meneruskannya ke `media.service.js`. Jangan taruh logika
Cloudinary di sini.

### Express (Multer)
```js
import multer from 'multer';

const storage = multer.memoryStorage(); // simpan di memory, lalu upload manual via service
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: (req, file, cb) => {
    const allowed = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
    cb(null, allowed.includes(file.mimetype));
  },
});

export default upload;
```

> Gunakan `memoryStorage`, bukan `multer-storage-cloudinary`, supaya file diteruskan
> sebagai **buffer** ke `media.service.js` — ini yang membuat service layer tetap
> framework-agnostic (tidak bergantung pada storage engine Multer tertentu).

Konversi buffer ke base64 sebelum dikirim ke `uploadImage`:
```js
const toBase64 = (file) =>
  `data:${file.mimetype};base64,${file.buffer.toString('base64')}`;
```

### Fastify (`@fastify/multipart`)
```js
const data = await request.file();
const buffer = await data.toBuffer();
const base64 = `data:${data.mimetype};base64,${buffer.toString('base64')}`;
// kirim `base64` ke uploadImage()
```

### NestJS (`FileInterceptor`, tetap berbasis Multer)
```ts
@Post('upload')
@UseInterceptors(FileInterceptor('image', { storage: memoryStorage() }))
uploadImage(@UploadedFile() file: Express.Multer.File) {
  const base64 = `data:${file.mimetype};base64,${file.buffer.toString('base64')}`;
  return this.mediaService.uploadImage(base64, { folder: 'uploads/projects' });
}
```

### Hono
```js
const body = await c.req.parseBody();
const file = body['image']; // File object (Web API)
const buffer = Buffer.from(await file.arrayBuffer());
const base64 = `data:${file.type};base64,${buffer.toString('base64')}`;
```

---

## 6. Controller/Handler — Hanya Memanggil Service

Pola ini identik di semua framework, hanya sintaksnya yang beda.

```js
import * as MediaService from '../services/media.service.js';
import * as ResourceModel from '../models/<resource>.model.js';

export const createResourceWithImage = async (req, res) => {
  const base64 = `data:${req.file.mimetype};base64,${req.file.buffer.toString('base64')}`;

  const image = await MediaService.uploadImage(base64, {
    folder: 'uploads/<resource>',
  });

  const data = await ResourceModel.create({
    ...req.body,
    image: { url: image.url, public_id: image.public_id },
  });

  res.status(201).json(data);
};

export const updateResourceImage = async (req, res) => {
  const existing = await ResourceModel.findById(req.params.id);
  const base64 = `data:${req.file.mimetype};base64,${req.file.buffer.toString('base64')}`;

  const image = await MediaService.replaceImage(
    existing.image?.public_id,
    base64,
    { folder: 'uploads/<resource>' }
  );

  const data = await ResourceModel.update(req.params.id, {
    image: { url: image.url, public_id: image.public_id },
  });

  res.json(data);
};

export const deleteResource = async (req, res) => {
  const existing = await ResourceModel.findById(req.params.id);
  if (existing?.image?.public_id) {
    await MediaService.deleteImage(existing.image.public_id);
  }
  await ResourceModel.remove(req.params.id);
  res.status(204).send();
};
```

---

## 7. Skema Data Wajib di Model

Field gambar pada model/skema **selalu** menyimpan pasangan `url` + `public_id`,
tidak peduli database-nya SQL, NoSQL, atau ORM apa pun:

```
image: {
  url: string,        // ditampilkan di frontend
  public_id: string,  // dipakai untuk delete/replace/transform
}

gallery: [
  { url: string, public_id: string }
]
```

Contoh adaptasi:
- **Mongoose (MongoDB)** → sub-document seperti di atas.
- **Prisma (SQL)** → dua kolom terpisah `imageUrl` dan `imagePublicId`, atau
  tabel relasi `Image` jika galeri banyak.
- **Sequelize (SQL)** → sama seperti Prisma, dua kolom atau tabel relasi.

---

## 8. Upload dari URL Eksternal (Opsional)

Berguna jika sumber gambar bukan dari upload user, tapi dari URL pihak ketiga
(mis. scraping, import data, integrasi API lain).

```js
export const uploadFromUrl = async (imageUrl, options = {}) => {
  return uploadImage(imageUrl, options); // Cloudinary bisa fetch langsung dari URL
};
```

---

## 9. Checklist yang Harus Dijalankan Agentic AI Saat Mengimplementasikan Cloudinary

1. [ ] Deteksi framework yang dipakai proyek (Express/Fastify/NestJS/Hono/lainnya).
2. [ ] Install package inti: `npm install cloudinary` + package upload-parser
       sesuai framework (mis. `multer` untuk Express, `@fastify/multipart` untuk Fastify).
3. [ ] Buat `config/cloudinary.js` sesuai Bagian 3, gunakan environment variable.
4. [ ] Tambahkan `CLOUDINARY_CLOUD_NAME`, `CLOUDINARY_API_KEY`, `CLOUDINARY_API_SECRET`
       ke `.env` dan `.env.example`.
5. [ ] Buat `services/media.service.js` sesuai Bagian 4 — **jangan** taruh logika ini
       di Controller/Handler.
6. [ ] Buat middleware/parser upload sesuai framework yang terdeteksi (Bagian 5),
       gunakan `memoryStorage`/buffer, **jangan** pakai storage engine yang langsung
       auto-upload ke Cloudinary (supaya logic tetap terpusat di service layer).
7. [ ] Pastikan skema/model resource menyimpan `{ url, public_id }`, bukan hanya `url`.
8. [ ] Pastikan setiap operasi update gambar memanggil `replaceImage()`
       (upload baru dulu, baru hapus lama).
9. [ ] Pastikan setiap operasi delete resource menghapus gambar terkait di Cloudinary
       (`deleteImage`/`deleteMultipleImages`) sebelum/scaligus menghapus record di DB.
10. [ ] Set default transformasi `quality: auto` + `fetch_format: auto` di semua upload.
11. [ ] Batasi ukuran file (default 5MB) dan tipe file (jpg, jpeg, png, webp, gif)
        di layer parser sebelum sampai ke service.
12. [ ] Tambahkan error handler khusus untuk error ukuran file & format tidak didukung.

---

## 10. Hal yang HARUS Dihindari

- ❌ Memanggil `cloudinary.uploader.*` langsung dari Controller/Handler/Route.
- ❌ Menggunakan storage engine yang otomatis upload ke Cloudinary di level middleware
     (mis. `multer-storage-cloudinary`) — ini mengunci logic ke Express + Multer dan
     menyulitkan reuse ke framework lain. Gunakan `memoryStorage` + service layer manual.
- ❌ Menyimpan hanya `url` tanpa `public_id` — membuat gambar lama tidak bisa dihapus.
- ❌ Menghapus gambar lama sebelum gambar baru berhasil diupload (urutan harus:
     upload baru → sukses → baru hapus lama).
- ❌ Meng-upload file tanpa validasi tipe/ukuran terlebih dahulu.
- ❌ Hardcode credentials Cloudinary di dalam kode.

---

*File ini fokus pada logika penyimpanan gambar yang portable lintas framework.
Untuk kebutuhan spesifik (mis. video, PDF, atau format non-gambar lain), tambahkan
section baru mengikuti gaya penulisan yang sama — jangan menimpa struktur dasar di atas.
Jika proyek memakai caching (mis. Redis) untuk metadata gambar, lihat `REDIS.md`
untuk pola integrasinya.*

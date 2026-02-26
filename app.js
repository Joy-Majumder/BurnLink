require("dotenv").config();

const path = require("path");
const crypto = require("crypto");
const { promisify } = require("util");
const express = require("express");
const multer = require("multer");
const File = require("./models/File");
const supabase = require("./lib/supabase");

const app = express();
const pbkdf2Async = promisify(crypto.pbkdf2);
const storageBucket = process.env.SUPABASE_STORAGE_BUCKET || "files";
const maxUploadBytes = Number(process.env.MAX_UPLOAD_BYTES || 8 * 1024 * 1024);

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: maxUploadBytes },
});

const SALT_LENGTH = 16;
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const KEY_LENGTH = 32;
const PBKDF2_ITERATIONS = 210000;
const PBKDF2_DIGEST = "sha256";

function buildStoragePath(originalName) {
  const safeName = (originalName || "file").replace(/[^\w.\-]+/g, "_");
  return `${new Date().toISOString().slice(0, 10)}/${crypto.randomUUID()}-${safeName}`;
}

async function uploadToStorage(storagePath, buffer) {
  const { error } = await supabase.storage
    .from(storageBucket)
    .upload(storagePath, buffer, {
      contentType: "application/octet-stream",
      upsert: false,
    });

  if (error) {
    throw new Error(`Storage upload failed: ${error.message}`);
  }
}

async function downloadFromStorage(storagePath) {
  const { data, error } = await supabase.storage
    .from(storageBucket)
    .download(storagePath);

  if (error) {
    throw new Error(`Storage download failed: ${error.message}`);
  }

  const arrayBuffer = await data.arrayBuffer();
  return Buffer.from(arrayBuffer);
}

async function removeFromStorage(storagePath) {
  if (!storagePath) return;

  const { error } = await supabase.storage
    .from(storageBucket)
    .remove([storagePath]);

  if (error && !/not found/i.test(error.message)) {
    console.error(`Storage delete failed for ${storagePath}:`, error.message);
  }
}

async function encryptBuffer(plainBuffer, password) {
  const salt = crypto.randomBytes(SALT_LENGTH);
  const iv = crypto.randomBytes(IV_LENGTH);
  const key = await pbkdf2Async(
    password,
    salt,
    PBKDF2_ITERATIONS,
    KEY_LENGTH,
    PBKDF2_DIGEST
  );

  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encryptedBuffer = Buffer.concat([
    cipher.update(plainBuffer),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();

  // payload format: [salt][iv][authTag][ciphertext]
  return Buffer.concat([salt, iv, authTag, encryptedBuffer]);
}

async function decryptBuffer(payload, password) {
  const headerLength = SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH;
  if (payload.length <= headerLength) {
    throw new Error("Encrypted payload is invalid.");
  }

  const salt = payload.subarray(0, SALT_LENGTH);
  const iv = payload.subarray(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
  const authTag = payload.subarray(
    SALT_LENGTH + IV_LENGTH,
    SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH
  );
  const ciphertext = payload.subarray(headerLength);

  const key = await pbkdf2Async(
    password,
    salt,
    PBKDF2_ITERATIONS,
    KEY_LENGTH,
    PBKDF2_DIGEST
  );

  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

async function sendOneTimeFile(res, file, password) {
  const storedBuffer = await downloadFromStorage(file.path);
  const outputBuffer = file.password
    ? await decryptBuffer(storedBuffer, password)
    : storedBuffer;

  // Burn the link before sending data so the URL cannot be reused.
  const deleted = await File.deleteById(file.id);
  if (!deleted) {
    return res.status(410).render("not-found");
  }

  await removeFromStorage(file.path);
  res.attachment(file.originalName);
  res.setHeader("Content-Type", "application/octet-stream");
  return res.send(outputBuffer);
}

app.use(express.urlencoded({ extended: true }));
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.get("/", (req, res) => {
  res.render("index", { fileLink: null, error: null });
});

app.post("/upload", upload.single("file"), async (req, res) => {
  let storagePath = null;

  try {
    if (!req.file) {
      return res.status(400).render("index", {
        fileLink: null,
        error: "Please choose a file to upload.",
      });
    }

    const rawPassword = req.body.password?.trim() || "";
    const uploadBuffer = rawPassword
      ? await encryptBuffer(req.file.buffer, rawPassword)
      : req.file.buffer;

    storagePath = buildStoragePath(req.file.originalname);
    await uploadToStorage(storagePath, uploadBuffer);

    const file = await File.createFile({
      path: storagePath,
      originalName: req.file.originalname,
      password: rawPassword || undefined,
    });

    const fileLink = `${req.protocol}://${req.get("host")}/file/${file.id}`;
    return res.render("index", { fileLink, error: null });
  } catch (error) {
    if (storagePath) {
      await removeFromStorage(storagePath);
    }

    return res.status(500).render("index", {
      fileLink: null,
      error: "Upload failed. Please try again.",
    });
  }
});

app.get("/file/:id", async (req, res) => {
  try {
    const file = await File.findById(req.params.id);

    if (!file) {
      return res.status(404).render("not-found");
    }

    if (file.password) {
      return res.render("password", { error: null });
    }

    return sendOneTimeFile(res, file, "");
  } catch (error) {
    return res.status(400).render("not-found");
  }
});

app.post("/file/:id", async (req, res) => {
  try {
    const file = await File.findById(req.params.id);

    if (!file) {
      return res.status(404).render("not-found");
    }

    if (!file.password) {
      return sendOneTimeFile(res, file, "");
    }

    const submittedPassword = req.body.password || "";
    const passwordOk = await File.comparePassword(file, submittedPassword);
    if (!passwordOk) {
      return res.status(401).render("password", {
        error: "Wrong password. Try again.",
      });
    }

    return sendOneTimeFile(res, file, submittedPassword);
  } catch (error) {
    if (error.message && error.message.includes("authenticate")) {
      return res.status(401).render("password", {
        error: "Wrong password. Try again.",
      });
    }

    return res.status(400).render("not-found");
  }
});

app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError && error.code === "LIMIT_FILE_SIZE") {
    return res.status(413).render("index", {
      fileLink: null,
      error: `File is too large. Max size is ${Math.floor(maxUploadBytes / 1024 / 1024)}MB.`,
    });
  }

  return next(error);
});

module.exports = app;

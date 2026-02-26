const bcrypt = require("bcrypt");
const supabase = require("../lib/supabase");

const filesTable = process.env.SUPABASE_FILES_TABLE || "files";

function mapRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    path: row.path,
    originalName: row.original_name,
    password: row.password,
    failedAttempts: row.failed_attempts || 0,
    lockedUntil: row.locked_until || null,
  };
}

async function createFile({ path, originalName, password }) {
  const hashedPassword = password ? await bcrypt.hash(password, 10) : null;

  const { data, error } = await supabase
    .from(filesTable)
    .insert({
      path,
      original_name: originalName,
      password: hashedPassword,
      failed_attempts: 0,
      locked_until: null,
    })
    .select("*")
    .single();

  if (error) {
    throw new Error(error.message);
  }

  return mapRow(data);
}

async function findFileById(id) {
  const { data, error } = await supabase
    .from(filesTable)
    .select("*")
    .eq("id", id)
    .maybeSingle();

  if (error) {
    throw new Error(error.message);
  }

  return mapRow(data);
}

async function updateLockState(id, failedAttempts, lockedUntil) {
  const { error } = await supabase
    .from(filesTable)
    .update({
      failed_attempts: failedAttempts,
      locked_until: lockedUntil,
    })
    .eq("id", id);

  if (error) {
    throw new Error(error.message);
  }
}

async function deleteFileById(id) {
  const { data, error } = await supabase
    .from(filesTable)
    .delete()
    .eq("id", id)
    .select("id")
    .maybeSingle();

  if (error) {
    throw new Error(error.message);
  }

  return Boolean(data);
}

function comparePassword(file, password) {
  return bcrypt.compare(password, file.password);
}

module.exports = {
  createFile,
  findById: findFileById,
  deleteById: deleteFileById,
  updateLockState,
  comparePassword,
};

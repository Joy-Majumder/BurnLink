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
    })
    .select("id, path, original_name, password")
    .single();

  if (error) {
    throw new Error(error.message);
  }

  return mapRow(data);
}

async function findFileById(id) {
  const { data, error } = await supabase
    .from(filesTable)
    .select("id, path, original_name, password")
    .eq("id", id)
    .maybeSingle();

  if (error) {
    throw new Error(error.message);
  }

  return mapRow(data);
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
  comparePassword,
};

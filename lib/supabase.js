const { createClient } = require("@supabase/supabase-js");

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!supabaseUrl) {
  throw new Error("SUPABASE_URL is missing in .env");
}

if (!supabaseKey) {
  throw new Error("SUPABASE_SERVICE_ROLE_KEY is missing in .env");
}

if (supabaseUrl.includes("YOUR_PROJECT_REF")) {
  throw new Error("SUPABASE_URL is still a placeholder. Set your real project URL.");
}

if (supabaseKey.includes("YOUR_SUPABASE_SERVICE_ROLE_KEY")) {
  throw new Error(
    "SUPABASE_SERVICE_ROLE_KEY is still a placeholder. Set your real service role key."
  );
}

const supabase = createClient(supabaseUrl, supabaseKey);

module.exports = supabase;

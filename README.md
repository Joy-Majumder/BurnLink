# File Sharing Server

One-time file sharing app with browser-side end-to-end encryption.

## Features
- True end-to-end encryption: files are encrypted in browser before upload.
- Optional password mode (recipient enters password to decrypt in browser).
- No-password mode uses a secret key embedded in the share link fragment.
- One-time download links (burn after successful download).
- Password-protected links lock for 10 minutes after 3 wrong attempts.
- Supabase table for metadata + Supabase Storage for file payloads.
- Copy-link button in UI.


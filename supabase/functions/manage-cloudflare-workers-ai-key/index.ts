// PusoAI: owner-only Cloudflare Workers AI credential manager.
// Secrets are encrypted with AES-256-GCM before being stored in public.ai_provider_secrets.
// Required Edge Function secret: AI_KEY_ENCRYPTION_SECRET (32+ random characters).
// Supabase provides SUPABASE_URL, SUPABASE_ANON_KEY and SUPABASE_SERVICE_ROLE_KEY.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const OWNER_EMAIL = "pusoai001@gmail.com";
const PROVIDER = "cloudflare_workers_ai";
const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Content-Type": "application/json",
};

function json(status: number, body: Record<string, unknown>) {
  return new Response(JSON.stringify(body), { status, headers: corsHeaders });
}

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

async function encryptionKey(secret: string): Promise<CryptoKey> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(secret));
  return crypto.subtle.importKey("raw", digest, { name: "AES-GCM" }, false, ["encrypt"]);
}

async function encryptCredentials(value: unknown, secret: string) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await encryptionKey(secret);
  const plaintext = new TextEncoder().encode(JSON.stringify(value));
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext);
  return { iv: toBase64(iv), ciphertext: toBase64(new Uint8Array(encrypted)) };
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json(405, { error: "Method not allowed." });

  try {
    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
    const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    const encryptionSecret = Deno.env.get("AI_KEY_ENCRYPTION_SECRET");
    if (!supabaseUrl || !anonKey || !serviceRoleKey || !encryptionSecret || encryptionSecret.length < 32) {
      return json(500, { error: "Server configuration is incomplete. Check Supabase Edge Function secrets." });
    }

    const authorization = req.headers.get("Authorization") || "";
    const jwt = authorization.replace(/^Bearer\\s+/i, "");
    if (!jwt || jwt === authorization) return json(401, { error: "Please sign in as the PusoAI owner." });

    const authClient = createClient(supabaseUrl, anonKey, {
      auth: { persistSession: false, autoRefreshToken: false },
    });
    const { data: userData, error: userError } = await authClient.auth.getUser(jwt);
    if (userError || !userData.user || userData.user.email?.toLowerCase() !== OWNER_EMAIL) {
      return json(403, { error: "Only the configured PusoAI owner can manage Cloudflare credentials." });
    }

    const admin = createClient(supabaseUrl, serviceRoleKey, {
      auth: { persistSession: false, autoRefreshToken: false },
    });
    const body = await req.json().catch(() => ({}));
    const action = typeof body.action === "string" ? body.action : "";

    if (action === "status") {
      const { data, error } = await admin.from("ai_provider_secrets")
        .select("provider").eq("provider", PROVIDER).maybeSingle();
      if (error) throw new Error("Could not read the saved Cloudflare configuration.");
      return json(200, { configured: Boolean(data) });
    }

    if (action === "remove") {
      const { error } = await admin.from("ai_provider_secrets")
        .delete().eq("provider", PROVIDER);
      if (error) throw new Error("Could not remove the saved Cloudflare configuration.");
      return json(200, { success: true, configured: false });
    }

    if (action === "save") {
      const accountId = typeof body.accountId === "string" ? body.accountId.trim() : "";
      const apiToken = typeof body.apiToken === "string" ? body.apiToken.trim() : "";
      if (!/^[a-f0-9]{32}$/i.test(accountId)) return json(400, { error: "Enter a valid 32-character Cloudflare Account ID." });
      if (apiToken.length < 20 || apiToken.length > 1000) return json(400, { error: "The Cloudflare API token is missing or invalid." });

      // Verify the token is active without ever logging or returning it.
      const verifyResponse = await fetch("https://api.cloudflare.com/client/v4/user/tokens/verify", {
        method: "GET",
        headers: { Authorization: `Bearer ${apiToken}`, "Content-Type": "application/json" },
      });
      const verifyData = await verifyResponse.json().catch(() => ({}));
      if (!verifyResponse.ok || verifyData?.success !== true) {
        return json(400, { error: "Cloudflare rejected this API token. Check that it is active and try again." });
      }

      const encrypted = await encryptCredentials({ accountId, apiToken }, encryptionSecret);
      const { error } = await admin.from("ai_provider_secrets").upsert({
        provider: PROVIDER,
        ciphertext: encrypted.ciphertext,
        iv: encrypted.iv,
        updated_at: new Date().toISOString(),
      }, { onConflict: "provider" });
      if (error) throw new Error("Could not save the encrypted Cloudflare credentials.");
      return json(200, { success: true, configured: true });
    }

    return json(400, { error: "Unsupported action. Use save, status, or remove." });
  } catch (error) {
    // Deliberately avoid logging request bodies or secret values.
    console.error("Cloudflare credential manager error:", error instanceof Error ? error.message : "Unknown error");
    return json(500, { error: error instanceof Error ? error.message : "Unexpected server error." });
  }
});

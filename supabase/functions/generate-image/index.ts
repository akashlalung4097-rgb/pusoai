import { createClient } from "npm:@supabase/supabase-js@2";

const ALLOWED_ORIGINS = new Set([
  "https://pusoai.online",
  "https://www.pusoai.online",
  "https://akashlalung4097-rgb.github.io",
  "http://localhost:5500",
  "http://127.0.0.1:5500",
]);

const PROVIDER = "cloudflare_workers_ai";
const TEXT_MODEL = "@cf/black-forest-labs/flux-1-schnell";
const EDIT_MODEL = "@cf/black-forest-labs/flux-2-klein-9b";
const MAX_PROMPT_LENGTH = 1500;
const MAX_IMAGE_BYTES = 2 * 1024 * 1024;

function corsHeaders(origin: string | null): Record<string, string> {
  return {
    "Access-Control-Allow-Origin": origin && ALLOWED_ORIGINS.has(origin) ? origin : "null",
    "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin",
  };
}

function json(body: unknown, status: number, origin: string | null): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders(origin), "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

function getSecretKey(): string {
  const jsonKeys = Deno.env.get("SUPABASE_SECRET_KEYS");
  if (jsonKeys) {
    try {
      const parsed = JSON.parse(jsonKeys);
      if (typeof parsed === "string") return parsed;
      if (parsed?.default) return String(parsed.default);
      const first = Object.values(parsed ?? {}).find((v) => typeof v === "string");
      if (first) return String(first);
    } catch {
      // Fall through to legacy secret names.
    }
  }
  return Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ||
    Deno.env.get("SUPABASE_SECRET_KEY") || "";
}

function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function decryptCredentials(ciphertext: string, iv: string): Promise<{ accountId: string; apiToken: string }> {
  const secret = Deno.env.get("AI_KEY_ENCRYPTION_SECRET") || "";
  if (secret.length < 32) throw new Error("AI_KEY_ENCRYPTION_SECRET is missing or too short.");
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(secret));
  const key = await crypto.subtle.importKey("raw", digest, { name: "AES-GCM" }, false, ["decrypt"]);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToBytes(iv) },
    key,
    base64ToBytes(ciphertext),
  );
  const parsed = JSON.parse(new TextDecoder().decode(plain));
  if (!/^[a-f0-9]{32}$/i.test(String(parsed.accountId || "")) || typeof parsed.apiToken !== "string") {
    throw new Error("Saved Cloudflare credentials are invalid.");
  }
  return { accountId: parsed.accountId, apiToken: parsed.apiToken };
}

function safeImageDimensions(width: unknown, height: unknown): { width: number; height: number } {
  const w = Number(width);
  const h = Number(height);
  const valid = (n: number) => Number.isInteger(n) && n >= 256 && n <= 1920;
  return {
    width: valid(w) ? w : 1024,
    height: valid(h) ? h : 1024,
  };
}

Deno.serve(async (request: Request) => {
  const origin = request.headers.get("origin");
  if (request.method === "OPTIONS") return new Response("ok", { headers: corsHeaders(origin) });
  if (request.method !== "POST") return json({ error: "Only POST requests are supported." }, 405, origin);
  if (!origin || !ALLOWED_ORIGINS.has(origin)) return json({ error: "This website origin is not allowed." }, 403, origin);

  // Supabase publishable keys are public identifiers, not user authentication.
  // The origin allowlist is a browser boundary, not a substitute for rate limiting.
  const apikey = request.headers.get("apikey") || "";
  if (!apikey) return json({ error: "Supabase publishable key is required." }, 401, origin);

  let body: {
    prompt?: string;
    clientId?: string;
    image_b64?: string;
    outputWidth?: number;
    outputHeight?: number;
  };
  try {
    body = await request.json();
  } catch {
    return json({ error: "Request body must be valid JSON." }, 400, origin);
  }

  const prompt = String(body?.prompt || "").trim();
  if (prompt.length < 5 || prompt.length > MAX_PROMPT_LENGTH) {
    return json({ error: "Enter a prompt between 5 and 1,500 characters." }, 400, origin);
  }

  const imageB64 = typeof body.image_b64 === "string" ? body.image_b64.trim() : "";
  if (imageB64.length > Math.ceil(MAX_IMAGE_BYTES * 4 / 3) + 16) {
    return json({ error: "Reference photo is too large. Choose a smaller image." }, 413, origin);
  }

  const supabaseUrl = Deno.env.get("SUPABASE_URL") || "";
  const secretKey = getSecretKey();
  if (!supabaseUrl || !secretKey) {
    return json({ error: "Supabase server configuration is missing." }, 503, origin);
  }

  const admin = createClient(supabaseUrl, secretKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });

  const { data: saved, error: readError } = await admin
    .from("ai_provider_secrets")
    .select("ciphertext,iv")
    .eq("provider", PROVIDER)
    .maybeSingle();

  if (readError) {
    console.error("Cloudflare credential lookup failed:", readError.message);
    return json({ error: "Could not read the saved AI provider configuration." }, 503, origin);
  }
  if (!saved?.ciphertext || !saved?.iv) {
    return json({ error: "Cloudflare Workers AI is not configured. Ask the website owner to save API 2 credentials." }, 503, origin);
  }

  let credentials: { accountId: string; apiToken: string };
  try {
    credentials = await decryptCredentials(saved.ciphertext, saved.iv);
  } catch (error) {
    console.error("Cloudflare credential decryption failed:", error instanceof Error ? error.message : "unknown error");
    return json({ error: "Could not unlock saved Cloudflare credentials. The encryption secret may have changed." }, 503, origin);
  }

  const dimensions = safeImageDimensions(body.outputWidth, body.outputHeight);
  const model = imageB64 ? EDIT_MODEL : TEXT_MODEL;
  const endpoint = `https://api.cloudflare.com/client/v4/accounts/${credentials.accountId}/ai/run/${model}`;

  let cloudflareResponse: Response;
  try {
    const headers = { Authorization: `Bearer ${credentials.apiToken}` };

    if (imageB64) {
      const imageBytes = base64ToBytes(imageB64);
      if (imageBytes.byteLength > MAX_IMAGE_BYTES) {
        return json({ error: "Reference photo is too large. Choose a smaller image." }, 413, origin);
      }
      const form = new FormData();
      form.append("prompt", prompt);
      form.append("input_image_0", new Blob([imageBytes], { type: "image/jpeg" }), "reference.jpg");
      form.append("width", String(dimensions.width));
      form.append("height", String(dimensions.height));
      cloudflareResponse = await fetch(endpoint, { method: "POST", headers, body: form });
    } else {
      cloudflareResponse = await fetch(endpoint, {
        method: "POST",
        headers: { ...headers, "Content-Type": "application/json" },
        body: JSON.stringify({ prompt, steps: 4 }),
      });
    }
  } catch (error) {
    console.error("Cloudflare request failed:", error instanceof Error ? error.message : "network error");
    return json({ error: "Could not connect to Cloudflare Workers AI. Please try again." }, 502, origin);
  }

  const result = await cloudflareResponse.json().catch(() => null);
  if (!cloudflareResponse.ok || result?.success === false) {
    const providerMessage = Array.isArray(result?.errors)
      ? result.errors.map((e: { message?: string }) => e?.message).filter(Boolean).join("; ")
      : "";
    console.error("Cloudflare Workers AI returned an error:", providerMessage || cloudflareResponse.status);
    return json({
      error: providerMessage
        ? `Cloudflare AI error: ${providerMessage.slice(0, 300)}`
        : `Cloudflare Workers AI request failed (HTTP ${cloudflareResponse.status}). Check token permissions and Workers AI availability.`,
    }, cloudflareResponse.status >= 500 ? 502 : 400, origin);
  }

  const image = result?.result?.image || result?.image;
  if (typeof image !== "string" || image.length < 100) {
    console.error("Cloudflare response did not contain an image.");
    return json({ error: "Cloudflare returned no image. Please try again." }, 502, origin);
  }

  return json({ b64_json: image, mime_type: "image/jpeg" }, 200, origin);
});

/**
 * cfmail 兼容的简单 token 签发/验证
 * 使用 HMAC-SHA256，兼容 Cloudflare Workers edge runtime
 */

interface TokenPayload {
  emailId: string
  address: string
}

function base64url(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf)
  let s = ""
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

function base64urlDecode(s: string): Uint8Array {
  s = s.replace(/-/g, "+").replace(/_/g, "/")
  while (s.length % 4) s += "="
  const raw = atob(s)
  const buf = new Uint8Array(raw.length)
  for (let i = 0; i < raw.length; i++) buf[i] = raw.charCodeAt(i)
  return buf
}

async function getKey(secret: string): Promise<CryptoKey> {
  const enc = new TextEncoder()
  return crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  )
}

export async function signToken(payload: TokenPayload, secret: string): Promise<string> {
  const key = await getKey(secret)
  const data = JSON.stringify(payload)
  const enc = new TextEncoder()
  const dataB64 = base64url(enc.encode(data).buffer as ArrayBuffer)
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(dataB64))
  const sigB64 = base64url(sig)
  return `${dataB64}.${sigB64}`
}

export async function verifyToken(token: string, secret: string): Promise<TokenPayload | null> {
  try {
    const [dataB64, sigB64] = token.split(".")
    if (!dataB64 || !sigB64) return null

    const key = await getKey(secret)
    const enc = new TextEncoder()
    const valid = await crypto.subtle.verify(
      "HMAC",
      key,
      base64urlDecode(sigB64),
      enc.encode(dataB64)
    )
    if (!valid) return null

    const decoded = new TextDecoder().decode(base64urlDecode(dataB64))
    return JSON.parse(decoded) as TokenPayload
  } catch {
    return null
  }
}

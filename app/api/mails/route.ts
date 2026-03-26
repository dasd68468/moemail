import { NextResponse } from "next/server"
import { createDb } from "@/lib/db"
import { emails, messages } from "@/lib/schema"
import { eq, desc } from "drizzle-orm"
import { getRequestContext } from "@cloudflare/next-on-pages"
import { verifyToken } from "@/lib/cfmail-token"

export const runtime = "edge"

/**
 * cfmail 兼容接口 — 拉取邮件
 * GET /api/mails?limit=10&offset=0
 * Headers: Authorization: Bearer {jwt}
 * Returns: { results: [{ address, raw, metadata }] }
 */
export async function GET(request: Request) {
  const env = getRequestContext().env

  // 1. 验证 JWT
  const authHeader = request.headers.get("Authorization") || ""
  const token = authHeader.replace(/^Bearer\s+/i, "").trim()

  const secret = await env.SITE_CONFIG.get("CFMAIL_ADMIN_PASSWORD")
  if (!secret || !token) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
  }

  const payload = await verifyToken(token, secret)
  if (!payload) {
    return NextResponse.json({ error: "Invalid token" }, { status: 401 })
  }

  try {
    const url = new URL(request.url)
    const limit = Math.min(parseInt(url.searchParams.get("limit") || "10"), 50)
    const offset = parseInt(url.searchParams.get("offset") || "0")

    const db = createDb()

    // 2. 确认邮箱存在
    const email = await db.query.emails.findFirst({
      where: eq(emails.id, payload.emailId),
    })
    if (!email) {
      return NextResponse.json({ results: [] })
    }

    // 3. 查询消息
    const msgs = await db.query.messages.findMany({
      where: eq(messages.emailId, payload.emailId),
      orderBy: [desc(messages.receivedAt)],
      limit,
      offset,
    })

    // 4. 转换为 cfmail 格式
    const results = msgs.map((msg) => {
      // 构建类似 raw email 的内容，包含关键信息
      const rawParts = [
        `From: ${msg.fromAddress || "unknown"}`,
        `To: ${email.address}`,
        `Subject: ${msg.subject || "(no subject)"}`,
        `Date: ${msg.receivedAt?.toISOString() || ""}`,
        "",
        msg.html || msg.content || "",
      ]

      return {
        address: email.address,
        raw: rawParts.join("\n"),
        metadata: {
          id: msg.id,
          from: msg.fromAddress,
          to: email.address,
          subject: msg.subject,
          date: msg.receivedAt?.toISOString(),
        },
      }
    })

    return NextResponse.json({ results })
  } catch (error) {
    console.error("cfmail mails error:", error)
    return NextResponse.json({ error: "Failed to fetch mails" }, { status: 500 })
  }
}

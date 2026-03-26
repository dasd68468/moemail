import { NextResponse } from "next/server"
import { nanoid } from "nanoid"
import { createDb } from "@/lib/db"
import { emails } from "@/lib/schema"
import { eq, sql } from "drizzle-orm"
import { getRequestContext } from "@cloudflare/next-on-pages"
import { signToken } from "@/lib/cfmail-token"

export const runtime = "edge"

/**
 * cfmail 兼容接口 — 创建临时邮箱
 * POST /api/new_address
 * Headers: Authorization: Bearer {admin_password}
 * Body: { name?: string, domain?: string }
 * Returns: { address: string, jwt: string }
 */
export async function POST(request: Request) {
  const env = getRequestContext().env

  // 1. 验证 admin 密码
  const authHeader = request.headers.get("Authorization") || ""
  const bearerToken = authHeader.replace(/^Bearer\s+/i, "").trim()

  const adminPassword = await env.SITE_CONFIG.get("CFMAIL_ADMIN_PASSWORD")
  if (!adminPassword || bearerToken !== adminPassword) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
  }

  try {
    const body = await request.json<{ name?: string; domain?: string }>()
    const name = body.name || nanoid(8)

    // 2. 获取域名
    const domainString = await env.SITE_CONFIG.get("EMAIL_DOMAINS")
    const domains = domainString ? domainString.split(",") : []
    const domain = body.domain && domains.includes(body.domain)
      ? body.domain
      : domains[0]

    if (!domain) {
      return NextResponse.json({ error: "No email domain configured" }, { status: 500 })
    }

    const address = `${name}@${domain}`

    // 3. 检查重复
    const db = createDb()
    const existing = await db.query.emails.findFirst({
      where: eq(sql`LOWER(${emails.address})`, address.toLowerCase()),
    })
    if (existing) {
      // 地址已存在，直接返回（幂等）
      const secret = adminPassword
      const jwt = await signToken({ emailId: existing.id, address: existing.address }, secret)
      return NextResponse.json({ address: existing.address, jwt })
    }

    // 4. 创建邮箱（默认 1 小时过期）
    const now = new Date()
    const expiresAt = new Date(now.getTime() + 3600_000)

    // 找到第一个可用 userId（admin 用户），如果没有则设为 null
    const result = await db.insert(emails).values({
      address,
      createdAt: now,
      expiresAt,
      userId: null as any,
    }).returning({ id: emails.id, address: emails.address })

    const emailId = result[0].id
    const emailAddress = result[0].address

    // 5. 签发 token
    const secret = adminPassword
    const jwt = await signToken({ emailId, address: emailAddress }, secret)

    return NextResponse.json({ address: emailAddress, jwt })
  } catch (error) {
    console.error("cfmail new_address error:", error)
    return NextResponse.json({ error: "Failed to create email" }, { status: 500 })
  }
}

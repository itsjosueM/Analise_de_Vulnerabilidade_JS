export const redirectAllowlist = new Set([
  'https:
  'http:
  'http:
  'https:
  'http:
])

export const isRedirectAllowed = (url: string) => {
  let allowed = false
  for (const allowedUrl of redirectAllowlist) {
    allowed = allowed || url.includes(allowedUrl)
  }
  return allowed
}
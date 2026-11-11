import crypto from 'node:crypto';
import { next } from '@vercel/functions';

// O cookie é validado no servidor com a mesma HMAC SHA-256 das APIs.
const COOKIE_MAIN = 'lab_main_session';
function sessionAuthorized(request) {
  const secret = process.env.SESSION_SECRET;
  if (!secret || secret.length < 32) return false;
  const raw = request.headers.get('cookie') || '';
  const part = raw.split(';').map(x=>x.trim()).find(x=>x.startsWith(COOKIE_MAIN+'='));
  if (!part) return false;
  const token = part.slice(COOKIE_MAIN.length+1);
  const parts = token.split('.');
  if (parts.length !== 2 || !parts[0] || !parts[1]) return false;
  const [body, signature] = parts;
  const expected = crypto.createHmac('sha256',secret).update(body).digest('base64url');
  const a=Buffer.from(signature), b=Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a,b)) return false;
  try {
    const data=JSON.parse(Buffer.from(body,'base64url').toString('utf8'));
    return data.scope === 'main' && Number.isFinite(data.exp) && data.exp > Date.now();
  } catch { return false; }
}
export const config = {
  runtime: 'nodejs',
  matcher: ['/', '/index.html', '/login.html'],
};
export default function middleware(request) {
  const pathname=new URL(request.url).pathname;
  const authorized=sessionAuthorized(request);
  if (pathname==='/login.html') {
    return authorized?Response.redirect(new URL('/',request.url),302):next();
  }
  return authorized?next():Response.redirect(new URL('/login.html',request.url),302);
}

import crypto from 'node:crypto';

const COOKIE_MAIN = 'lab_main_session';
const COOKIE_REPORT = 'lab_report_session';
const maxAgeMain=60*60*8;
const maxAgeReport=60*60*2;

function secret(){
 const s=process.env.SESSION_SECRET;
 if(!s||s.length<32)throw new Error('SESSION_SECRET ausente ou muito curto (mínimo 32 caracteres).');
 return s;
}
function digest(v){return crypto.createHmac('sha256',secret()).update(v).digest('base64url')}
function equal(a,b){
 const aa=Buffer.from(String(a||'')); const bb=Buffer.from(String(b||''));
 return aa.length===bb.length && crypto.timingSafeEqual(aa,bb);
}
function getCookies(req){
 const obj={}; const raw=req.headers.cookie||'';
 for(const part of raw.split(';')){
  const pos=part.indexOf('=');if(pos<0)continue;
  const k=part.slice(0,pos).trim(),v=part.slice(pos+1).trim();
  if(k)obj[k]=v;
 }
 return obj;
}
function token(scope,ttl){
 const body=Buffer.from(JSON.stringify({scope,exp:Date.now()+ttl*1000,nonce:crypto.randomBytes(16).toString('hex')})).toString('base64url');
 return `${body}.${digest(body)}`;
}
function valid(value,scope){
 if(!value||typeof value!=='string')return false;
 const [data,sig,extra]=value.split('.');
 if(!data||!sig||extra||!equal(digest(data),sig))return false;
 try{const x=JSON.parse(Buffer.from(data,'base64url').toString('utf8'));return x.scope===scope&&Number.isFinite(x.exp)&&x.exp>Date.now()}
 catch{return false}
}
function cookie(name,value,age){
 return `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${age}`;
}
export function setSession(res,scope){
 if(scope==='main')res.setHeader('Set-Cookie',[cookie(COOKIE_MAIN,token(scope,maxAgeMain),maxAgeMain),cookie(COOKIE_REPORT,'',0)]);
 else res.setHeader('Set-Cookie',cookie(COOKIE_REPORT,token(scope,maxAgeReport),maxAgeReport));
}
export function clearSessions(res){
 res.setHeader('Set-Cookie',[cookie(COOKIE_MAIN,'',0),cookie(COOKIE_REPORT,'',0)]);
}
export function hasMain(req){return valid(getCookies(req)[COOKIE_MAIN],'main')}
export function hasReport(req){return hasMain(req)&&valid(getCookies(req)[COOKIE_REPORT],'report')}
export function verifyPassword(input,envName){
 const env=process.env[envName];
 if(!env||env.length<8)throw new Error(`Senha do servidor não configurada: ${envName}`);
 // Comparação em tamanho fixo para evitar diferenças de tempo por comprimento.
 const a=crypto.createHash('sha256').update(String(input||''),'utf8').digest();
 const b=crypto.createHash('sha256').update(env,'utf8').digest();
 return crypto.timingSafeEqual(a,b);
}
export function json(res,status,body){res.setHeader('Cache-Control','no-store');res.setHeader('Content-Type','application/json; charset=utf-8');return res.status(status).json(body)}
export function sameOrigin(req){
 const origin=req.headers.origin;if(!origin)return true;
 const scheme=(req.headers['x-forwarded-proto']||'https').split(',')[0];
 const host=(req.headers['x-forwarded-host']||req.headers.host||'').split(',')[0];
 try{return new URL(origin).origin===`${scheme}://${host}`}catch{return false}
}
export function rejectCrossOrigin(req,res){if(sameOrigin(req))return false;json(res,403,{erro:'Origem não permitida.'});return true}

import crypto from 'node:crypto';
import {db} from './_lib/database.js';
import {json,hasMain,hasReport,rejectCrossOrigin} from './_lib/security.js';

// PDFs moderados dentro do Neon, sem bucket externo nem credenciais adicionais.
// O limite evita exceder o payload de funções da Vercel e crescimento excessivo do banco.
// JSON em base64 tem cerca de 33% a mais que o PDF original.
export const config={api:{bodyParser:{sizeLimit:'3mb'}}};
const MAX_PDF_BYTES=2*1024*1024;
const MAX_DOCUMENTS=80;
const MAX_TOTAL_BYTES=48*1024*1024;

async function ensureTable(sql){
 await sql`CREATE TABLE IF NOT EXISTS public.lab_documents (
  id text PRIMARY KEY,
  title text NOT NULL,
  category text NOT NULL,
  code text NOT NULL DEFAULT '',
  revision text NOT NULL DEFAULT '',
  description text NOT NULL DEFAULT '',
  filename text NOT NULL,
  bytes integer NOT NULL,
  sha256 text NOT NULL,
  content bytea NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
 )`;
}
function clean(v,max){return String(v??'').trim().slice(0,max)}
function isPdf(data){
 return data.length>=12 && data.subarray(0,5).toString('ascii')==='%PDF-' &&
 data.subarray(Math.max(0,data.length-2048)).toString('latin1').includes('%%EOF');
}
const categories=new Set(['Norma técnica','Datasheet','Procedimento','Manual','Especificação','Outros']);
function validateMetadata(body){
 const title=clean(body?.title,160);
 if(title.length<3)throw Error('Informe um título de pelo menos três caracteres.');
 const category=clean(body?.category,40);
 if(!categories.has(category))throw Error('Categoria não reconhecida.');
 return {title,category,code:clean(body?.code,80),revision:clean(body?.revision,60),description:clean(body?.description,900)};
}
export default async function handler(req,res){
 if(!hasMain(req))return json(res,401,{erro:'Faça login para consultar a Biblioteca Técnica.'});
 if(!['GET','POST','PATCH','DELETE'].includes(req.method)){
  res.setHeader('Allow','GET, POST, PATCH, DELETE');return json(res,405,{erro:'Método não permitido.'});
 }
 if(req.method!=='GET'){
  if(!hasReport(req))return json(res,403,{erro:'A mesma senha das áreas 01 e 02 é necessária para gerenciar os PDFs.'});
  if(rejectCrossOrigin(req,res))return;
 }
 try{
  const sql=db();await ensureTable(sql);
  if(req.method==='GET'){
   const rows=await sql`SELECT id,title,category,code,revision,description,filename,bytes,created_at,updated_at
      FROM public.lab_documents ORDER BY updated_at DESC, title ASC`;
   return json(res,200,{documents:rows,canManage:hasReport(req),limitBytes:MAX_PDF_BYTES});
  }
  if(req.method==='POST'){
   const meta=validateMetadata(req.body);
   const b64=String(req.body?.contentBase64||'');
   if(!b64||b64.length>Math.ceil(MAX_PDF_BYTES*4/3)+20||!/^[A-Za-z0-9+/]+={0,2}$/.test(b64))
    return json(res,413,{erro:'Arquivo inválido ou superior a 2 MB.'});
   const data=Buffer.from(b64,'base64');
   if(data.length>MAX_PDF_BYTES||!isPdf(data))return json(res,400,{erro:'Selecione um PDF válido de até 2 MB.'});
   const count=await sql`SELECT count(*)::int as n, COALESCE(sum(bytes),0)::int as total FROM public.lab_documents`;
   if(count[0].n>=MAX_DOCUMENTS||count[0].total+data.length>MAX_TOTAL_BYTES)
    return json(res,413,{erro:'Limite da biblioteca atingido (80 PDFs ou 48 MB). Remova documentos antigos.'});
   const id=crypto.randomUUID();
   const filename=clean(req.body.filename,160).replace(/[\\/\x00-\x1f]/g,'_')||'documento.pdf';
   const sha256=crypto.createHash('sha256').update(data).digest('hex');
   await sql`INSERT INTO public.lab_documents(id,title,category,code,revision,description,filename,bytes,sha256,content)
    VALUES(${id},${meta.title},${meta.category},${meta.code},${meta.revision},${meta.description},${filename},${data.length},${sha256},decode(${b64},'base64'))`;
   return json(res,201,{ok:true,id});
  }
  const id=clean(req.body?.id,90);
  if(!/^[0-9a-f]{8}-[0-9a-f-]{27,}$/.test(id))return json(res,400,{erro:'Documento inválido.'});
  if(req.method==='PATCH'){
   const m=validateMetadata(req.body);
   const r=await sql`UPDATE public.lab_documents SET title=${m.title},category=${m.category},code=${m.code},revision=${m.revision},description=${m.description},updated_at=now() WHERE id=${id} RETURNING id`;
   return r.length?json(res,200,{ok:true}):json(res,404,{erro:'PDF não encontrado.'});
  }
  const r=await sql`DELETE FROM public.lab_documents WHERE id=${id} RETURNING id`;
  return r.length?json(res,200,{ok:true}):json(res,404,{erro:'PDF não encontrado.'});
 }catch(e){
  if(e.message?.startsWith('Informe um título')||e.message==='Categoria não reconhecida.')return json(res,400,{erro:e.message});
  console.error('Biblioteca BCMS95',e);
  return json(res,500,{erro:'Não foi possível acessar a biblioteca. Verifique a conexão e as permissões de criação da tabela no Neon.'});
 }
}

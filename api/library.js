import crypto from 'node:crypto';
import {db} from './_lib/database.js';
import {json,hasMain,hasReport,rejectCrossOrigin} from './_lib/security.js';

// PDFs moderados dentro do Neon, sem bucket externo nem credenciais adicionais.
// O limite evita exceder o payload de funções da Vercel e crescimento excessivo do banco.
// JSON em base64 tem cerca de 33% a mais que o PDF original.
export const config={api:{bodyParser:{sizeLimit:'1.5mb'}}};
const MAX_PDF_BYTES=10*1024*1024;
const CHUNK_BYTES=512*1024;
const MAX_DOCUMENTS=80;
const MAX_TOTAL_BYTES=160*1024*1024;

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
 await sql`ALTER TABLE public.lab_documents ADD COLUMN IF NOT EXISTS upload_state text NOT NULL DEFAULT 'ready'`;
 await sql`ALTER TABLE public.lab_documents ADD COLUMN IF NOT EXISTS expected_bytes integer NOT NULL DEFAULT 0`;
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
      FROM public.lab_documents WHERE upload_state='ready' ORDER BY updated_at DESC, title ASC`;
   return json(res,200,{documents:rows,canManage:hasReport(req),limitBytes:MAX_PDF_BYTES});
  }
  if(req.method==='POST'){
   const action=clean(req.body?.action,20);
   if(action==='begin'){
    const meta=validateMetadata(req.body);
    const expectedBytes=Number(req.body?.expectedBytes);
    if(!Number.isInteger(expectedBytes)||expectedBytes<12||expectedBytes>MAX_PDF_BYTES)
     return json(res,413,{erro:'Selecione um PDF válido de até 10 MB.'});
    await sql`DELETE FROM public.lab_documents WHERE upload_state='uploading' AND created_at < now()-interval '2 hours'`;
    const count=await sql`SELECT count(*)::int as n, COALESCE(sum(GREATEST(bytes,expected_bytes)),0)::bigint as total FROM public.lab_documents`;
    if(count[0].n>=MAX_DOCUMENTS||Number(count[0].total)+expectedBytes>MAX_TOTAL_BYTES)
     return json(res,413,{erro:'Capacidade da biblioteca atingida (80 PDFs ou 160 MB).'});
    const id=crypto.randomUUID();
    const filename=clean(req.body?.filename,160).replace(/[\\/\x00-\x1f]/g,'_')||'documento.pdf';
    await sql`INSERT INTO public.lab_documents
     (id,title,category,code,revision,description,filename,bytes,expected_bytes,sha256,content,upload_state)
     VALUES(${id},${meta.title},${meta.category},'','','',${filename},0,${expectedBytes},'',decode('','hex'),'uploading')`;
    return json(res,201,{id});
   }
   const id=clean(req.body?.id,90);
   if(!/^[0-9a-f]{8}-[0-9a-f-]{27,}$/.test(id))return json(res,400,{erro:'Identificação do PDF inválida.'});
   if(action==='chunk'){
    const offset=Number(req.body?.offset);
    const b64=String(req.body?.contentBase64||'');
    if(!Number.isInteger(offset)||offset<0||offset>MAX_PDF_BYTES||
       !b64||b64.length>Math.ceil(CHUNK_BYTES*4/3)+20||!/^[A-Za-z0-9+/]+={0,2}$/.test(b64))
     return json(res,413,{erro:'Parte do PDF inválida ou muito grande.'});
    const part=Buffer.from(b64,'base64');
    if(!part.length||part.length>CHUNK_BYTES)return json(res,413,{erro:'Parte do PDF excede o limite.'});
    const next=offset+part.length;
    const row=await sql`UPDATE public.lab_documents
     SET content=content || decode(${b64},'base64'),bytes=${next},updated_at=now()
     WHERE id=${id} AND upload_state='uploading' AND bytes=${offset} AND expected_bytes>=${next}
     RETURNING id`;
    return row.length?json(res,200,{ok:true,bytes:next}):json(res,409,{erro:'Envio interrompido ou partes fora de ordem. Tente novamente.'});
   }
   if(action==='finish'){
    const rows=await sql`SELECT encode(content,'base64') AS base64,bytes,expected_bytes
      FROM public.lab_documents WHERE id=${id} AND upload_state='uploading' LIMIT 1`;
    if(!rows.length)return json(res,404,{erro:'Envio não encontrado.'});
    if(rows[0].bytes!==rows[0].expected_bytes)return json(res,409,{erro:'PDF incompleto. Envie novamente.'});
    const buffer=Buffer.from(rows[0].base64,'base64');
    if(!isPdf(buffer)){
     await sql`DELETE FROM public.lab_documents WHERE id=${id} AND upload_state='uploading'`;
     return json(res,400,{erro:'O arquivo não é um PDF válido.'});
    }
    const sha256=crypto.createHash('sha256').update(buffer).digest('hex');
    await sql`UPDATE public.lab_documents SET upload_state='ready',sha256=${sha256},updated_at=now() WHERE id=${id} AND upload_state='uploading'`;
    return json(res,201,{ok:true,id});
   }
   return json(res,400,{erro:'Operação de envio não reconhecida.'});
  }
  const id=clean(req.body?.id,90);
  if(!/^[0-9a-f]{8}-[0-9a-f-]{27,}$/.test(id))return json(res,400,{erro:'Documento inválido.'});
  if(req.method==='PATCH'){
   const m=validateMetadata(req.body);
   const r=await sql`UPDATE public.lab_documents SET title=${m.title},category=${m.category},code=${m.code},revision=${m.revision},description=${m.description},updated_at=now() WHERE id=${id} AND upload_state='ready' RETURNING id`;
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

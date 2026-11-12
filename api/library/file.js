import {db} from '../_lib/database.js';
import {json,hasMain} from '../_lib/security.js';

export default async function handler(req,res){
 if(!hasMain(req))return json(res,401,{erro:'Acesso não autorizado.'});
 if(req.method!=='GET'){
  res.setHeader('Allow','GET');return json(res,405,{erro:'Método não permitido.'});
 }
 const id=String(req.query?.id||'');
 const part=Number(req.query?.part);
 if(!Number.isInteger(part)||part<0||part>19)return json(res,400,{erro:'Parte inválida.'});
 if(!/^[0-9a-f]{8}-[0-9a-f-]{27,}$/.test(id))return json(res,400,{erro:'Documento inválido.'});
 try{
  const sql=db();
  const start=part*512*1024+1;
  const rows=await sql`SELECT encode(substring(content from ${start} for 524288),'base64') AS base64,filename,bytes
   FROM public.lab_documents WHERE id=${id} AND upload_state='ready' LIMIT 1`;
  if(!rows.length)return json(res,404,{erro:'Documento não encontrado.'});
  if(start>rows[0].bytes)return json(res,416,{erro:'Parte além do final do PDF.'});
  const bytes=Buffer.from(rows[0].base64,'base64');
  const filename=String(rows[0].filename||'documento.pdf').replace(/["\\\r\n]/g,'_').replace(/[^\x20-\x7E]/g,'_');
  res.setHeader('Content-Type','application/octet-stream');
  res.setHeader('Content-Disposition',`attachment; filename="${filename}"`);
  res.setHeader('Content-Length',String(bytes.length));
  res.setHeader('Cache-Control','private, no-store, max-age=0');
  res.setHeader('X-Content-Type-Options','nosniff');
  res.setHeader('X-Frame-Options','SAMEORIGIN');
  return res.status(200).send(bytes);
 }catch(e){console.error('PDF BCMS95',e);return json(res,500,{erro:'Falha na leitura do PDF armazenado.'})}
}

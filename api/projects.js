import {db} from './_lib/database.js';
import {json,hasMain,hasReport,rejectCrossOrigin} from './_lib/security.js';

const maxBytes=1500000;
const protectedData=(p)=>Array.isArray(p.notes)&&p.notes.length || Array.isArray(p.signatures)&&p.signatures.length;

export default async function handler(req,res){
 if(!hasMain(req))return json(res,401,{erro:'Acesso não autorizado. Faça login novamente.'});
 if(!hasReport(req))return json(res,403,{erro:'Digite a senha adicional das áreas 01 e 02 para acessar os projetos.'});
 if(!['GET','PUT'].includes(req.method)){
  res.setHeader('Allow','GET, PUT');return json(res,405,{erro:'Método não permitido.'});
 }
 if(req.method==='PUT'&&rejectCrossOrigin(req,res))return;
 try{
  const sql=db();
  const rows=await sql`SELECT revision, data FROM public.lab_workspace WHERE id='principal' LIMIT 1`;
  const revision=rows.length?Number(rows[0].revision):0;
  const stored=rows.length&&Array.isArray(rows[0].data)?rows[0].data:[];
  const report=hasReport(req);
  if(req.method==='GET'){
   // A segunda senha protege as observações manuais e assinaturas também na API,
   // não somente na interface. O conversor acessa dados de identificação e conversões.
   const visible=report?stored:stored.map(p=>({...p,notes:[],signatures:[]}));
   return json(res,200,{revision,projects:visible});
  }
  const {revision:clientRevision,projects}=req.body||{};
  if(!Number.isInteger(clientRevision)||clientRevision<0||!Array.isArray(projects))
   return json(res,400,{erro:'Dados inválidos.'});
  if(projects.length>500)return json(res,413,{erro:'Limite de 500 projetos por área de trabalho.'});
  if(projects.some(p=>!p||typeof p!=='object'||typeof p.id!=='string'||typeof p.name!=='string'||!Array.isArray(p.conversions)||!Array.isArray(p.notes)||!Array.isArray(p.signatures)))
   return json(res,400,{erro:'Estrutura de projeto inválida.'});
  if(clientRevision!==revision)return json(res,409,{erro:'Outro dispositivo modificou os registros. Faça um backup e recarregue antes de continuar.'});
  let incoming=projects;
  if(!report){
   const byId=new Map(stored.map(p=>[p.id,p]));
   const submitted=new Set(projects.map(p=>p.id));
   // Impede a exclusão silenciosa de dados do relatório por alguém sem sua senha.
   if(stored.some(p=>!submitted.has(p.id)&&protectedData(p)))
    return json(res,403,{erro:'Este projeto contém dados de relatório. Desbloqueie Relatório Tapeboard para excluí-lo.'});
   incoming=projects.map(p=>{
    const old=byId.get(p.id);
    return {...p,notes:old?.notes||[],signatures:old?.signatures||[]};
   });
  }
  if(Buffer.byteLength(JSON.stringify(incoming),'utf8')>maxBytes)
   return json(res,413,{erro:'O limite de 1,5 MB foi ultrapassado. Exporte um backup e revise os registros.'});
  const saved=await sql`INSERT INTO public.lab_workspace (id, revision, data, updated_at)
    VALUES ('principal', 1, ${JSON.stringify(incoming)}::jsonb, now())
    ON CONFLICT (id) DO UPDATE SET revision=public.lab_workspace.revision+1,
      data=EXCLUDED.data, updated_at=now()
    WHERE public.lab_workspace.revision=${clientRevision}
    RETURNING revision`;
  if(!saved.length)return json(res,409,{erro:'Dados alterados em outra sessão. Não foram sobrescritos.'});
  return json(res,200,{ok:true,revision:Number(saved[0].revision)});
 }catch(e){
  console.error('LAB projects',e);
  return json(res,500,{erro:'Falha de acesso ao banco. Verifique DATABASE_URL e a tabela lab_workspace.'});
 }
}

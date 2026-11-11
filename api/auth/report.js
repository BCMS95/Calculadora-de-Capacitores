import {json,hasMain,verifyPassword,setSession,rejectCrossOrigin} from '../_lib/security.js';
export default async function handler(req,res){
 if(req.method!=='POST'){res.setHeader('Allow','POST');return json(res,405,{erro:'Método não permitido.'})}
 if(rejectCrossOrigin(req,res))return;
 if(!hasMain(req))return json(res,401,{erro:'Sessão expirada. Entre novamente.'});
 try{
  if(!verifyPassword(req.body?.password,'LAB_REPORT_PASSWORD'))return json(res,401,{erro:'Senha do relatório incorreta.'});
  setSession(res,'report');return json(res,200,{ok:true});
 }catch(e){console.error('report auth',e);return json(res,500,{erro:'Autenticação indisponível.'})}
}

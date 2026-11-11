import {json,verifyPassword,setSession,rejectCrossOrigin} from '../_lib/security.js';
export default async function handler(req,res){
 if(req.method!=='POST'){res.setHeader('Allow','POST');return json(res,405,{erro:'Método não permitido.'})}
 if(rejectCrossOrigin(req,res))return;
 try{
  if(!verifyPassword(req.body?.password,'LAB_MAIN_PASSWORD'))return json(res,401,{erro:'Senha não reconhecida.'});
  setSession(res,'main');return json(res,200,{ok:true});
 }catch(e){console.error('login',e);return json(res,500,{erro:'Autenticação indisponível. Verifique a configuração do servidor.'})}
}

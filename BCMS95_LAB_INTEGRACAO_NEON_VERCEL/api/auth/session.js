import {json,hasMain,hasReport} from '../_lib/security.js';
export default function handler(req,res){
 if(req.method!=='GET'){res.setHeader('Allow','GET');return json(res,405,{erro:'Método não permitido.'})}
 return json(res,200,{authenticated:hasMain(req),report:hasReport(req)});
}

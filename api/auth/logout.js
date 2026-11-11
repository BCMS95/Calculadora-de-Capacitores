import {json,clearSessions,rejectCrossOrigin} from '../_lib/security.js';
export default function handler(req,res){
 if(req.method!=='POST'){res.setHeader('Allow','POST');return json(res,405,{erro:'Método não permitido.'})}
 if(rejectCrossOrigin(req,res))return;
 clearSessions(res);return json(res,200,{ok:true});
}

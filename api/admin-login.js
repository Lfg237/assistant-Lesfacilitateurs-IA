const crypto=require("crypto");
function send(res,status,data){res.status(status).setHeader("Content-Type","application/json; charset=utf-8").end(JSON.stringify(data));}
function sign(payload,secret){const b=Buffer.from(JSON.stringify(payload)).toString("base64url");const s=crypto.createHmac("sha256",secret).update(b).digest("base64url");return b+"."+s;}
module.exports=async(req,res)=>{if(req.method!=="POST")return send(res,405,{error:"Méthode non autorisée"});const code=process.env.ADMIN_CODE,secret=process.env.ADMIN_SESSION_SECRET||process.env.ADMIN_CODE;if(!code)return send(res,500,{error:"La variable Vercel ADMIN_CODE est manquante"});try{const body=typeof req.body==='string'?JSON.parse(req.body||'{}'):(req.body||{});if(String(body.code||'')!==String(code))return send(res,401,{error:"Code administrateur incorrect"});const now=Math.floor(Date.now()/1000),exp=now+28800;const token=sign({role:'admin',iat:now,exp},secret);
  res.setHeader('Set-Cookie', 'lfg_admin_session='+token+'; Path=/; Max-Age=28800; HttpOnly; Secure; SameSite=Lax');
  return send(res,200,{ok:true,expiresAt:exp});}catch(e){return send(res,400,{error:'Requête invalide'});}};

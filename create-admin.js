"use strict";
const {Pool}=require("pg");
const bcrypt=require("bcryptjs");
const crypto=require("crypto");
const DATABASE_URL=process.env.DATABASE_URL;
if(!DATABASE_URL){console.error("DATABASE_URL est obligatoire.");process.exit(1)}
const email=String(process.env.ADMIN_EMAIL||"").trim().toLowerCase();
const password=String(process.env.ADMIN_PASSWORD||"");
const adminName=String(process.env.ADMIN_NAME||"Administrateur DALZON").trim();
if(!email||!email.includes("@")){console.error("ADMIN_EMAIL est obligatoire.");process.exit(1)}
if(password.length<8){console.error("ADMIN_PASSWORD doit contenir au moins 8 caractères.");process.exit(1)}
const pool=new Pool({connectionString:DATABASE_URL,ssl:process.env.NODE_ENV==="production"?{rejectUnauthorized:false}:undefined});
(async()=>{const c=await pool.connect();try{
 await c.query("BEGIN");
 const exists=await c.query("SELECT id,account_id,email FROM users WHERE role='admin' OR email=$1 LIMIT 1",[email]);
 if(exists.rows.length){await c.query("ROLLBACK");console.log("Administrateur ou e-mail déjà existant:",exists.rows[0].account_id,exists.rows[0].email);return}
 let aid;for(;;){aid=`DLZ-${new Date().getFullYear()}-${crypto.randomInt(100000,1000000)}`;if(!(await c.query("SELECT 1 FROM users WHERE account_id=$1",[aid])).rowCount)break}
 const hash=await bcrypt.hash(password,12);
 const u=(await c.query("INSERT INTO users(account_id,name,email,password_hash,role,status) VALUES($1,$2,$3,$4,'admin','active') RETURNING *",[aid,adminName,email,hash])).rows[0];
 const card=[1,2,3,4].map(()=>crypto.randomInt(1000,10000)).join(" ");const d=new Date();d.setFullYear(d.getFullYear()+4);const exp=`${String(d.getMonth()+1).padStart(2,"0")}/${String(d.getFullYear()).slice(-2)}`;
 await c.query("INSERT INTO wallets(user_id) VALUES($1)",[u.id]);await c.query("INSERT INTO cards(user_id,card_number,expiry) VALUES($1,$2,$3)",[u.id,card,exp]);await c.query("COMMIT");
 console.log("ADMIN DALZON CRÉÉ");console.log("Account ID:",u.account_id);console.log("Email:",u.email);
}catch(e){await c.query("ROLLBACK");console.error(e);process.exitCode=1}finally{c.release();await pool.end()}})();

require('dotenv').config();
const express=require('express'),mongoose=require('mongoose'),bcrypt=require('bcryptjs'),jwt=require('jsonwebtoken'),helmet=require('helmet'),rl=require('express-rate-limit'),cookie=require('cookie-parser'),crypto=require('crypto'),QR=require('qrcode'),path=require('path');
const {MONGO_URI,JWT_SECRET}=process.env;
if(!MONGO_URI||!JWT_SECRET||JWT_SECRET.length<32)throw new Error('Set MONGO_URI and a JWT_SECRET of 32+ characters in .env');
const S=mongoose.Schema,M=(n,s)=>mongoose.model(n,new S(s,{timestamps:true}));
const User=M('User',{username:{type:String,unique:true},name:String,role:String,hash:String});
const Visitor=M('Visitor',{name:String,phone:String,email:String,idRef:String});
const Visit=M('Visit',{visitor:{type:S.Types.ObjectId,ref:'Visitor'},host:{type:S.Types.ObjectId,ref:'User'},zone:String,purpose:String,from:Date,until:Date,status:{type:String,default:'PENDING'},tokenHash:String,used:[String],fails:{type:Number,default:0}});
const Audit=M('Audit',{actor:String,action:String,resource:String,result:String,details:String,prev:String,hash:String});
const ZONES={'Reception':0,'Meeting Room A':1,'Training Room':1,'Server Room':2};
const sha=s=>crypto.createHash('sha256').update(s).digest('hex');
const chain=a=>sha(JSON.stringify([a.actor,a.action,a.resource,a.result,a.details,a.prev]));
// Tamper-evident audit log: every entry stores the hash of the previous one
let q=Promise.resolve();
const log=(actor,action,resource,result,details='')=>q=q.then(async()=>{const l=await Audit.findOne().sort({_id:-1});const a={actor,action,resource,result,details,prev:l?l.hash:'GENESIS'};a.hash=chain(a);await Audit.create(a)}).catch(console.error);
const app=express();
app.set('trust proxy',1);
app.use(helmet(),express.json({limit:'10kb'}),cookie(),express.static(path.join(__dirname,'../frontend')));
app.use('/api',rl({windowMs:9e5,max:300}));
// Serverless: wait for pending audit writes before replying, so none are lost when the function freezes
app.use((req,res,next)=>{const j=res.json.bind(res);res.json=b=>{q.then(()=>j(b));return res};next()});
// Serverless: connect once per instance and reuse the connection
let conn;
const db=()=>conn||(conn=mongoose.connect(MONGO_URI,{serverSelectionTimeoutMS:8000}).then(seed).catch(e=>{conn=null;throw e}));
app.use('/api',async(req,res,next)=>{try{await db();next()}catch(e){console.error(e.message);res.status(503).json({error:'Database unavailable'})}});
app.get('/api/health',(req,res)=>res.json({ok:true}));
const bad=(res,m,c=400)=>res.status(c).json({error:m});
const pub=u=>({name:u.name,role:u.role,username:u.username});
const auth=(...roles)=>async(req,res,next)=>{try{const p=jwt.verify(req.cookies.zt,JWT_SECRET);const u=await User.findById(p.id);if(!u)throw 0;if(roles.length&&!roles.includes(u.role))return bad(res,'You do not have access to this',403);req.user=u;next()}catch{bad(res,'Please sign in',401)}};
app.post('/api/login',rl({windowMs:9e5,max:10,message:{error:'Too many attempts. Try again in 15 minutes.'}}),async(req,res)=>{
 const un=String(req.body.username||'').slice(0,30);const u=await User.findOne({username:un});
 if(!u||!await bcrypt.compare(String(req.body.password||'').slice(0,100),u.hash)){log(un,'LOGIN','-','DENY','Wrong credentials');return bad(res,'Wrong username or password',401)}
 res.cookie('zt',jwt.sign({id:u.id},JWT_SECRET,{expiresIn:'2h'}),{httpOnly:true,sameSite:'strict',secure:process.env.NODE_ENV==='production',maxAge:7.2e6});
 log(u.username,'LOGIN','-','SUCCESS');res.json(pub(u))});
app.post('/api/logout',(req,res)=>{res.clearCookie('zt');res.json({ok:1})});
app.get('/api/me',auth(),(req,res)=>res.json({...pub(req.user),zones:Object.keys(ZONES)}));
app.get('/api/hosts',auth('ADMIN'),async(req,res)=>res.json(await User.find({role:'HOST'}).select('name')));
app.get('/api/visitors',auth('ADMIN','HOST'),async(req,res)=>res.json(await Visitor.find().sort({_id:-1})));
app.post('/api/visitors',auth('ADMIN','HOST'),async(req,res)=>{
 const b=req.body,name=String(b.name||'').trim(),phone=String(b.phone||'').trim(),email=String(b.email||'').trim().toLowerCase();let idRef=String(b.idRef||'').trim();
 if(name.length<2||name.length>60)return bad(res,'Name must be 2 to 60 characters');
 if(!/^[6-9]\d{9}$/.test(phone))return bad(res,'Enter a valid 10-digit mobile number');
 if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||email.length>80)return bad(res,'Enter a valid email address');
 if(!idRef)idRef='SYN-ID-'+(1001+await Visitor.countDocuments());
 if(!/^SYN-ID-\d{4,}$/.test(idRef))return bad(res,'ID reference must look like SYN-ID-1003 (never a real ID number)');
 const v=await Visitor.create({name,phone,email,idRef});log(req.user.username,'REGISTER_VISITOR','Visitor '+v.idRef,'SUCCESS');res.json(v)});
app.get('/api/visits',auth('ADMIN','HOST'),async(req,res)=>{
 await Visit.updateMany({status:'APPROVED',until:{$lt:new Date()}},{status:'EXPIRED'});
 const f=req.user.role==='HOST'?{host:req.user._id}:{};
 res.json(await Visit.find(f).sort({_id:-1}).select('-tokenHash -used -fails').populate('visitor','name').populate('host','name'))});
app.post('/api/visits',auth('ADMIN','HOST'),async(req,res)=>{
 const b=req.body,from=new Date(b.from),until=new Date(b.until),purpose=String(b.purpose||'').trim();
 if(!(b.zone in ZONES))return bad(res,'Choose a valid zone');
 if(purpose.length<3||purpose.length>80)return bad(res,'Purpose must be 3 to 80 characters');
 if(isNaN(from)||isNaN(until))return bad(res,'Enter valid start and end times');
 if(until<=from)return bad(res,'End time must be after start time');
 if(until<new Date())return bad(res,'End time is already in the past');
 if(until-from>12*36e5)return bad(res,'A visit pass can be valid for 12 hours at most');
 if(!mongoose.isValidObjectId(b.visitor)||!await Visitor.exists({_id:b.visitor}))return bad(res,'Choose a registered visitor');
 let host=req.user._id;if(req.user.role==='ADMIN'){if(!mongoose.isValidObjectId(b.host)||!await User.exists({_id:b.host,role:'HOST'}))return bad(res,'Choose a host');host=b.host}
 const v=await Visit.create({visitor:b.visitor,host,zone:b.zone,purpose,from,until});log(req.user.username,'CREATE_VISIT','Visit '+v.id.slice(-6),'SUCCESS',b.zone);res.json({ok:1})});
const own=async(req,res,st)=>{if(!mongoose.isValidObjectId(req.params.id))return bad(res,'Not found',404);const v=await Visit.findById(req.params.id);if(!v)return bad(res,'Not found',404);
 if(req.user.role==='HOST'&&!v.host.equals(req.user._id)){log(req.user.username,'ACCESS_OTHER_HOST_VISIT','Visit '+v.id.slice(-6),'DENY');bad(res,'Only the assigned host can do this',403);return}
 if(v.status!==st){bad(res,'This visit is '+v.status.toLowerCase());return}return v};
app.post('/api/visits/:id/approve',auth('ADMIN','HOST'),async(req,res)=>{const v=await own(req,res,'PENDING');if(!v)return;
 if(v.until<new Date()){v.status='EXPIRED';await v.save();return bad(res,'This visit has already ended')}
 const token=crypto.randomBytes(24).toString('hex');v.tokenHash=sha(token);v.status='APPROVED';await v.save(); // only the hash is stored
 log(req.user.username,'APPROVE_VISIT','Visit '+v.id.slice(-6),'SUCCESS','Pass issued');res.json({token,qr:await QR.toDataURL(token,{margin:1,width:240})})});
app.post('/api/visits/:id/reject',auth('ADMIN','HOST'),async(req,res)=>{const v=await own(req,res,'PENDING');if(!v)return;v.status='REJECTED';await v.save();log(req.user.username,'REJECT_VISIT','Visit '+v.id.slice(-6),'DENY');res.json({ok:1})});
app.post('/api/visits/:id/revoke',auth('ADMIN','HOST'),async(req,res)=>{const v=await own(req,res,'APPROVED');if(!v)return;v.status='REVOKED';await v.save();log(req.user.username,'REVOKE_PASS','Visit '+v.id.slice(-6),'SUCCESS');res.json({ok:1})});
app.get('/api/stats',auth('ADMIN','HOST'),async(req,res)=>{const f=req.user.role==='HOST'?{host:req.user._id}:{};
 const [visitors,visits,pending,active]=await Promise.all([Visitor.countDocuments(),Visit.countDocuments(f),Visit.countDocuments({...f,status:'PENDING'}),Visit.countDocuments({...f,status:'APPROVED',until:{$gt:new Date()}})]);res.json({visitors,visits,pending,active})});
// Continuous verification: every scan is re-checked, scored and logged
app.post('/api/verify',auth('SECURITY'),async(req,res)=>{
 const {token,zone,device,stepUpDone}=req.body;if(!(zone in ZONES))return bad(res,'Choose a valid zone');
 const v=typeof token==='string'&&token.length>=10&&token.length<=100?await Visit.findOne({tokenHash:sha(token.trim())}).populate('visitor','name'):null;
 const now=new Date();if(v&&v.status==='APPROVED'&&v.until<now){v.status='EXPIRED';await v.save()}
 const dev={KNOWN:0,UNKNOWN:25,OUTDATED:45}[device]??45;
 const checks=[['Pass exists',!!v],['Pass approved and not revoked',!!v&&v.status==='APPROVED'],['Inside valid time window',!!v&&v.from<=now&&now<=v.until],['Zone matches approval',!!v&&v.zone===zone],['Not already used for this zone',!!v&&!v.used.includes(zone)]].map(([name,ok])=>({name,ok}));
 const hard=checks.find(c=>!c.ok),score=Math.min(100,dev+(v?v.fails*15:0)+ZONES[zone]*10+(hard?50:0));
 let decision=hard||score>=60?'DENY':score>=25?'STEP_UP':'ALLOW';if(decision==='STEP_UP'&&stepUpDone===true)decision='ALLOW';
 if(v){if(decision==='ALLOW')v.used.push(zone);else if(decision==='DENY')v.fails++;await v.save()}
 log(req.user.username,'CHECK_IN',v?'Visit '+v.id.slice(-6):'Unknown pass',decision,(hard?hard.name+' failed':'Risk '+score)+' | '+zone+' | device '+device);
 res.json({decision,score,checks,visitor:v?.visitor?.name,reason:hard?hard.name+' failed':decision==='DENY'?'Risk score too high':decision==='STEP_UP'?'Extra identity check needed':''})});
app.get('/api/audit',auth('ADMIN'),async(req,res)=>{const all=await Audit.find().sort({_id:1});let prev='GENESIS',ok=true;for(const a of all){if(a.prev!==prev||a.hash!==chain(a)){ok=false;break}prev=a.hash}
 res.json({intact:ok,total:all.length,logs:all.slice(-100).reverse()})});
async function seed(){
 if(await User.countDocuments())return;
 const sp=process.env.SEED_PASSWORD;
 if(process.env.NODE_ENV==='production'&&(!sp||sp.length<10))throw new Error('Set SEED_PASSWORD (10+ characters) to create the first users');
 for(const [username,name,role] of [['admin','System Administrator','ADMIN'],['host','Amit Kumar','HOST'],['security','Security Officer','SECURITY']]){
  const pw=sp||crypto.randomBytes(6).toString('hex');
  try{await User.create({username,name,role,hash:await bcrypt.hash(pw,12)})}catch(e){if(e.code!==11000)throw e}
  if(!sp)console.log(`  ${username} / ${pw}`)}
}
module.exports=app;app.db=db;

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const PDFDocument = require('pdfkit');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;
const DATA = path.join(ROOT,'data');
const UPLOADS = path.join(ROOT,'uploads');
for (const d of [DATA,UPLOADS]) fs.mkdirSync(d,{recursive:true});
const files = { users:path.join(DATA,'users.json'), orders:path.join(DATA,'orders.json'), messages:path.join(DATA,'messages.json') };
for (const f of Object.values(files)) if (!fs.existsSync(f)) fs.writeFileSync(f,'[]');
const SECRET = process.env.JWT_SECRET || 'tikka-dev-secret-change-me';
const corsOrigin = process.env.CORS_ORIGIN || '*';
app.use(cors({origin:corsOrigin === '*' ? true : corsOrigin}));
app.use(express.json({limit:'1mb'}));
app.use(express.urlencoded({extended:true}));
app.use(rateLimit({windowMs:15*60*1000,max:300,standardHeaders:true,legacyHeaders:false}));
app.use('/uploads',express.static(UPLOADS));
app.use(express.static(path.join(ROOT,'public')));
app.get('/admin',(req,res)=>res.sendFile(path.join(ROOT,'public','admin.html')));

const read = key => JSON.parse(fs.readFileSync(files[key],'utf8') || '[]');
const write = (key,data) => fs.writeFileSync(files[key],JSON.stringify(data,null,2),'utf8');
const id = prefix => `${prefix}-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;
const token = user => jwt.sign({id:user.id,email:user.email,role:user.role,name:user.name},SECRET,{expiresIn:'7d'});
function auth(req,res,next){
  const h=req.headers.authorization||'';
  if(!h.startsWith('Bearer ')) return res.status(401).json({success:false,message:'يجب تسجيل الدخول'});
  try{req.user=jwt.verify(h.slice(7),SECRET);next();}catch{return res.status(401).json({success:false,message:'جلسة الدخول غير صالحة أو منتهية'});}
}
function admin(req,res,next){ if(req.user?.role!=='admin') return res.status(403).json({success:false,message:'صلاحيات المدير مطلوبة'}); next(); }
function safeUser(u){ const {passwordHash,...x}=u; return x; }

app.get('/api/health',(req,res)=>res.json({success:true,status:'healthy',service:'tikka-backend',time:new Date().toISOString()}));
app.get('/api/config',(req,res)=>res.json({success:true,shamCashNumber:process.env.SHAM_CASH_NUMBER||'ضع رقم محفظتك هنا'}));

app.post('/api/auth/register',async(req,res)=>{
  const {name,email,password}=req.body||{};
  if(!name||!email||!password||password.length<6) return res.status(400).json({success:false,message:'الاسم والبريد وكلمة السر (6 أحرف على الأقل) مطلوبة'});
  const users=read('users'); const normalized=String(email).trim().toLowerCase();
  if(users.some(u=>u.email===normalized)) return res.status(409).json({success:false,message:'البريد مستخدم مسبقاً'});
  const user={id:id('USR'),name:String(name).trim(),email:normalized,passwordHash:await bcrypt.hash(password,12),role:'customer',createdAt:new Date().toISOString()};
  users.push(user); write('users',users); res.status(201).json({success:true,user:safeUser(user),token:token(user)});
});
app.post('/api/auth/login',async(req,res)=>{
  const {email,password}=req.body||{}; const users=read('users');
  const user=users.find(u=>u.email===String(email||'').trim().toLowerCase());
  if(!user || !(await bcrypt.compare(String(password||''),user.passwordHash))) return res.status(401).json({success:false,message:'البريد أو كلمة السر غير صحيحة'});
  res.json({success:true,user:safeUser(user),token:token(user)});
});
app.get('/api/auth/me',auth,(req,res)=>{const u=read('users').find(x=>x.id===req.user.id); res.json({success:!!u,user:u?safeUser(u):null});});

app.get('/api/orders',auth,(req,res)=>{
  let orders=read('orders'); if(req.user.role!=='admin') orders=orders.filter(o=>o.userId===req.user.id || o.phone===req.query.phone);
  res.json({success:true,orders});
});
app.get('/api/orders/:id',auth,(req,res)=>{const o=read('orders').find(x=>x.orderId===req.params.id); if(!o)return res.status(404).json({success:false,message:'الطلب غير موجود'}); if(req.user.role!=='admin'&&o.userId!==req.user.id)return res.status(403).json({success:false,message:'غير مصرح'}); res.json({success:true,order:o});});

app.post('/api/orders',async(req,res)=>{
  const b=req.body||{};
  if(!b.customerName||!b.phone||!Array.isArray(b.items)||!b.items.length) return res.status(400).json({success:false,message:'بيانات الطلب ناقصة'});
  if(b.payment==='Sham Cash' || b.payment==='shamcash') {
    if(!String(b.transactionId||b.txId||'').trim()) return res.status(400).json({success:false,message:'رقم عملية شام كاش مطلوب'});
  }
  const subtotal=Number(b.subtotal ?? b.items.reduce((s,x)=>s+Number(x.price||0)*Number(x.quantity||x.qty||1),0));
  const deliveryFee=Number(b.deliveryFee||0); const discount=Number(b.discount||0); const total=Math.max(0,Number(b.total ?? subtotal+deliveryFee-discount));
  const order={
    orderId:id('TIKKA'), userId:req.body.userId || null,
    customerName:String(b.customerName), phone:String(b.phone), address:String(b.address||''),
    delivery:b.delivery||b.deliveryMethod||'pickup', deliveryNotes:String(b.deliveryNotes||''),
    payment:b.payment||'cod', paymentStatus:b.paymentStatus || ((b.payment==='shamcash'||b.payment==='Sham Cash')?'بانتظار التحقق':'الدفع عند الاستلام'),
    transactionId:String(b.transactionId||b.txId||'—'), items:b.items.map(x=>({name:String(x.name),quantity:Number(x.quantity||x.qty||1),price:Number(x.price||0),total:Number(x.total ?? Number(x.price||0)*Number(x.quantity||x.qty||1))})),
    subtotal,deliveryFee,discount,total,status:'new',createdAt:new Date().toISOString(),updatedAt:new Date().toISOString()
  };
  const orders=read('orders'); orders.unshift(order); write('orders',orders);
  res.status(201).json({success:true,message:'تم حفظ الطلب بنجاح',order});
});

app.patch('/api/orders/:id/status',auth,admin,(req,res)=>{
  const allowed=['new','confirmed','preparing','ready','out_for_delivery','delivered','cancelled'];
  if(!allowed.includes(req.body.status))return res.status(400).json({success:false,message:'حالة الطلب غير صحيحة'});
  const orders=read('orders'); const o=orders.find(x=>x.orderId===req.params.id); if(!o)return res.status(404).json({success:false,message:'الطلب غير موجود'});
  o.status=req.body.status;o.updatedAt=new Date().toISOString();write('orders',orders);res.json({success:true,order:o});
});
app.patch('/api/orders/:id/payment',auth,admin,(req,res)=>{
  const allowed=['بانتظار الدفع','بانتظار التحقق','تم التحقق','مرفوض','الدفع عند الاستلام'];
  if(!allowed.includes(req.body.paymentStatus))return res.status(400).json({success:false,message:'حالة الدفع غير صحيحة'});
  const orders=read('orders'); const o=orders.find(x=>x.orderId===req.params.id); if(!o)return res.status(404).json({success:false,message:'الطلب غير موجود'});
  o.paymentStatus=req.body.paymentStatus;o.updatedAt=new Date().toISOString();write('orders',orders);res.json({success:true,order:o});
});

app.get('/api/admin/stats',auth,admin,(req,res)=>{const orders=read('orders');const customers=read('users').filter(x=>x.role==='customer');res.json({success:true,stats:{orders:orders.length,pending:orders.filter(x=>!['delivered','cancelled'].includes(x.status)).length,revenue:orders.filter(x=>x.status!=='cancelled').reduce((s,x)=>s+Number(x.total||0),0),customers:customers.length}});});
app.get('/api/admin/orders',auth,admin,(req,res)=>res.json({success:true,orders:read('orders')}));

app.post('/api/chat',async(req,res)=>{const m={id:id('MSG'),name:String(req.body.name||'زائر'),phone:String(req.body.phone||''),message:String(req.body.message||'').slice(0,2000),createdAt:new Date().toISOString()};if(!m.message)return res.status(400).json({success:false,message:'الرسالة فارغة'});const a=read('messages');a.push(m);write('messages',a);res.status(201).json({success:true,message:m});});
app.get('/api/admin/messages',auth,admin,(req,res)=>res.json({success:true,messages:read('messages').slice(-200).reverse()}));

app.get('/api/orders/:id/pdf',auth,admin,(req,res)=>{
  const o=read('orders').find(x=>x.orderId===req.params.id);if(!o)return res.status(404).json({success:false,message:'الطلب غير موجود'});
  const doc=new PDFDocument({size:'A4',margin:50}); res.setHeader('Content-Type','application/pdf');res.setHeader('Content-Disposition',`inline; filename="${o.orderId}.pdf"`);doc.pipe(res);
  doc.fontSize(20).text('TIKKA ORDER', {align:'center'});doc.moveDown();
  doc.fontSize(11).text(`Order ID: ${o.orderId}`);doc.text(`Customer: ${o.customerName}`);doc.text(`Phone: ${o.phone}`);doc.text(`Address: ${o.address}`);doc.text(`Delivery: ${o.delivery}`);doc.text(`Payment: ${o.payment}`);doc.text(`Payment status: ${o.paymentStatus}`);doc.text(`Transaction ID: ${o.transactionId}`);doc.moveDown();doc.fontSize(14).text('Items');doc.moveDown(0.5);
  o.items.forEach((x,i)=>doc.fontSize(11).text(`${i+1}. ${x.name} x ${x.quantity} = ${x.total.toLocaleString()} SYP`));doc.moveDown();doc.fontSize(12).text(`Subtotal: ${o.subtotal.toLocaleString()} SYP`);doc.text(`Delivery: ${o.deliveryFee.toLocaleString()} SYP`);doc.text(`Discount: ${o.discount.toLocaleString()} SYP`);doc.fontSize(15).text(`TOTAL: ${o.total.toLocaleString()} SYP`);doc.moveDown();doc.fontSize(9).text(`Created: ${o.createdAt}`);doc.end();
});

app.use((req,res)=>res.status(404).json({success:false,message:'المسار غير موجود'}));
app.use((err,req,res,next)=>{console.error(err);res.status(500).json({success:false,message:'حدث خطأ في السيرفر'});});

(async()=>{
  const users=read('users');
  const adminEmail=(process.env.ADMIN_EMAIL||'admin@tikka.local').toLowerCase();
  if(!users.some(u=>u.email===adminEmail)) { const password=process.env.ADMIN_PASSWORD||'ChangeMe123!'; users.push({id:id('USR'),name:'Tikka Admin',email:adminEmail,passwordHash:await bcrypt.hash(password,12),role:'admin',createdAt:new Date().toISOString()}); write('users',users); console.log(`Admin created: ${adminEmail}`); }
  app.listen(PORT,()=>console.log(`Tikka Backend يعمل على http://localhost:${PORT}`));
})();

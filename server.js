const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || __dirname;
const DATA_FILE = path.join(DATA_DIR, 'data.json');

// ==================== DATA LAYER ====================
function readData(){
  try{
    const raw = fs.readFileSync(DATA_FILE,'utf8');
    return JSON.parse(raw);
  }catch(e){
    return {
      opps:[],
      tasks:[],
      team:['Monica'],
      version:6,
      users:[
        {id:1,username:'admin',password:bcrypt.hashSync('admin123',10),name:'Monica',role:'admin'}
      ]
    };
  }
}

function writeData(data){
  const tmp = DATA_FILE+'.tmp';
  fs.writeFileSync(tmp, JSON.stringify(data,null,2));
  fs.renameSync(tmp, DATA_FILE);
}

// Ensure data file exists with defaults
if(!fs.existsSync(DATA_FILE)){
  writeData({
    opps:[],
    tasks:[],
    team:['Monica'],
    version:6,
    users:[
      {id:1,username:'admin',password:bcrypt.hashSync('admin123',10),name:'Monica',role:'admin'}
    ]
  });
}

// ==================== MIDDLEWARE ====================
app.use(express.json({limit:'10mb'}));

// CORS for cross-origin frontend
app.use((req,res,next)=>{
  res.header('Access-Control-Allow-Origin','*');
  res.header('Access-Control-Allow-Methods','GET,POST,PUT,DELETE,OPTIONS');
  res.header('Access-Control-Allow-Headers','Content-Type,Authorization,X-Session-Id');
  res.header('Access-Control-Allow-Credentials','true');
  if(req.method==='OPTIONS') return res.sendStatus(200);
  // Expose session ID header
  res.header('Access-Control-Expose-Headers','X-Session-Id');
  next();
});

// Session store: supports both cookie-based (same-origin) and header-based (cross-origin)
const sessionStore = new Map(); // sessionId -> {user, createdAt}
const SESSION_TTL = 24*60*60*1000; // 24h

function getSession(req){
  // Try header first (cross-origin)
  const headerSid = req.headers['x-session-id'];
  if(headerSid && sessionStore.has(headerSid)){
    const s = sessionStore.get(headerSid);
    if(Date.now()-s.createdAt < SESSION_TTL) return s.user;
    sessionStore.delete(headerSid);
  }
  // Fallback to express-session (same-origin)
  return req.session && req.session.user;
}

app.use(session({
  secret:'sales-workbench-2026-secret',
  resave:false,
  saveUninitialized:false,
  cookie:{maxAge:SESSION_TTL}
}));
app.use(express.static(path.join(__dirname,'public')));

function requireAuth(req,res,next){
  const user = getSession(req);
  if(!user) return res.status(401).json({error:'请先登录'});
  next();
}

function requireAdmin(req,res,next){
  const user = getSession(req);
  if(!user || user.role!=='admin') return res.status(403).json({error:'需要管理员权限'});
  next();
}

// ==================== AUTH ROUTES ====================
app.post('/api/login',(req,res)=>{
  const {username,password} = req.body;
  if(!username||!password) return res.status(400).json({error:'请输入用户名和密码'});
  const data = readData();
  const user = (data.users||[]).find(u=>u.username===username);
  if(!user||!bcrypt.compareSync(password,user.password)){
    return res.status(401).json({error:'用户名或密码错误'});
  }
  const userInfo = {id:user.id,username:user.username,name:user.name,role:user.role};
  // Cookie session
  req.session.user = userInfo;
  // Header session for cross-origin
  const sid = Date.now().toString(36)+Math.random().toString(36).slice(2);
  sessionStore.set(sid, {user:userInfo, createdAt:Date.now()});
  res.header('X-Session-Id', sid);
  res.json(userInfo);
});

app.post('/api/logout',(req,res)=>{
  const headerSid = req.headers['x-session-id'];
  if(headerSid) sessionStore.delete(headerSid);
  req.session.destroy();
  res.json({ok:true});
});

app.get('/api/me',(req,res)=>{
  const user = getSession(req);
  if(!user) return res.status(401).json({error:'not authenticated'});
  res.json(user);
});

// ==================== DATA ROUTES ====================
app.get('/api/data',requireAuth,(req,res)=>{
  const data = readData();
  // Don't send passwords to client
  data.users = (data.users||[]).map(u=>({id:u.id,username:u.username,name:u.name,role:u.role}));
  res.json(data);
});

app.post('/api/data',requireAuth,(req,res)=>{
  const current = readData();
  const incoming = req.body;

  // Merge: update opps and tasks by ID (entity-level merge to avoid overwrite)
  if(incoming.opps){
    incoming.opps.forEach(newOpp=>{
      const idx = current.opps.findIndex(o=>o.id===newOpp.id);
      if(idx>=0) current.opps[idx] = newOpp;
      else current.opps.push(newOpp);
    });
  }
  if(incoming.tasks){
    incoming.tasks.forEach(newTask=>{
      const idx = current.tasks.findIndex(t=>t.id===newTask.id);
      if(idx>=0) current.tasks[idx] = newTask;
      else current.tasks.push(newTask);
    });
  }
  if(incoming.team){
    current.team = incoming.team;
  }

  // Remove opps/tasks that are in current but not in incoming (deleted)
  if(incoming.opps){
    const incomingIds = new Set(incoming.opps.map(o=>o.id));
    current.opps = current.opps.filter(o=>incomingIds.has(o.id));
  }
  if(incoming.tasks){
    const incomingIds = new Set(incoming.tasks.map(t=>t.id));
    current.tasks = current.tasks.filter(t=>incomingIds.has(t.id));
  }

  current.version = incoming.version || current.version;
  writeData(current);

  // Return merged data (without passwords)
  const safe = {...current, users: current.users.map(u=>({id:u.id,username:u.username,name:u.name,role:u.role}))};
  res.json(safe);
});

// ==================== USER MANAGEMENT ====================
app.get('/api/users',requireAuth,(req,res)=>{
  const data = readData();
  res.json((data.users||[]).map(u=>({id:u.id,username:u.username,name:u.name,role:u.role})));
});

app.post('/api/users',requireAuth,requireAdmin,(req,res)=>{
  const {username,password,name,role} = req.body;
  if(!username||!password) return res.status(400).json({error:'用户名和密码不能为空'});
  const data = readData();
  if((data.users||[]).some(u=>u.username===username)){
    return res.status(400).json({error:'用户名已存在'});
  }
  const maxId = Math.max(0,...(data.users||[]).map(u=>u.id||0));
  data.users = data.users||[];
  data.users.push({
    id:maxId+1,
    username,
    password:bcrypt.hashSync(password,10),
    name:name||username,
    role:role||'sales'
  });
  writeData(data);
  res.json({ok:true});
});

app.post('/api/users/:id/reset-password',requireAuth,requireAdmin,(req,res)=>{
  const data = readData();
  const user = (data.users||[]).find(u=>u.id===parseInt(req.params.id));
  if(!user) return res.status(404).json({error:'用户不存在'});
  user.password = bcrypt.hashSync(req.body.password||'123456',10);
  writeData(data);
  res.json({ok:true});
});

app.delete('/api/users/:id',requireAuth,requireAdmin,(req,res)=>{
  const id = parseInt(req.params.id);
  if(id===1) return res.status(400).json({error:'不能删除管理员账户'});
  const data = readData();
  data.users = (data.users||[]).filter(u=>u.id!==id);
  writeData(data);
  res.json({ok:true});
});

// ==================== START ====================
app.listen(PORT,'0.0.0.0',()=>{
  console.log(`Sales Workbench running at http://localhost:${PORT}`);
  console.log(`Default login: admin / admin123`);
});

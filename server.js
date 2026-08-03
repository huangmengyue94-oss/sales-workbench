const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || __dirname;
const DATA_FILE = path.join(DATA_DIR, 'data.json');
const GH_TOKEN = process.env.GITHUB_TOKEN || '';

function DEFAULT_DATA(){
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

// ==================== DATA LAYER ====================
// Uses GitHub Gist for persistent storage (free, no DB needed)
// Falls back to local file if GITHUB_TOKEN not set

function writeDataFile(data){
  const tmp = DATA_FILE+'.tmp';
  fs.writeFileSync(tmp, JSON.stringify(data,null,2));
  fs.renameSync(tmp, DATA_FILE);
}

let gistId = null;

async function findGist(){
  if(!GH_TOKEN) return null;
  try{
    const res = await fetch('https://api.github.com/gists?per_page=100',{
      headers:{'Authorization':`Bearer ${GH_TOKEN}`,'User-Agent':'sales-workbench'}
    });
    if(!res.ok) throw new Error(`GitHub API ${res.status}`);
    const gists = await res.json();
    const found = gists.find(g=>g.files && g.files['sales-data.json']);
    return found ? found.id : null;
  }catch(e){
    console.error('findGist error:',e.message);
    return null;
  }
}

async function createGist(){
  if(!GH_TOKEN) return null;
  try{
    const res = await fetch('https://api.github.com/gists',{
      method:'POST',
      headers:{'Authorization':`Bearer ${GH_TOKEN}`,'Content-Type':'application/json','User-Agent':'sales-workbench'},
      body:JSON.stringify({
        description:'Sales Workbench Data (auto-created)',
        public:false,
        files:{'sales-data.json':{content:JSON.stringify(DEFAULT_DATA(),null,2)}}
      })
    });
    if(!res.ok) throw new Error(`GitHub API ${res.status}`);
    const gist = await res.json();
    console.log('Created Gist:',gist.id);
    return gist.id;
  }catch(e){
    console.error('createGist error:',e.message);
    return null;
  }
}

async function initStorage(){
  if(GH_TOKEN){
    gistId = await findGist();
    if(!gistId) gistId = await createGist();
    if(gistId){
      console.log('GitHub Gist storage active - data will persist');
      return;
    }
    console.error('Gist init failed, falling back to file storage');
  }
  if(!fs.existsSync(DATA_FILE)) writeDataFile(DEFAULT_DATA());
  console.log('Using local file storage (NOT persistent on Render free)');
}

async function readData(){
  if(gistId && GH_TOKEN){
    try{
      const res = await fetch(`https://api.github.com/gists/${gistId}`,{
        headers:{'Authorization':`Bearer ${GH_TOKEN}`,'User-Agent':'sales-workbench'}
      });
      if(!res.ok) throw new Error(`GitHub API ${res.status}`);
      const gist = await res.json();
      const content = gist.files['sales-data.json'].content;
      return JSON.parse(content);
    }catch(e){
      console.error('readData gist error:',e.message);
    }
  }
  try{
    return JSON.parse(fs.readFileSync(DATA_FILE,'utf8'));
  }catch(e){
    return DEFAULT_DATA();
  }
}

// Throttle writes to avoid GitHub API rate limits
let lastWriteTime = 0;
let pendingWrite = null;
let writeTimer = null;

async function writeData(data){
  if(gistId && GH_TOKEN){
    // Throttle: at most 1 write per 3 seconds
    const now = Date.now();
    const wait = Math.max(0, 3000 - (now - lastWriteTime));
    pendingWrite = data;
    if(writeTimer) clearTimeout(writeTimer);
    writeTimer = setTimeout(async()=>{
      const toWrite = pendingWrite;
      pendingWrite = null;
      lastWriteTime = Date.now();
      try{
        await fetch(`https://api.github.com/gists/${gistId}`,{
          method:'PATCH',
          headers:{'Authorization':`Bearer ${GH_TOKEN}`,'Content-Type':'application/json','User-Agent':'sales-workbench'},
          body:JSON.stringify({files:{'sales-data.json':{content:JSON.stringify(toWrite,null,2)}}})
        });
      }catch(e){
        console.error('writeData gist error:',e.message);
      }
    }, wait);
    return;
  }
  writeDataFile(data);
}

// ==================== MIDDLEWARE ====================
app.use(express.json({limit:'10mb'}));
app.use((req,res,next)=>{
  res.header('Access-Control-Allow-Origin','*');
  res.header('Access-Control-Allow-Methods','GET,POST,PUT,DELETE,OPTIONS');
  res.header('Access-Control-Allow-Headers','Content-Type,Authorization,X-Session-Id');
  res.header('Access-Control-Allow-Credentials','true');
  res.header('Access-Control-Expose-Headers','X-Session-Id');
  if(req.method==='OPTIONS') return res.sendStatus(200);
  next();
});

const sessionStore = new Map();
const SESSION_TTL = 24*60*60*1000;

function getSession(req){
  const headerSid = req.headers['x-session-id'];
  if(headerSid && sessionStore.has(headerSid)){
    const s = sessionStore.get(headerSid);
    if(Date.now()-s.createdAt < SESSION_TTL) return s.user;
    sessionStore.delete(headerSid);
  }
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
app.post('/api/login',async(req,res)=>{
  const {username,password} = req.body;
  if(!username||!password) return res.status(400).json({error:'请输入用户名和密码'});
  const data = await readData();
  const user = (data.users||[]).find(u=>u.username===username);
  if(!user||!bcrypt.compareSync(password,user.password)){
    return res.status(401).json({error:'用户名或密码错误'});
  }
  const userInfo = {id:user.id,username:user.username,name:user.name,role:user.role};
  req.session.user = userInfo;
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

app.get('/health',(req,res)=>res.json({status:'ok'}));

// ==================== DATA ROUTES ====================
app.get('/api/data',requireAuth,async(req,res)=>{
  const data = await readData();
  data.users = (data.users||[]).map(u=>({id:u.id,username:u.username,name:u.name,role:u.role}));
  res.json(data);
});

app.post('/api/data',requireAuth,async(req,res)=>{
  const current = await readData();
  const incoming = req.body;

  if(incoming.opps){
    incoming.opps.forEach(newOpp=>{
      const idx = current.opps.findIndex(o=>o.id===newOpp.id);
      if(idx>=0) current.opps[idx] = newOpp;
      else current.opps.push(newOpp);
    });
    const incomingIds = new Set(incoming.opps.map(o=>o.id));
    current.opps = current.opps.filter(o=>incomingIds.has(o.id));
  }
  if(incoming.tasks){
    incoming.tasks.forEach(newTask=>{
      const idx = current.tasks.findIndex(t=>t.id===newTask.id);
      if(idx>=0) current.tasks[idx] = newTask;
      else current.tasks.push(newTask);
    });
    const incomingIds = new Set(incoming.tasks.map(t=>t.id));
    current.tasks = current.tasks.filter(t=>incomingIds.has(t.id));
  }
  if(incoming.team) current.team = incoming.team;
  if(incoming.users) current.users = incoming.users;
  current.version = incoming.version || current.version;

  await writeData(current);

  const safe = {...current, users: current.users.map(u=>({id:u.id,username:u.username,name:u.name,role:u.role}))};
  res.json(safe);
});

// ==================== USER MANAGEMENT ====================
app.get('/api/users',requireAuth,async(req,res)=>{
  const data = await readData();
  res.json((data.users||[]).map(u=>({id:u.id,username:u.username,name:u.name,role:u.role})));
});

app.post('/api/users',requireAuth,requireAdmin,async(req,res)=>{
  const {username,password,name,role} = req.body;
  if(!username||!password) return res.status(400).json({error:'用户名和密码不能为空'});
  const data = await readData();
  if((data.users||[]).some(u=>u.username===username)){
    return res.status(400).json({error:'用户名已存在'});
  }
  const maxId = Math.max(0,...(data.users||[]).map(u=>u.id||0));
  data.users = data.users||[];
  data.users.push({id:maxId+1,username,password:bcrypt.hashSync(password,10),name:name||username,role:role||'sales'});
  await writeData(data);
  res.json({ok:true});
});

app.post('/api/users/:id/reset-password',requireAuth,requireAdmin,async(req,res)=>{
  const data = await readData();
  const user = (data.users||[]).find(u=>u.id===parseInt(req.params.id));
  if(!user) return res.status(404).json({error:'用户不存在'});
  user.password = bcrypt.hashSync(req.body.password||'123456',10);
  await writeData(data);
  res.json({ok:true});
});

app.delete('/api/users/:id',requireAuth,requireAdmin,async(req,res)=>{
  const id = parseInt(req.params.id);
  if(id===1) return res.status(400).json({error:'不能删除管理员账户'});
  const data = await readData();
  data.users = (data.users||[]).filter(u=>u.id!==id);
  await writeData(data);
  res.json({ok:true});
});

// ==================== START ====================
initStorage().then(()=>{
  app.listen(PORT,'0.0.0.0',()=>{
    console.log(`Sales Workbench running at http://localhost:${PORT}`);
    console.log(`Default login: admin / admin123`);
    if(gistId) console.log('Storage: GitHub Gist (persistent)');
    else console.log('Storage: Local file (NOT persistent)');
  });
});

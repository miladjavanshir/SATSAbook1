/* Capability Book — Supabase content sync, schema v2 (automatic page ownership).
   Only the public Publishable Key in supabase.js is used. Never add a Secret here. */
(()=>{'use strict';
const QUEUE='cloud_queue',META='cloud_meta',PAGES='richTexts';
const PAGE_LIMIT=4*1024*1024,PROFILE_LIMIT=12*1024*1024;
const sanitizerReady=()=>!!window.DOMPurify?.isSupported;
const own=(o,k)=>Object.prototype.hasOwnProperty.call(o,k);
const copy=o=>o==null?o:JSON.parse(JSON.stringify(o));
const uid=()=>globalThis.crypto?.randomUUID?.()||Date.now().toString(36)+'-'+Math.random().toString(36).slice(2);
const bytes=s=>new TextEncoder().encode(s).byteLength;
const fail=(code,message)=>Object.assign(new Error(message||code),{code});
const integer=(v,min,max,fallback)=>Number.isInteger(Number(v))&&Number(v)>=min&&Number(v)<=max?Number(v):fallback;
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const chooseEntry=(disk,memory)=>memory?.durable===false&&(!disk||Date.parse(memory.queuedAt)>=Date.parse(disk.queuedAt))?memory:disk||null;
function upgrade(database){
  if(!database.objectStoreNames.contains(QUEUE))database.createObjectStore(QUEUE,{keyPath:'key'});
  if(!database.objectStoreNames.contains(META))database.createObjectStore(META,{keyPath:'key'});
}

// DOMPurify removes active HTML; the second pass also removes unsafe CSS and URLs.
// A missing sanitizer fails closed to escaped text, never to raw innerHTML.
function cleanHtml(input){
  const raw=typeof input==='string'?input:'';
  if(!window.DOMPurify?.isSupported){const div=document.createElement('div');div.textContent=raw;return div.innerHTML;}
  const fragment=DOMPurify.sanitize(raw,{
    RETURN_DOM_FRAGMENT:true,ALLOW_DATA_ATTR:false,ALLOW_ARIA_ATTR:false,
    ALLOWED_TAGS:['p','br','b','strong','i','em','u','s','strike','span','div','font','ul','ol','li','a','blockquote','pre','code','h1','h2','h3','h4','h5','h6','sub','sup','table','thead','tbody','tfoot','tr','th','td','hr'],
    ALLOWED_ATTR:['href','title','target','rel','dir','style','color','face','size','align','colspan','rowspan','start','type']
  });
  const color=v=>/^(#[0-9a-f]{3,8}|rgba?\([\d\s.,%]+\)|hsla?\([\d\s.,%a-z]+\)|[a-z]{1,24})$/i.test(v)&&CSS.supports('color',v);
  const family=v=>/^[\p{L}\p{N} _,'"-]{1,160}$/u.test(v);
  const cssRules={
    color, 'background-color':color,
    'font-family':family,
    'font-size':v=>/^(\d{1,3}(\.\d{1,2})?(px|pt|em|rem|%)|xx-small|x-small|small|medium|large|x-large|xx-large|xxx-large)$/i.test(v),
    'font-weight':v=>/^(normal|bold|bolder|lighter|[1-9]00)$/i.test(v),
    'font-style':v=>/^(normal|italic|oblique)$/i.test(v),
    'text-align':v=>/^(start|end|left|right|center|justify)$/i.test(v),
    'text-decoration':v=>/^(none|underline|line-through|overline)( (underline|line-through|overline))*$/i.test(v),
    'text-decoration-line':v=>/^(none|underline|line-through|overline)( (underline|line-through|overline))*$/i.test(v),
    'white-space':v=>/^(normal|pre|pre-wrap|pre-line|break-spaces)$/i.test(v),
    'margin-left':v=>/^(0|[0-9]{1,3}(px|pt))$/.test(v),
    'margin-right':v=>/^(0|[0-9]{1,3}(px|pt))$/.test(v),
    'text-indent':v=>/^(0|-?[0-9]{1,3}(px|pt))$/.test(v)
  };
  fragment.querySelectorAll('*').forEach(el=>{
    const safe=[];
    for(const name of [...el.style]){
      const value=el.style.getPropertyValue(name).trim();
      if(cssRules[name]?.(value))safe.push([name,value]);
    }
    el.removeAttribute('style');
    safe.forEach(([k,v])=>el.style.setProperty(k,v));
    if(el.hasAttribute('dir')&&!/^(rtl|ltr|auto)$/.test(el.getAttribute('dir')))el.removeAttribute('dir');
    if(el.hasAttribute('align')&&!/^(left|right|center|justify)$/.test(el.getAttribute('align')))el.removeAttribute('align');
    if(el.hasAttribute('color')&&!color(el.getAttribute('color')))el.removeAttribute('color');
    if(el.hasAttribute('face')&&!family(el.getAttribute('face')))el.removeAttribute('face');
    if(el.hasAttribute('size')&&!/^[1-7]$/.test(el.getAttribute('size')))el.removeAttribute('size');
    for(const attr of ['colspan','rowspan','start'])if(el.hasAttribute(attr)&&!/^\d{1,3}$/.test(el.getAttribute(attr)))el.removeAttribute(attr);
    if(el.tagName==='A'){
      const href=String(el.getAttribute('href')||'').trim();
      if(!/^(https?:\/\/|mailto:|tel:)/i.test(href)||/[\u0000-\u0020\u007f]/.test(href))el.removeAttribute('href');
      el.setAttribute('rel','noopener noreferrer');
      if(el.getAttribute('target')!=='_blank')el.removeAttribute('target');
    }else{el.removeAttribute('href');el.removeAttribute('target');el.removeAttribute('rel');}
  });
  const div=document.createElement('div');div.append(fragment);return div.innerHTML;
}
function cellMeta(meta){
  const value={};
  if(meta&&typeof meta==='object'){
    if(typeof meta.bg==='string'&&meta.bg.length<=40&&/^(#[0-9a-f]{3,8}|rgba?\([\d\s.,]+\))$/i.test(meta.bg)&&CSS.supports('color',meta.bg))value.bg=meta.bg;
    if(['left','right','center'].includes(meta.align))value.align=meta.align;
  }
  return value;
}
function cleanPage(src={}){
  const rows=integer(src.tableRows,1,12,3),cols=integer(src.tableCols,1,8,3);
  const out={
    intro:cleanHtml(src.intro),
    table:Array.from({length:rows*cols},(_,i)=>cleanHtml(typeof src.table?.[i]==='string'?src.table[i]:'<br>')),
    tableRows:rows,tableCols:cols,
    tableMeta:Array.from({length:rows*cols},(_,i)=>cellMeta(src.tableMeta?.[i])),
    tableStyle:integer(src.tableStyle,1,4,1),certificates:cleanHtml(src.certificates),
    contacts:Array.from({length:7},(_,i)=>cleanHtml(src.contacts?.[i])),styleId:integer(src.styleId,1,10,1)
  };
  if(bytes(JSON.stringify(out))>PAGE_LIMIT)throw fail('payload_too_large');
  return out;
}
function safePhoto(photo){
  if(typeof photo!=='string')return '';
  if(/^data:image\/(png|jpeg|webp|gif);base64,[a-z0-9+/=]+$/i.test(photo))return photo;
  if(/^https:\/\/[^\s<>"']+$/i.test(photo)&&photo.length<=2048)return photo;
  return '';
}
// Rich profile fields are PRIVATE, with a separate plain-text projection for Auth/labels.
// Legacy six-field profiles remain valid; no HTML is placed in Auth metadata.
function plainFromRich(input){
  const div=document.createElement('div');div.innerHTML=cleanHtml(input);
  // Native Enter often produces text followed by a DIV, not two P elements.
  // Keep both boundaries and table-cell separators; textContent alone joins words.
  const blocks=new Set(['P','DIV','LI','UL','OL','BLOCKQUOTE','PRE','H1','H2','H3','H4','H5','H6','TR','TABLE','THEAD','TBODY','TFOOT']);
  let value='';const line=()=>{value=value.replace(/\t+$/,'');if(value&&!value.endsWith('\n'))value+='\n';};
  const stack=[[div,false]];
  while(stack.length){
    const [node,exit]=stack.pop();
    if(node.nodeType===3){value+=node.textContent;continue;}
    if(node.nodeType!==1)continue;
    const tag=node.tagName;
    if(tag==='BR'){value+='\n';continue;}
    if(tag==='HR'){line();continue;}
    if(exit){if(tag==='TD'||tag==='TH')value+='\t';else if(blocks.has(tag))line();continue;}
    if(blocks.has(tag))line();stack.push([node,true]);
    for(let child=node.lastChild;child;child=child.previousSibling)stack.push([child,false]);
  }
  return value.replace(/\u200b/g,'').replace(/\u00a0/g,' ').replace(/\n{3,}/g,'\n\n').trim();
}
function cleanProfile(src={}){
  const out={fullname:String(src.fullname||'').trim(),role:String(src.role||'').trim(),phone:String(src.phone||'').trim(),bio:String(src.bio||'').trim(),photo:safePhoto(src.photo),profileTags:[]};
  const sourceRich=src.richText&&typeof src.richText==='object'&&!Array.isArray(src.richText)?src.richText:null,rich={};
  if(sourceRich&&!sanitizerReady())throw fail('sanitizer_unavailable');
  function richHtml(value,limit){
    if(typeof value!=='string')throw fail('profile_field_invalid');
    if(bytes(value)>limit)throw fail('profile_field_too_long','richText');
    const html=cleanHtml(value);if(bytes(html)>limit)throw fail('profile_field_too_long','richText');return html;
  }
  for(const key of ['fullname','role','phone','bio'])if(sourceRich&&own(sourceRich,key)){
    rich[key]=richHtml(sourceRich[key],key==='bio'?524288:65536);out[key]=plainFromRich(rich[key]);
  }
  const tags=Array.isArray(src.profileTags)?src.profileTags:[],richTags=sourceRich&&own(sourceRich,'profileTags')?sourceRich.profileTags:null;
  if(richTags!==null&&(!Array.isArray(richTags)||richTags.length!==tags.length))throw fail('profile_field_invalid','profileTags');
  if(tags.length>100)throw fail('profile_field_too_long','profileTags');
  if(richTags)rich.profileTags=[];
  tags.forEach((tag,index)=>{
    const html=richTags?richHtml(richTags[index],32768):null,text=html!==null?plainFromRich(html):String(tag).trim();
    if(text){out.profileTags.push(text);if(richTags)rich.profileTags.push(html);}
  });
  for(const [key,max] of Object.entries({fullname:200,role:200,phone:80,bio:20000}))if([...out[key]].length>max)throw fail('profile_field_too_long',key);
  if(out.profileTags.some(x=>[...x].length>200))throw fail('profile_field_too_long','profileTags');
  if(Object.keys(rich).length)out.richText=rich;
  if(bytes(JSON.stringify(out))>PROFILE_LIMIT)throw fail('payload_too_large');
  return out;
}
function pageRecord(row){return {pageId:Number(row.page_id),...cleanPage(row.content),_cloudVersion:Number(row.version)||0,_cloudSource:true,updatedAt:row.updated_at||null};}
function profileRecord(row){return {key:'profile:'+row.user_id,profile:cleanProfile(row.profile),version:Number(row.version)||0,updatedAt:row.updated_at||null};}
function blankPage(page){return {pageId:page,...cleanPage(),_cloudSource:true,_cloudVersion:0};}
function hasPageData(src){
  if(!src)return false;
  const page=cleanPage(src);
  return [page.intro,page.certificates,...page.table,...page.contacts].some(x=>x.replace(/<[^>]*>/g,'').trim())||page.styleId!==1||page.tableRows!==3||page.tableCols!==3||page.tableStyle!==1;
}
function errorKind(error){
  const code=String(error?.code||''),message=String(error?.message||'').toLowerCase();
  if(['PGRST205','PGRST202','42P01','42883'].includes(code))return 'setup';
  if(message.includes('app_version_conflict'))return 'conflict';
  if(message.includes('app_page_already_assigned')||message.includes('app_account_already_assigned'))return 'owned';
  if(message.includes('app_email_confirmation_required'))return 'verification';
  if(code==='42501'||message.includes('app_not_page_owner'))return 'permission';
  if(message.includes('app_invalid_profile_payload'))return 'richschema';
  if(['22001','23514','22023','payload_too_large','profile_field_too_long','profile_field_invalid'].includes(code))return 'validation';
  if(code==='PGRST301'||code==='session_missing'||Number(error?.status)===401)return 'auth';
  return 'network';
}
async function request(builder){
  const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),12000);
  // The outbox owns retry/backoff; SDK GET retries would delay offline startup.
  if(typeof builder.retry==='function')builder=builder.retry(false);
  try{const {data,error}=await builder.abortSignal(controller.signal);if(error)throw error;return data;}
  finally{clearTimeout(timer);}
}

class Sync{
  constructor({database,onChange=()=>{},onProfile=()=>{},onAccount=()=>{},onPageSaved=()=>{}}){
    this.database=database;this.onChange=onChange;this.onProfile=onProfile;this.onAccount=onAccount;this.onPageSaved=onPageSaved;
    this.writerId=uid();this.identity=null;this.member=null;this.memberCached=false;this.membershipIssue=null;this.currentPage=1;this.generation=0;
    this.memoryQueue=new Map();this.memoryCache=new Map();this.errors=new Map();this.inFlight=new Set();
    this.heads=new Map();this.acknowledged=new Map();this.queueView=[];this.freshPages=new Set();this.loading=false;this.timer=null;this.flushPromise=null;
    this.notifySequence=0;
  }
  meta(kind,pageId){const ownerId=this.identity?.id;if(!ownerId)throw fail('session_missing');return {kind,ownerId,pageId,writerId:this.writerId,key:kind==='page'?`page:${ownerId}:${pageId}`:`profile:${ownerId}`};}
  cacheId(meta){return meta.kind==='page'?Number(meta.pageId):'profile:'+meta.ownerId;}
  async read(store,key){
    const database=await this.database();
    return new Promise((resolve,reject)=>{const tx=database.transaction(store,'readonly'),req=tx.objectStore(store).get(key);tx.oncomplete=()=>resolve(req.result||null);tx.onerror=tx.onabort=()=>reject(tx.error||new Error('Local read failed'));});
  }
  async allQueue(){
    let values=[],readOK=false;
    try{const database=await this.database();values=await new Promise((resolve,reject)=>{const tx=database.transaction(QUEUE,'readonly'),req=tx.objectStore(QUEUE).getAll();tx.oncomplete=()=>resolve(req.result||[]);tx.onerror=tx.onabort=()=>reject(tx.error||new Error('Local read failed'));});readOK=true;}catch(_){}
    const merged=new Map(values.map(e=>[e.key,e]));this.memoryQueue.forEach((e,k)=>{if(!readOK||e.durable===false)merged.set(k,chooseEntry(merged.get(k),e)||e);});return [...merged.values()];
  }
  async entry(key){try{return chooseEntry(await this.read(QUEUE,key),this.memoryQueue.get(key));}catch(_){return this.memoryQueue.get(key)||null;}}
  async cached(meta){const id=this.cacheId(meta);try{const v=await this.read(meta.kind==='page'?PAGES:META,id);if(v)this.memoryCache.set(id,v);return v||this.memoryCache.get(id)||null;}catch(_){return this.memoryCache.get(id)||null;}}
  // The outbox and public/server cache are changed in one IndexedDB transaction.
  // A failed local transaction uses memory only; the caller must await a real server ACK.
  async change(meta,transform){
    const id=this.cacheId(meta),store=meta.kind==='page'?PAGES:META;
    const applyMemory=patch=>{
      if(own(patch,'entry')){if(patch.entry)this.memoryQueue.set(meta.key,patch.entry);else this.memoryQueue.delete(meta.key);}
      if(own(patch,'cache'))this.memoryCache.set(id,patch.cache);
    };
    let patch,readEntry,readCache;
    try{
      const database=await this.database();
      await new Promise((resolve,reject)=>{
        const tx=database.transaction([QUEUE,PAGES,META],'readwrite'),q=tx.objectStore(QUEUE).get(meta.key),c=tx.objectStore(store).get(id);let count=0;
        const ready=()=>{if(++count!==2)return;try{
          readEntry=chooseEntry(q.result,this.memoryQueue.get(meta.key));readCache=c.result||this.memoryCache.get(id)||null;
          patch=transform(readEntry,readCache);
          if(own(patch,'entry')){if(patch.entry){patch.entry.durable=true;tx.objectStore(QUEUE).put(patch.entry);}else tx.objectStore(QUEUE).delete(meta.key);}
          if(own(patch,'cache'))tx.objectStore(store).put(patch.cache);
          if(patch.backup)tx.objectStore(META).put(patch.backup);
        }catch(error){reject(error);try{tx.abort();}catch(_){}}};
        q.onsuccess=c.onsuccess=ready;
        tx.oncomplete=resolve;tx.onerror=tx.onabort=()=>reject(tx.error||new Error('Local save failed'));
      });
      applyMemory(patch);return {value:patch.value,durable:true};
    }catch(error){
      patch=transform(readEntry!==undefined?readEntry:(this.memoryQueue.get(meta.key)||null),readCache!==undefined?readCache:(this.memoryCache.get(id)||null));
      if(patch.entry)patch.entry.durable=false;
      applyMemory(patch);return {value:patch.value,durable:false};
    }
  }
  async putMeta(value){try{const database=await this.database();await new Promise((resolve,reject)=>{const tx=database.transaction(META,'readwrite');tx.objectStore(META).put(value);tx.oncomplete=resolve;tx.onerror=tx.onabort=()=>reject(tx.error);});}catch(_){} }
  async notify(){
    const sequence=++this.notifySequence,entries=await this.allQueue();if(sequence!==this.notifySequence)return;
    this.queueView=entries.filter(e=>e.ownerId===this.identity?.id);
    const conflict=this.queueView.find(e=>e.state==='conflict'&&(e.kind==='profile'||Number(e.pageId)===this.currentPage));
    const pending=this.queueView.filter(e=>e.state!=='conflict');
    let state='public';
    if(!sanitizerReady())state='sanitizer';
    else if([...this.errors.values()].includes('setup'))state='setup';
    else if(conflict)state='conflict';
    else if(this.queueView.some(e=>e.durable===false))state='memory';
    else if(this.inFlight.size)state='syncing';
    else if(pending.some(e=>e.error==='permission'))state='permission';
    else if(pending.some(e=>e.error==='richschema'))state='richschema';
    else if(pending.some(e=>e.error==='validation'))state='validation';
    else if(pending.some(e=>e.error==='auth'))state='auth';
    else if(pending.some(e=>e.error==='owned'))state='owned';
    else if(pending.some(e=>e.error==='verification'))state='verification';
    else if(pending.length)state='pending';
    else if(this.loading)state='loading';
    else if(this.errors.has('page:'+this.currentPage)||this.errors.has('profile'))state='offline';
    else if(this.membershipIssue==='owned')state='owned';
    else if(this.membershipIssue==='verification')state='verification';
    else if(this.identity&&!this.member)state='permission';
    else if(this.member?.provisional)state='linking';
    else if((this.heads.get(this.currentPage)?.version||0)>0)state='synced';
    else state='empty';
    this.onChange({state,pending:pending.length,conflict:copy(conflict),canEdit:!!this.member,memberCached:this.memberCached,memberPending:!!this.member?.provisional,page:this.currentPage,version:Number(this.heads.get(this.currentPage)?.version)||0,updatedAt:this.heads.get(this.currentPage)?.updated_at||null});
  }
  note(error,scope){this.errors.set(scope,errorKind(error));}
  rememberAck(entry,version){
    if(!entry?.localId||!Number.isInteger(version)||version<1)return;
    const known=this.acknowledged.get(entry.key)||new Map();known.set(entry.localId,version);
    while(known.size>64)known.delete(known.keys().next().value);
    this.acknowledged.set(entry.key,known);
  }
  async fetchPage(page){
    const data=await request(getSupabaseClient().from('app_pages').select('page_id,content,version,updated_at').eq('page_id',page).maybeSingle());
    this.errors.delete('page:'+page);
    for(const [key,kind] of this.errors)if(key.startsWith('page:')&&kind==='setup')this.errors.delete(key);
    return data;
  }
  async fetchProfile(ownerId){
    const data=await request(getSupabaseClient().from('app_profiles').select('user_id,profile,version,updated_at').eq('user_id',ownerId).maybeSingle());
    this.errors.delete('profile');return data;
  }
  async fetchMember(identity){
    const row=await request(getSupabaseClient().from('app_company_memberships').select('page_id,user_id').eq('user_id',identity.id).maybeSingle());
    this.errors.delete('membership');
    if(row&&(row.user_id!==identity.id||!integer(row.page_id,1,95,0)))throw fail('profile_invalid');
    return row?{pageId:Number(row.page_id),ownerId:identity.id}:null;
  }
  async claimMember(identity){
    if(!integer(identity.pageNumber,1,95,0))throw fail('profile_invalid');
    let row;
    try{row=await request(getSupabaseClient().rpc('app_claim_company_page',{p_user_id:identity.id,p_page_id:Number(identity.pageNumber)}));}
    catch(error){
      if(String(error?.message||'').includes('APP_ACCOUNT_ALREADY_ASSIGNED')){
        const existing=await this.fetchMember(identity);if(existing)return existing;
      }
      throw error;
    }
    if(!row||row.user_id!==identity.id||!integer(row.page_id,1,95,0))throw fail('invalid_server_response');
    this.errors.delete('membership');return {pageId:Number(row.page_id),ownerId:identity.id};
  }
  async syncMembership(identity,generation=this.generation){
    let member=null,cached=false,issue=null;
    const valid=()=>this.identity?.id===identity.id&&this.generation===generation;
    try{
      member=await this.fetchMember(identity);
      if(!member)member=await this.claimMember(identity);
      if(!valid())return null;
      await this.putMeta({key:'member:'+identity.id,member});
      this.errors.delete('membership');
    }catch(error){
      if(!valid())return null;
      issue=errorKind(error);this.note(error,'membership');
      if(['setup','network'].includes(issue)){
        // This grants local editing only. Every server save still checks the
        // real Auth UID, company domain and unique ownership in PostgreSQL.
        try{const saved=await this.read(META,'member:'+identity.id);if(saved?.member?.ownerId===identity.id&&integer(saved.member.pageId,1,95,0)){member={...saved.member};cached=true;}}catch(_){}
        if(!member&&integer(identity.pageNumber,1,95,0))member={pageId:Number(identity.pageNumber),ownerId:identity.id,provisional:true};
      }else await this.putMeta({key:'member:'+identity.id,member:null});
    }
    if(!valid())return null;
    this.member=member;this.memberCached=cached;this.membershipIssue=issue;
    this.onAccount({ownerId:identity.id,member:copy(member),cached,pending:!!member?.provisional});
    return member;
  }
  async connect(identity,fallback={},options={}){
    const generation=++this.generation;this.identity={...identity};this.member=null;this.memberCached=false;this.acknowledged.clear();
    this.errors.delete('profile');this.errors.delete('membership');clearTimeout(this.timer);
    const guard=()=>generation===this.generation&&this.identity?.id===identity.id;
    await this.syncMembership(identity,generation);
    if(!guard())throw fail('session_missing');
    await this.recoverEmergency();
    try{const staged=await this.read(META,'registration-draft:'+identity.id);if(staged?.profile&&!options.draft)fallback={...fallback,...staged.profile};}catch(_){}
    const meta=this.meta('profile');let remote=null,readOK=false;
    try{remote=await this.fetchProfile(identity.id);readOK=true;}catch(error){this.note(error,'profile');}
    if(!guard())throw fail('session_missing');
    const existing=await this.entry(meta.key),knownProfile=await this.cached(meta);
    const head=remote?profileRecord(remote):{key:'profile:'+identity.id,profile:cleanProfile(fallback),version:0};
    const fallbackProfile=cleanProfile(fallback);
    let seed=null;
    const needsMigration=(!remote&&readOK)||options.legacy||options.draft||(!readOK&&!knownProfile);
    if(!existing&&needsMigration&&Object.values(fallbackProfile).some(v=>Array.isArray(v)?v.length:!!v)){
      if(!remote||!same(cleanProfile(remote.profile),fallbackProfile))seed={...meta,payload:fallbackProfile,baseVersion:readOK?Number(remote?.version||0):null,localId:uid(),origin:'migration',state:remote?'conflict':'pending',remoteVersion:Number(remote?.version||0),queuedAt:new Date().toISOString(),attempts:0};
    }
    if(readOK)await this.accept(meta,remote,{seed});
    else if(seed)await this.change(meta,e=>({entry:e||seed}));
    const queued=await this.entry(meta.key),cached=await this.cached(meta);
    const selected=queued?.payload||cached?.profile||head.profile;
    await this.notify();
    // A profile failure must not invent an auth failure or a fake local login.
    await this.flush();
    const after=await this.entry(meta.key),profileCache=await this.cached(meta);
    return {profile:copy(after?.payload||profileCache?.profile||selected),profileVersion:Number(profileCache?.version)||0,profileLocalId:after?.localId||null,profileState:after?after.state:(readOK?'synced':'pending'),pageNumber:this.member?.pageId||identity.pageNumber,canEdit:!!this.member,memberCached:this.memberCached,memberPending:!!this.member?.provisional};
  }
  disconnect(){
    ++this.generation;this.identity=null;this.member=null;this.memberCached=false;this.membershipIssue=null;this.acknowledged.clear();clearTimeout(this.timer);
    for(const key of [...this.errors.keys()])if(key==='profile'||key==='membership'||key.startsWith('rpc:'))this.errors.delete(key);
    this.notify().catch(()=>{});
  }
  async accept(meta,remote,{seed=null}={}){
    const version=Number(remote?.version)||0;
    if(meta.kind==='page'){
      const known=this.heads.get(Number(meta.pageId));
      if(known&&Number(known.version)>version)remote=known;
      else this.heads.set(Number(meta.pageId),remote);
    }
    const actualVersion=Number(remote?.version)||0;
    const payload=remote?(meta.kind==='page'?cleanPage(remote.content):cleanProfile(remote.profile)):null;
    const incoming=meta.kind==='page'?(remote?pageRecord(remote):blankPage(meta.pageId)):(remote?profileRecord(remote):{key:'profile:'+meta.ownerId,profile:cleanProfile(),version:0});
    let acceptedPending=false,acceptedEntry=null;
    const result=await this.change(meta,(entry,cache)=>{
      let next=entry||seed;
      if(next&&!this.inFlight.has(meta.key)){
        if(payload&&same(next.payload,payload)){acceptedEntry=next;this.rememberAck(next,actualVersion);next=null;acceptedPending=true;}
        else if(next.baseVersion===null){
          next={...next,baseVersion:actualVersion,state:remote?'conflict':'pending',remoteVersion:actualVersion};
        }else if(next.baseVersion!==actualVersion)next={...next,state:'conflict',remoteVersion:actualVersion,error:null};
      }
      const oldVersion=Number(meta.kind==='page'?cache?._cloudVersion:cache?.version)||0;
      if(acceptedEntry)incoming._cloudAck={ownerId:meta.ownerId,localId:acceptedEntry.localId,version:actualVersion};
      else if(cache?._cloudAck?.ownerId===meta.ownerId&&cache._cloudAck.version===actualVersion)incoming._cloudAck=cache._cloudAck;
      return {entry:next,cache:oldVersion>actualVersion?cache:incoming,value:next};
    });
    if(acceptedPending&&this.identity?.id===meta.ownerId){
      this.errors.delete('rpc:'+meta.kind);
      if(meta.kind==='page')this.onPageSaved({ownerId:meta.ownerId,pageId:Number(meta.pageId),version:actualVersion,localId:acceptedEntry?.localId,writerId:acceptedEntry?.writerId});
      else this.onProfile({ownerId:meta.ownerId,profile:copy(payload),version:actualVersion});
    }
    return result.value;
  }
  async loadPage(page,legacy=null){
    page=integer(page,1,95,1);this.currentPage=page;this.loading=true;await this.notify();
    let savedLegacy=null;
    if(legacy&&!legacy._cloudSource&&hasPageData(legacy)){
      savedLegacy={key:'legacy-page:'+page,record:copy(legacy),consumed:false};
      try{const old=await this.read(META,savedLegacy.key);savedLegacy=old||savedLegacy;}catch(_){}
      await this.putMeta(savedLegacy);
    }else{try{savedLegacy=await this.read(META,'legacy-page:'+page);}catch(_){} }
    const ownerId=this.identity?.id;
    const canEdit=!!ownerId&&this.member?.pageId===page&&sanitizerReady();
    const meta=canEdit?this.meta('page',page):{key:'public:'+page,kind:'page',pageId:page,ownerId:''};
    let remote=null,readOK=false;
    try{remote=await this.fetchPage(page);readOK=true;this.freshPages.add(page);}catch(error){this.note(error,'page:'+page);}
    // Never attach a previous account's draft to a newly signed-in account.
    const stillOwner=canEdit&&this.identity?.id===ownerId&&this.member?.pageId===page;
    let seed=null;
    if(stillOwner&&savedLegacy&&!savedLegacy.consumed&&!await this.entry(meta.key)){
      const payload=cleanPage(savedLegacy.record);
      if(!remote||!same(payload,cleanPage(remote.content)))seed={...meta,payload,baseVersion:readOK?Number(remote?.version||0):null,localId:uid(),origin:'migration',state:remote?'conflict':'pending',remoteVersion:Number(remote?.version||0),queuedAt:new Date().toISOString(),attempts:0};
      if(seed){const stored=await this.change(meta,e=>({entry:e||seed,backup:{...savedLegacy,consumed:true,ownerId}}));if(!stored.durable)savedLegacy.consumed=false;}
      else if(readOK)await this.putMeta({...savedLegacy,consumed:true,ownerId});
    }
    if(readOK)await this.accept(meta,remote);
    const pending=stillOwner?await this.entry(meta.key):null;
    let cache=await this.cached(meta);
    if(!cache?._cloudSource)cache=null;
    this.loading=false;await this.notify();
    if(stillOwner&&pending?.state!=='conflict')this.flush().catch(()=>{});
    return pending?{pageId:page,...copy(pending.payload),_cloudPending:true,_cloudVersion:pending.baseVersion,_cloudLocalId:pending.localId,_cloudAncestors:pending.ancestors||[]}:cache||blankPage(page);
  }
  async queue(kind,payload,pageId,baseVersion,parentId=null){
    const meta=this.meta(kind,pageId);
    if(kind==='page'&&!sanitizerReady())throw fail('sanitizer_unavailable');
    if(kind==='page'&&this.member?.pageId!==Number(pageId))throw fail('42501','APP_NOT_PAGE_OWNER');
    const clean=kind==='page'?cleanPage(payload):cleanProfile(payload);
    const token=uid(),at=new Date().toISOString();
    const saved=await this.change(meta,(entry,cache)=>{
      const known=baseVersion!==undefined?baseVersion:(kind==='page'?(this.heads.has(Number(pageId))?Number(this.heads.get(Number(pageId))?.version||0):cache?._cloudVersion):cache?.version);
      const foreign=!!entry&&entry.writerId!==this.writerId&&parentId!==entry.localId&&!same(entry.payload,clean);
      // An ACK can clear the previous outbox item AFTER the UI captured its
      // baseVersion but BEFORE this transaction reads it. Rebase only when the
      // exact parent mutation is acknowledged, never from an unrelated/latest
      // cache version (which could belong to another device or tab).
      const memoryAck=parentId?this.acknowledged.get(meta.key)?.get(parentId):null;
      const cacheAck=parentId&&cache?._cloudAck?.ownerId===meta.ownerId&&cache._cloudAck.localId===parentId?cache._cloudAck.version:null;
      const linkedVersion=Math.max(Number(memoryAck)||0,Number(cacheAck)||0);
      const captured=Number.isFinite(known)?Number(known):null;
      const base=entry&&!foreign?entry.baseVersion:(linkedVersion?Math.max(captured||0,linkedVersion):captured);
      const ancestors=entry&&!foreign?[entry.localId,...(entry.ancestors||[])].slice(0,32):[];
      return {entry:{...meta,payload:clean,baseVersion:base,state:entry?.state==='conflict'||foreign?'conflict':'pending',reason:foreign?'other-tab':entry?.reason,remoteVersion:entry?.remoteVersion,localId:token,ancestors,origin:'edit',queuedAt:at,attempts:0,error:null},
        ...(foreign?{backup:{key:'backup:'+meta.key+':'+token,entry:copy(entry),savedAt:at}}:{}),value:{localId:token,ancestors}};
    });
    await this.notify();
    const sending=this.flush();
    if(!saved.durable){await sending;if(await this.entry(meta.key))throw fail('local_unavailable');}
    return {durable:saved.durable,key:meta.key,localId:token,ancestors:saved.value?.ancestors||[]};
  }
  async savePage(page,payload,baseVersion,parentId){
    const result=await this.queue('page',payload,Number(page),baseVersion,parentId);this.clearEmergency(page,payload);
    const head=this.heads.get(Number(page));
    if(!await this.entry(result.key)&&head&&same(cleanPage(head.content),cleanPage(payload)))result.serverVersion=Number(head.version);
    return result;
  }
  async saveProfile(payload,baseVersion,parentId){const saved=await this.queue('profile',payload,undefined,baseVersion,parentId);await this.flush();const entry=await this.entry(saved.key),cache=await this.cached(this.meta('profile'));return {state:entry?entry.state:'synced',error:entry?.error||null,version:Number(cache?.version)||0,localId:entry?.localId||null};}
  async send(entry){
    if(!this.identity||this.identity.id!==entry.ownerId)return;
    if(entry.kind==='page'&&this.member?.pageId!==Number(entry.pageId))return;
    const meta={key:entry.key,kind:entry.kind,pageId:entry.pageId,ownerId:entry.ownerId};
    if(entry.baseVersion===null){
      const row=entry.kind==='page'?await this.fetchPage(entry.pageId):await this.fetchProfile(entry.ownerId);
      await this.accept(meta,row);entry=await this.entry(entry.key);if(!entry||entry.state==='conflict')return;
    }
    if(this.identity?.id!==entry.ownerId)return;
    this.inFlight.add(entry.key);await this.notify();
    try{
      const page=entry.kind==='page';
      const args={p_user_id:entry.ownerId,p_base_version:entry.baseVersion,...(page?{p_page_id:Number(entry.pageId),p_content:entry.payload}:{p_profile:entry.payload})};
      const row=await request(getSupabaseClient().rpc(page?'app_save_page':'app_save_profile',args));
      if(!row||Number(row.version)<1||(page?Number(row.page_id)!==Number(entry.pageId):row.user_id!==entry.ownerId))throw fail('invalid_server_response');
      const cache={...(page?pageRecord(row):profileRecord(row)),_cloudAck:{ownerId:entry.ownerId,localId:entry.localId,version:Number(row.version)}};
      this.rememberAck(entry,Number(row.version));
      if(page)this.heads.set(Number(entry.pageId),row);
      const acknowledged=await this.change(meta,(latest,previous)=>{
        let next=latest;
        if(latest?.localId===entry.localId)next=null;
        else if(latest&&latest.baseVersion===entry.baseVersion&&(latest.writerId===entry.writerId||latest.ancestors?.includes(entry.localId)))next={...latest,baseVersion:Number(row.version),state:'pending',error:null,nextAttemptAt:0};
        const oldVersion=Number(page?previous?._cloudVersion:previous?.version)||0;
        return {entry:next,cache:oldVersion>Number(row.version)?previous:cache,value:next};
      });
      this.errors.delete('rpc:'+entry.kind);
      if(page&&this.identity?.id===entry.ownerId&&this.member?.provisional){
        this.member={pageId:Number(entry.pageId),ownerId:entry.ownerId};this.membershipIssue=null;this.errors.delete('membership');
        await this.putMeta({key:'member:'+entry.ownerId,member:this.member});
        this.onAccount({ownerId:entry.ownerId,member:copy(this.member),cached:false,pending:false});
      }
      if(page&&this.identity?.id===entry.ownerId)this.onPageSaved({ownerId:entry.ownerId,pageId:Number(entry.pageId),version:Number(row.version),localId:entry.localId,writerId:entry.writerId});
      if(!page&&!acknowledged.value&&this.identity?.id===entry.ownerId)this.onProfile({ownerId:entry.ownerId,profile:copy(cache.profile),version:cache.version});
    }catch(error){
      const kind=errorKind(error);
      if(kind==='conflict'){
        this.inFlight.delete(entry.key);
        const row=entry.kind==='page'?await this.fetchPage(entry.pageId):await this.fetchProfile(entry.ownerId);
        await this.accept(meta,row);
      }else{
        if(entry.kind==='page'&&['owned','verification'].includes(kind)&&this.identity?.id===entry.ownerId){
          this.member=null;this.membershipIssue=kind;await this.putMeta({key:'member:'+entry.ownerId,member:null});
          this.onAccount({ownerId:entry.ownerId,member:null,cached:false,pending:false});
        }
        this.note(error,'rpc:'+entry.kind);
        await this.change(meta,latest=>({entry:latest?{...latest,error:kind,attempts:(latest.attempts||0)+1,nextAttemptAt:Date.now()+Math.min(60000,2000*2**Math.min(latest.attempts||0,5))}:null}));
      }
    }finally{this.inFlight.delete(entry.key);await this.notify();}
  }
  flush({force=false}={}){
    if(this.flushPromise){this.flushAgain=true;return this.flushPromise;}
    this.flushPromise=(async()=>{
      if(!this.identity)return;
      let rounds=0;
      do{
        this.flushAgain=false;
        const entries=(await this.allQueue()).filter(e=>e.ownerId===this.identity?.id&&e.state!=='conflict'&&e.error!=='validation'&&(force||!e.nextAttemptAt||e.nextAttemptAt<=Date.now())&&(e.kind!=='page'||(sanitizerReady()&&this.member?.pageId===Number(e.pageId))));
        for(const entry of entries){
          try{await this.send(entry);}catch(error){
            this.note(error,'rpc:'+entry.kind);
            await this.change(entry,latest=>({entry:latest?{...latest,error:errorKind(error),attempts:(latest.attempts||0)+1,nextAttemptAt:Date.now()+10000}:null}));
          }
        }
        const newer=(await this.allQueue()).some(e=>e.ownerId===this.identity?.id&&e.state==='pending'&&!e.error&&!e.nextAttemptAt&&(e.kind!=='page'||(sanitizerReady()&&this.member?.pageId===Number(e.pageId))));
        this.flushAgain=this.flushAgain||newer;
      }while(this.identity&&this.flushAgain&&++rounds<8);
    })().finally(async()=>{
      this.flushPromise=null;await this.notify();this.armRetry();
    });
    return this.flushPromise;
  }
  async armRetry(){
    clearTimeout(this.timer);
    if(!this.identity)return;
    const entries=(await this.allQueue()).filter(e=>e.ownerId===this.identity.id&&e.state==='pending'&&e.error!=='validation'&&(e.kind!=='page'||(sanitizerReady()&&this.member?.pageId===Number(e.pageId))));
    if(!entries.length)return;
    const delay=Math.max(1500,Math.min(...entries.map(e=>Math.max(0,(e.nextAttemptAt||0)-Date.now()))));
    this.timer=setTimeout(()=>this.flush().catch(()=>{}),delay);
  }
  async retry(){
    if(this.identity){
      const ownerId=this.identity.id;
      await this.syncMembership({...this.identity});
      if(this.identity?.id===ownerId){
        const meta=this.meta('profile');
        try{
          const row=await this.fetchProfile(ownerId);
          if(this.identity?.id===ownerId){
            await this.accept(meta,row);
            if(row&&!await this.entry(meta.key))this.onProfile({ownerId,profile:cleanProfile(row.profile),version:Number(row.version)});
          }
        }catch(error){this.note(error,'profile');}
      }
    }
    await this.flush({force:true});await this.notify();
  }
  async resolve(useLocal){
    const entry=(await this.allQueue()).find(e=>e.ownerId===this.identity?.id&&e.state==='conflict'&&(e.kind==='profile'||Number(e.pageId)===this.currentPage));
    if(!entry)return;
    const row=entry.kind==='page'?await this.fetchPage(entry.pageId):await this.fetchProfile(entry.ownerId);
    const version=Number(row?.version)||0,meta={key:entry.key,kind:entry.kind,pageId:entry.pageId,ownerId:entry.ownerId};
    const cache=entry.kind==='page'?(row?pageRecord(row):blankPage(entry.pageId)):(row?profileRecord(row):{key:'profile:'+entry.ownerId,profile:cleanProfile(),version:0});
    await this.change(meta,latest=>({entry:useLocal&&latest?{...latest,state:'pending',baseVersion:version,error:null,nextAttemptAt:0,localId:uid()}:null,cache,backup:{key:'backup:'+entry.key+':'+uid(),entry:copy(latest||entry),savedAt:new Date().toISOString()}}));
    if(entry.kind==='page')this.heads.set(Number(entry.pageId),row);
    else if(!useLocal)this.onProfile({ownerId:entry.ownerId,profile:cache.profile,version:cache.version});
    await this.notify();if(useLocal)await this.flush({force:true});
  }
  async stageRegistrationProfile(remote,profile){
    if(remote?.id)await this.putMeta({key:'registration-draft:'+remote.id,profile:cleanProfile(profile)});
  }
  emergencyPage(page,payload,baseVersion,parentId=null){
    if(!this.identity||this.member?.pageId!==Number(page))return false;
    try{localStorage.setItem('book-emergency:'+this.identity.id+':'+page,JSON.stringify({ownerId:this.identity.id,pageId:Number(page),payload:cleanPage(payload),baseVersion,parentId,writerId:this.writerId,at:new Date().toISOString()}));return true;}catch(_){return false;}
  }
  clearEmergency(page,payload){
    try{const key='book-emergency:'+this.identity?.id+':'+page,raw=localStorage.getItem(key);if(raw&&same(cleanPage(JSON.parse(raw).payload),cleanPage(payload)))localStorage.removeItem(key);}catch(_){}
  }
  async recoverEmergency(){
    if(!this.identity||!this.member||!sanitizerReady())return;
    const meta=this.meta('page',this.member.pageId),key='book-emergency:'+meta.ownerId+':'+meta.pageId;
    try{
      const raw=localStorage.getItem(key);if(!raw)return;const emergency=JSON.parse(raw);
      if(emergency.ownerId!==meta.ownerId||emergency.pageId!==meta.pageId)return;
      const payload=cleanPage(emergency.payload),existing=await this.entry(meta.key);
      if(existing&&(same(existing.payload,payload)||Date.parse(existing.queuedAt)>Date.parse(emergency.at))){localStorage.removeItem(key);return;}
      const recoveryId=uid();
      const saved=await this.change(meta,entry=>{
        const foreign=!!entry&&entry.localId!==emergency.parentId&&entry.writerId!==emergency.writerId;
        return {entry:{...meta,payload,baseVersion:entry&&!foreign?entry.baseVersion:(Number.isInteger(emergency.baseVersion)?emergency.baseVersion:null),state:entry?.state==='conflict'||foreign?'conflict':'pending',reason:foreign?'other-tab':entry?.reason,ancestors:entry&&!foreign?[entry.localId,...(entry.ancestors||[])].slice(0,32):[],origin:'recovered',localId:recoveryId,queuedAt:emergency.at,attempts:0},
          ...(foreign?{backup:{key:'backup:'+meta.key+':'+recoveryId,entry:copy(entry),savedAt:new Date().toISOString()}}:{})};
      });
      if(saved.durable)localStorage.removeItem(key);
    }catch(_){}
  }
  async searchPages(localRecords=[]){
    const byPage=new Map(localRecords.filter(r=>r?._cloudSource).map(r=>[Number(r.pageId),r]));let online=false;
    try{
      const rows=await request(getSupabaseClient().from('app_pages').select('page_id,content,version,updated_at').order('page_id').limit(95));
      rows.forEach(row=>byPage.set(Number(row.page_id),pageRecord(row)));online=true;this.errors.delete('search');
    }catch(error){this.note(error,'search');}
    for(const entry of await this.allQueue())if(entry.kind==='page'&&entry.ownerId===this.identity?.id)byPage.set(Number(entry.pageId),{pageId:Number(entry.pageId),...copy(entry.payload)});
    return {records:[...byPage.values()],online};
  }
  async exportDrafts(){
    const ownerId=this.identity?.id;let archives=[];
    try{const database=await this.database();archives=await new Promise((resolve,reject)=>{const tx=database.transaction(META),read=tx.objectStore(META).getAll();tx.oncomplete=()=>resolve(read.result||[]);tx.onerror=()=>reject(tx.error);});}catch(_){}
    return {format:'capability-book-local-drafts-v1',exportedAt:new Date().toISOString(),
      drafts:(await this.allQueue()).filter(e=>e.ownerId===ownerId).map(({kind,pageId,payload,baseVersion,queuedAt})=>({kind,pageId,payload,baseVersion,queuedAt})),
      conflictBackups:archives.filter(e=>e.key.startsWith('backup:')&&e.entry?.ownerId===ownerId).map(e=>({kind:e.entry.kind,pageId:e.entry.pageId,payload:e.entry.payload,baseVersion:e.entry.baseVersion,savedAt:e.savedAt})),
      legacyPages:archives.filter(e=>e.key.startsWith('legacy-page:')&&e.ownerId===ownerId).map(e=>({pageId:e.record.pageId,payload:cleanPage(e.record)}))};
  }
}
window.BookCloud=Object.freeze({upgrade,sanitizerReady,cleanHtml,cleanPage,cleanProfile,plainFromRich,safePhoto,errorKind,create:options=>new Sync(options)});
})();

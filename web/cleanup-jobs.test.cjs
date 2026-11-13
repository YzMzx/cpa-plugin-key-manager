const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const Jobs = require("./cleanup-jobs.js");
const State = require("./state.js");
const Client = require("./client.js");
const MIB = 1048576, NOW = Date.parse("2026-11-13T12:00:00Z");
const preview = (extra = {}) => ({token:"snapshot-token",expires_at:"2026-11-13T12:05:00Z",records:2300,logical_bytes:70*MIB,request_body_bytes:64*MIB,batch_max_records:1000,batch_max_bytes:32*MIB,scope:"all",...extra});
const job = (extra = {}) => ({id:"job-1",state:"running",total_records:2300,processed_records:1000,deleted_records:990,skipped_records:10,remaining_records:1300,deleted_logical_bytes:12*MIB,deleted_body_bytes:10*MIB,batches:1,batch_max_records:1000,batch_max_bytes:32*MIB,created_at:"2026-11-13T12:00:00Z",updated_at:"2026-11-13T12:00:01Z",error_code:"",...extra});
const deferred = () => {let resolve,reject;const promise = new Promise((a,b) => {resolve=a;reject=b;});return {promise,resolve,reject};};
const tick = () => new Promise(done => setImmediate(done));
class Element {
 constructor(tag="div"){this.tagName=tag;this.children=[];this.value="";this.checked=false;this.disabled=false;this._text="";this.dataset={};this.attributes={};this.listeners={};const set=new Set();this.classList={add:x=>set.add(x),remove:x=>set.delete(x),contains:x=>set.has(x)};}
 set textContent(v){this._text=String(v);this.children=[];} get textContent(){return this._text+this.children.map(c=>c.textContent).join("");}
 set innerHTML(_){throw new Error("dynamic HTML forbidden");} appendChild(n){this.children.push(n);return n;} replaceChildren(){this._text="";this.children=[];}
 setAttribute(k,v){this.attributes[k]=String(v);} removeAttribute(k){delete this.attributes[k];} getAttribute(k){return this.attributes[k]??null;}
 addEventListener(k,v){this.listeners[k]=v;} focus(){this.focused=true;}
}
function fixture(handler, selection=()=>({scope:"all"}), onChanged){
 const html=fs.readFileSync(path.join(__dirname,"index.html"),"utf8"), ids=new Set([...html.matchAll(/id="([^"]+)"/g)].map(m=>m[1]));
 const nodes=new Map(), doc={getElementById:id=>{assert.ok(ids.has(id),"missing production HTML: "+id);if(!nodes.has(id))nodes.set(id,new Element());return nodes.get(id);},createElement:tag=>new Element(tag)};
 const calls=[],timers=new Map();let auth=true,id=0,changed=0;
 const request=async(url,options)=>{calls.push({url,options});return handler ? handler(url,options) : url.endsWith("/preview")?{ok:true,preview:preview()}:options.method==="POST"?{ok:true,job:job()}:{jobs:[]};};
 const view=Jobs.create({document:doc,request,gate:State.createRequestGate(),isAuthenticated:()=>auth,selection,now:()=>NOW,schedule:(fn,ms)=>{assert.equal(ms,1000);timers.set(++id,fn);return id;},unschedule:id=>timers.delete(id),onChanged:async()=>{changed++;if(onChanged)await onChanged();}});
 return {view,calls,doc,node:id=>doc.getElementById(id),timers,setAuth:v=>auth=v,changed:()=>changed,async poll(){const [id,fn]=timers.entries().next().value;timers.delete(id);fn();await tick();}};
}

test("strict preview/job schema rejects malformed or contradictory counters",()=>{
 assert.equal(Jobs.validatePreview({ok:true,preview:preview()},{scope:"all"}).records,2300);
 for(const value of [preview({scope:"expired"}),preview({expires_at:"bad"}),preview({batch_max_bytes:1}),preview({records:NaN})])assert.throws(()=>Jobs.validatePreview({ok:true,preview:value},{scope:"all"}));
 assert.equal(Jobs.validateJob(job()).remaining_records,1300);
 for(const value of [job({state:"other"}),job({processed_records:2400}),job({remaining_records:1}),job({deleted_records:1001}),job({id:""}),job({updated_at:"bad"})])assert.throws(()=>Jobs.validateJob(value));
});

test("one explicit checkbox confirms the entire snapshot, no followup previews or automatic writes",async()=>{
 const f=fixture();await f.view.enter();await f.view.preview();assert.match(f.node("auditCleanupMessage").textContent,/2300 条/);assert.match(f.node("auditCleanupMessage").textContent,/全部快照/);assert.match(f.node("auditCleanupMessage").textContent,/1000/);
 await f.view.start();assert.equal(f.calls.filter(c=>c.options.method==="POST").length,1);
 f.node("auditCleanupAcknowledge").checked=true;await f.view.start();
 const writes=f.calls.filter(c=>c.options.method==="POST");assert.equal(writes.length,2);assert.deepEqual(JSON.parse(writes[1].options.body),{token:"snapshot-token",confirm:true});assert.ok(writes.every(c=>c.url.includes("/cleanup/jobs")));
 assert.equal(f.node("auditCleanupProgress").max,2300);assert.equal(f.node("auditCleanupProgress").value,1000);assert.match(f.node("auditCleanupJobStats").textContent,/990/);assert.equal(f.changed(),1);f.view.leave();
});

test("list restores jobs on entry and polling is sequential without overlap",async()=>{
 const wait=deferred();let reads=0;const f=fixture(async(url,options)=>url.includes("/detail?")?{job:job()}:++reads===1?{jobs:[job()]}:wait.promise);
 await f.view.enter();assert.equal(f.node("auditCleanupJobSelect").value,"job-1");assert.equal(f.timers.size,1);await f.poll();assert.equal(f.timers.size,0);const calls=f.calls.length;const a=f.view.refresh(),b=f.view.refresh();assert.equal(f.calls.length,calls);wait.resolve({jobs:[job({state:"completed",processed_records:2300,deleted_records:2290,remaining_records:0})]});await Promise.all([a,b]);assert.equal(f.timers.size,0);assert.match(f.node("auditCleanupJobState").textContent,/已完成/);f.view.leave();
});

test("leave/lock aborts reads, timers and generations, never cancels backend jobs",async()=>{
 const late=deferred();let first=true;const f=fixture(async url=>url.includes("/detail?")?{job:job()}:first?(first=false,{jobs:[job()]}):late.promise);
 await f.view.enter();await f.poll();const signal=f.calls.at(-1).options.signal;f.view.leave();assert.equal(signal.aborted,true);assert.equal(f.timers.size,0);late.resolve({jobs:[job({id:"late"})]});await tick();assert.ok(!f.calls.some(c=>c.url.endsWith("/cancel")));f.setAuth(false);f.view.lock();assert.equal(f.node("auditCleanupJobSelect").children.length,0);assert.equal(f.node("auditCleanupJobStats").textContent,"");assert.equal(f.node("auditCleanupProgress").getAttribute("value"),null);
});

test("cancel warns irreversible deletions and failed resume uses same job, no new preview",async()=>{
 let current=job({state:"failed",error_code:"sqlite_busy"});const f=fixture(async(url,options)=>{if(url.endsWith("/resume")){assert.deepEqual(JSON.parse(options.body),{id:"job-1"});current=job();return {ok:true,job:current};}if(url.endsWith("/cancel")){current=job({state:"canceled"});return {ok:true,job:current};}return url.includes("/detail?")?{job:current}:{jobs:[current]};});
 await f.view.enter();assert.equal(f.node("auditCleanupJobResume").disabled,false);await f.view.resume();assert.equal(f.calls.filter(c=>c.url.endsWith("/preview")).length,0);
 await f.view.cancel();assert.equal(f.calls.filter(c=>c.url.endsWith("/cancel")).length,0);assert.match(f.node("auditCleanupJobMessage").textContent,/已删除.*不可恢复/);f.node("auditCleanupCancelAcknowledge").checked=true;await f.view.cancel();assert.equal(f.node("auditCleanupJobResume").disabled,true);assert.match(f.node("auditCleanupJobState").textContent,/已取消/);f.view.leave();
});

test("uncertain start queries jobs, retains same token only for manual retry, never auto replays",async()=>{
 let starts=0;const f=fixture(async(url,options)=>{if(url.endsWith("/preview"))return {ok:true,preview:preview()};if(options.method==="POST"){if(++starts===1)throw new Client.APIError("timeout");return {ok:true,job:job()};}return {jobs:[]};});
 await f.view.enter();await f.view.preview();f.node("auditCleanupAcknowledge").checked=true;await f.view.start();assert.equal(starts,1);assert.match(f.node("auditCleanupMessage").textContent,/未确认/);assert.match(f.node("auditCleanupMessage").textContent,/同一/);assert.ok(f.calls.at(-1).options.method==="GET");await f.view.start();assert.equal(starts,2);assert.equal(f.calls.filter(c=>c.url.endsWith("/preview")).length,1);f.view.leave();
});

test("scope/date change invalidates pending preview and blocks a stale response",async()=>{
 const late=deferred();const f=fixture(async(url)=>url.endsWith("/preview")?late.promise:{jobs:[]});await f.view.enter();const p=f.view.preview();const signal=f.calls.at(-1).options.signal;f.node("auditCleanupScope").listeners.change();assert.equal(signal.aborted,true);late.resolve({ok:true,preview:preview()});await p;f.node("auditCleanupAcknowledge").checked=true;await f.view.start();assert.equal(f.calls.filter(c=>c.options.method==="POST").length,1);f.view.leave();
});

test("expired previews and unsupported backend never issue start; auth loss clears state",async()=>{
 const f=fixture(async(url)=>url.endsWith("/preview")?{ok:true,preview:preview({expires_at:"2026-11-13T11:59:59Z"})}:{jobs:[]});await f.view.enter();await f.view.preview();f.node("auditCleanupAcknowledge").checked=true;await f.view.start();assert.equal(f.calls.filter(c=>c.url.endsWith("/jobs")&&c.options.method==="POST").length,0);f.setAuth(false);f.view.lock();assert.equal(f.node("auditCleanupAcknowledge").checked,false);
 const old=fixture(async()=>{const error=new Error("not found");error.status=404;throw error;});await old.view.enter();assert.match(old.node("auditCleanupJobMessage").textContent,/不支持/);assert.equal(old.node("auditCleanupPreview").disabled,true);old.view.leave();
});



test("preview finishing restarts active polling after an in-flight read settles busy",async()=>{
 const read=deferred(),previewWait=deferred();let count=0;const f=fixture(async url=>url.endsWith("/preview")?previewWait.promise:++count===1?{jobs:[job()]}:read.promise);await f.view.enter();await f.poll();const p=f.view.preview();read.resolve({jobs:[job()]});await tick();assert.equal(f.timers.size,0);previewWait.resolve({ok:true,preview:preview()});await p;assert.equal(f.timers.size,1);f.view.leave();
});

test("missing historical detail is not namespace unsupported and active polling survives",async()=>{
 const f=fixture(async url=>{if(url.includes("/detail?")){const error=new Error("gone");error.status=404;throw error;}return {jobs:[job()]};});await f.view.enter();await f.view.refresh("job-1");assert.equal(f.node("auditCleanupPreview").disabled,false);assert.match(f.node("auditCleanupJobMessage").textContent,/读取失败/);assert.equal(f.timers.size,1);await f.view.refresh();assert.match(f.node("auditCleanupJobMessage").textContent,/已从服务端恢复/);f.view.leave();
});

test("terminal audit refresh failure warning remains visible after a successful task list",async()=>{
 let count=0;const f=fixture(async()=>({jobs:[++count===1?job():job({state:"completed",processed_records:2300,deleted_records:2290,remaining_records:0})]}),undefined,async()=>{throw new Error("storage offline");});await f.view.enter();await f.poll();assert.match(f.node("auditCleanupJobMessage").textContent,/刷新失败/);f.view.leave();
});

test("late successful start cannot refill lock or a reentered session",async()=>{
 const wait=deferred();const f=fixture(async(url,options)=>url.endsWith("/preview")?{ok:true,preview:preview()}:options.method==="POST"?wait.promise:{jobs:[]});await f.view.enter();await f.view.preview();f.node("auditCleanupAcknowledge").checked=true;const starting=f.view.start(),signal=f.calls.at(-1).options.signal;f.setAuth(false);f.view.lock();assert.equal(signal.aborted,true);f.setAuth(true);await f.view.enter();wait.resolve({ok:true,job:job()});await starting;assert.equal(f.node("auditCleanupJobSelect").children.length,0);assert.equal(f.changed(),0);assert.equal(f.node("auditCleanupAcknowledge").checked,false);f.view.leave();
});

test("write cancels an older poll and blocks new UI reads until response, never regresses job",async()=>{
 const late=deferred(),write=deferred();let reads=0;const f=fixture(async(url,options)=>options.method==="POST"?write.promise:++reads===1?{jobs:[job()]}:late.promise);await f.view.enter();await f.poll();const signal=f.calls.at(-1).options.signal;f.node("auditCleanupCancelAcknowledge").checked=true;const p=f.view.cancel();assert.equal(signal.aborted,true);assert.equal(f.node("auditCleanupJobsRefresh").disabled,true);const count=f.calls.length;await f.view.refresh();assert.equal(f.calls.length,count);write.resolve({ok:true,job:job({state:"canceled"})});await p;late.resolve({jobs:[job()]});await tick();assert.match(f.node("auditCleanupJobState").textContent,/已取消/);assert.equal(f.timers.size,0);f.view.leave();
});

test("uncertain cancel verifies list even while writes block ordinary refresh",async()=>{
 const f=fixture(async(url,options)=>{if(options.method==="POST")throw new Client.APIError("timeout");return {jobs:[job()]};});await f.view.enter();f.node("auditCleanupCancelAcknowledge").checked=true;await f.view.cancel();assert.equal(f.calls.filter(c=>c.options.method==="POST").length,1);assert.equal(f.calls.filter(c=>c.options.method==="GET").length,2);assert.equal(f.timers.size,1);f.view.leave();
});

test("expired failed snapshot cannot resume or auto-preview and clearly requires new explicit confirmation",async()=>{
 const f=fixture(async()=>({jobs:[job({state:"failed",error_code:"snapshot_expired"})]}));await f.view.enter();assert.equal(f.node("auditCleanupJobResume").disabled,true);assert.match(f.node("auditCleanupJobState").textContent,/不可继续/);assert.match(f.node("auditCleanupJobError").textContent,/已过期.*不可恢复/);assert.match(f.node("auditCleanupJobError").textContent,/手动.*预览.*确认/);await f.view.resume();assert.equal(f.calls.filter(c=>c.options.method==="POST").length,0);assert.equal(f.timers.size,0);f.view.leave();
});

test("native progress and form controls have accessible names and polite status",()=>{
 const html=fs.readFileSync(path.join(__dirname,"index.html"),"utf8");assert.match(html,/<progress[^>]*id="auditCleanupProgress"[^>]*aria-labelledby=/);assert.match(html,/id="auditCleanupJobState"[^>]*role="status"/);assert.match(html,/id="auditCleanupStartForm"[^>]*method="post"/);assert.match(html,/id="auditCleanupConfirm"[^>]*type="submit"|type="submit"[^>]*id="auditCleanupConfirm"/);
});


test("real preview contract accepts expired cutoff and timezone equivalent before, rejects widened scopes",()=>{
 assert.equal(Jobs.validatePreview({ok:true,preview:preview({scope:"expired",before:"2026-11-06T12:00:00Z"})},{scope:"expired"}).before,"2026-11-06T12:00:00Z");
 assert.equal(Jobs.validatePreview({ok:true,preview:preview({scope:"before",before:"2026-11-12T16:00:00Z"})},{scope:"before",before:"2026-11-13T00:00:00+08:00"}).scope,"before");
 assert.throws(()=>Jobs.validatePreview({ok:true,preview:preview({before:"2026-11-13T12:00:00Z"})},{scope:"all"}));
 assert.throws(()=>Jobs.validatePreview({ok:true,preview:preview({scope:"before",before:"2026-11-13T01:00:00+08:00"})},{scope:"before",before:"2026-11-13T00:00:00+08:00"}));
});

test("terminal polling transition refreshes audit data once, without creating another snapshot",async()=>{
 let count=0;const done=job({state:"completed",processed_records:2300,deleted_records:2290,remaining_records:0});const f=fixture(async()=>({jobs:[++count===1?job():done]}));await f.view.enter();assert.equal(f.changed(),0);await f.poll();assert.equal(f.changed(),1);await f.view.refresh();assert.equal(f.changed(),1);assert.equal(f.timers.size,0);assert.equal(f.calls.filter(c=>c.options.method==="POST").length,0);f.view.leave();
});

test("relative cutoff is fixed by preview and does not drift at confirmation",async()=>{
 // The selection clock advances after preview; confirmation must not recalculate it.
 let tick=0;const g=fixture(async(url,options)=>url.endsWith("/preview")?{ok:true,preview:preview({...JSON.parse(options.body)})}:options.method==="POST"?{ok:true,job:job()}:{jobs:[]},()=>({scope:"before",before:new Date(NOW-86400000+tick++).toISOString()}));g.node("auditCleanupScope").value="1d";await g.view.enter();await g.view.preview();g.node("auditCleanupAcknowledge").checked=true;await g.view.start();assert.equal(g.calls.filter(c=>c.url.endsWith("/jobs")&&c.options.method==="POST").length,1);g.view.leave();
});

test("task layout exposes scan-friendly metrics and clears all metadata on lock",async()=>{
 const raw=job({id:"a".repeat(64)}),f=fixture(async()=>({jobs:[raw]}));await f.view.enter();
 assert.equal(f.node("auditCleanupMetricProcessed").textContent,"1,000 / 2,300");
 assert.equal(f.node("auditCleanupMetricDeleted").textContent,"990");
 assert.equal(f.node("auditCleanupMetricRemaining").textContent,"1,300");
 assert.equal(f.node("auditCleanupMetricSkipped").textContent,"10");
 assert.equal(f.node("auditCleanupMetricBatches").textContent,"1");
 assert.equal(f.node("auditCleanupPercent").textContent,"43.5%");
 assert.equal(f.node("auditCleanupJobBadge").getAttribute("data-state"),"running");
 assert.match(f.node("auditCleanupJobMeta").textContent,/a{64}/);
 assert.ok(!f.node("auditCleanupJobSelect").children[0].textContent.includes("a".repeat(64)));
 f.view.lock();for(const id of ["auditCleanupJobBadge","auditCleanupPercent","auditCleanupMetricProcessed","auditCleanupMetricDeleted","auditCleanupMetricSkipped","auditCleanupMetricRemaining","auditCleanupMetricBytes","auditCleanupMetricBatches","auditCleanupJobMeta"])assert.equal(f.node(id).textContent,"");
 assert.equal(f.node("auditCleanupJobBadge").getAttribute("data-state"),null);
});
test("empty completed task shows a finished progress bar without invented records",async()=>{
 const f=fixture(async()=>({jobs:[job({state:"completed",total_records:0,processed_records:0,deleted_records:0,skipped_records:0,remaining_records:0,deleted_logical_bytes:0,deleted_body_bytes:0,batches:0})]}));await f.view.enter();
 assert.equal(f.node("auditCleanupPercent").textContent,"100.0%");assert.equal(f.node("auditCleanupProgress").value,1);assert.equal(f.node("auditCleanupMetricProcessed").textContent,"0 / 0");f.view.lock();
});

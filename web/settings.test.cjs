const test=require("node:test");
const assert=require("node:assert/strict");
const fs=require("node:fs");
const path=require("node:path");
const Settings=require("./settings.js");
const State=require("./state.js");
const Client=require("./client.js");
const MIB=1048576;
const config=()=>({audit:{enabled:true,retention_days:7,max_records:10000,max_body_bytes:10*MIB,max_total_bytes:64*MIB},storage:{flush_interval_seconds:10,ledger_retention_days:90,timezone:"Asia/Shanghai",pricing_cache_file:"data/models.json"},pricing:{sync_url:"https://models.dev/api.json",sync_interval_hours:24,http_timeout_seconds:30,auto_inject_include_usage:true}});
const bootstrap=(extra={})=>({effective:{enabled:true,priority:0,usage_db_file:"D:/CPA/data/key_usage.db",admin_token_configured:true},configured:{enabled:true,priority:0,usage_db_file:"./data/key_usage.db",admin_token_configured:true},file_revision:"file-sha",available:true,db_path_locked_by_env:false,...extra});
const payload=(extra={})=>({settings:config(),rules_revision:7,bootstrap:bootstrap(),deprecated:{rules_file:"data/legacy.json",usage_file:"data/usage.json"},...extra});
const deferred=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return{promise,resolve,reject};};
class Element{
 constructor(){this.value="";this.checked=false;this.disabled=false;this.textContent="";this.style={};this.children=[];this.listeners={};const set=new Set();this.classList={add:v=>set.add(v),remove:v=>set.delete(v),contains:v=>set.has(v)};}
 addEventListener(type,fn){this.listeners[type]=fn;}
 appendChild(value){this.children.push(value);return value;}
 replaceChildren(){this.children=[];this.textContent="";}
 set innerHTML(_){throw new Error("settings may not render dynamic HTML");}
}
function fixture(handler=async()=>payload(),onSaved=async()=>{}){
 const nodes=new Map();const doc={getElementById:id=>{if(!nodes.has(id))nodes.set(id,new Element());return nodes.get(id);},createElement:()=>new Element()};let auth=true;const calls=[],navigation=[];
 const view=Settings.create({document:doc,request:async(url,options)=>{calls.push({url,options});return handler(url,options);},gate:State.createRequestGate(),isAuthenticated:()=>auth,onSaved,navigate:tab=>navigation.push(tab)});
 const node=id=>doc.getElementById(id);return{view,node,calls,navigation,setAuth:v=>auth=v,change:(id,value)=>{const el=node(id);if(typeof value==="boolean")el.checked=value;else el.value=String(value);el.listeners.input();}};
}

test("validate bounded groups and reject URL credentials, query or unsafe numbers",()=>{
 assert.deepEqual(Settings.validateSettings(config()),config());
 for(const change of [v=>v.audit.max_total_bytes=1024*MIB+1,v=>v.audit.max_body_bytes=11*MIB,v=>v.audit.max_records=1.1,v=>v.storage.flush_interval_seconds=3601,v=>v.pricing.sync_interval_hours=721,v=>v.pricing.http_timeout_seconds=301,v=>v.audit.enabled="true",v=>v.storage.timezone="invalid/zone",v=>v.pricing.sync_url="https://user:pass@host/path",v=>v.pricing.sync_url="https://host/path?token=secret",v=>v.pricing.sync_url="javascript:alert(1)"]){const current=config();change(current);assert.throws(()=>Settings.validateSettings(current));}
 assert.throws(()=>Settings.validatePayload(payload({rules_revision:null})));
});

test("MiB inputs and configured bootstrap path are rendered without token echo",async()=>{
 const f=fixture();await f.view.enter();assert.equal(f.node("settingAuditTotalMiB").value,"64");assert.equal(f.node("settingAuditBodyMiB").value,"10");assert.equal(f.node("settingBootstrapDB").value,"./data/key_usage.db");assert.equal(f.node("settingBootstrapAdminToken").value,"");assert.equal(f.node("settingsSave").disabled,true);
 assert.ok(f.node("settingsBootstrap").children.some(el=>el.textContent.includes("已配置")));
});

test("dirty draft survives refresh/tab exit and invalid values never issue a PUT",async()=>{
 const f=fixture();await f.view.enter();f.change("settingAuditTotalMiB",512);assert.equal(f.view.isDirty(),true);const calls=f.calls.length;await f.view.refresh();assert.equal(f.calls.length,calls);f.view.leave();await f.view.enter();assert.equal(f.node("settingAuditTotalMiB").value,"512");
 f.change("settingFlushSeconds","NaN");await f.view.save();assert.equal(f.calls.length,calls);assert.match(f.node("settingsMessage").textContent,/有限/);
});

test("save sends exact byte conversion, body CAS and explicit revision header",async()=>{
 const f=fixture(async(url,options)=>options.method==="GET"?payload():payload({ok:true,settings:JSON.parse(options.body).settings,rules_revision:8}));await f.view.enter();f.change("settingAuditTotalMiB",1024);await f.view.save();const save=f.calls.at(-1);assert.equal(save.options.method,"PUT");assert.equal(save.options.headers["X-Key-Guard-Revision"],"7");const body=JSON.parse(save.options.body);assert.equal(body.expected_revision,7);assert.equal(body.settings.audit.max_total_bytes,1073741824);assert.equal(f.view.isDirty(),false);assert.equal(f.node("settingsSave").disabled,true);
});

test("shrinking retention needs an explicit acknowledgement before PUT",async()=>{
 const f=fixture(async(url,options)=>options.method==="GET"?payload():payload({ok:true,settings:JSON.parse(options.body).settings,rules_revision:8}));await f.view.enter();f.change("settingAuditRetention",3);await f.view.save();assert.equal(f.calls.length,1);assert.match(f.node("settingsMessage").textContent,/勾选/);assert.equal(f.node("settingsPruneWarning").classList.contains("hidden"),false);f.node("settingsAcknowledgePrune").checked=true;await f.view.save();assert.equal(JSON.parse(f.calls.at(-1).options.body).ack_prune,true);
});

test("409 keeps draft and never automatically retries a settings save",async()=>{
 const f=fixture(async(url,options)=>{if(options.method==="GET")return payload();const error=new Error("conflict");error.status=409;throw error;});await f.view.enter();f.change("settingAuditTotalMiB",512);await f.view.save();assert.equal(f.calls.length,2);assert.equal(f.view.isDirty(),true);assert.equal(f.node("settingAuditTotalMiB").value,"512");assert.match(f.node("settingsMessage").textContent,/其它会话/);
});

test("save is single-flight; refresh failure after success is not reported as save failure",async()=>{
 const pending=deferred();const f=fixture(async(url,options)=>options.method==="GET"?payload():pending.promise,async()=>{throw new Error("refresh offline");});await f.view.enter();f.change("settingAuditTotalMiB",128);const first=f.view.save();await f.view.save();assert.equal(f.calls.length,2);const saved=config();saved.audit.max_total_bytes=128*MIB;pending.resolve(payload({ok:true,settings:saved,rules_revision:8}));await first;assert.equal(f.view.isDirty(),false);assert.match(f.node("settingsMessage").textContent,/已保存，但页面刷新失败/);
});

test("lock cancels a read, clears sensitive drafts and ignores its late payload",async()=>{
 const late=deferred();const f=fixture(()=>late.promise);const entering=f.view.enter();const signal=f.calls[0].options.signal;f.node("settingBootstrapAdminToken").value="sensitive";f.setAuth(false);f.view.lock();assert.equal(signal.aborted,true);late.resolve(payload());await entering;assert.equal(f.node("settingBootstrapAdminToken").value,"");assert.equal(f.node("settingTimezone").value,"");assert.equal(f.node("settingsSave").disabled,true);assert.equal(f.node("settingsBootstrap").children.length,0);
});

test("read begun before typing cannot overwrite a newer draft",async()=>{
 let count=0;const late=deferred();const f=fixture(()=>++count===1?Promise.resolve(payload()):late.promise);await f.view.enter();const reading=f.view.refresh();f.change("settingTimezone","UTC");const server=config();server.storage.timezone="Europe/London";late.resolve(payload({settings:server}));await reading;assert.equal(f.node("settingTimezone").value,"UTC");assert.equal(f.view.isDirty(),true);
});

test("bootstrap save requires restart/path acknowledgements and treats token as write-only",async()=>{
 const f=fixture(async(url,options)=>options.method==="GET"?payload():{ok:true,requires_restart:true,bootstrap:bootstrap({configured:{...bootstrap().configured,usage_db_file:"./new/audit.db"},file_revision:"next-file"})});await f.view.enter();f.change("settingBootstrapDB","./new/audit.db");f.change("settingBootstrapAdminToken","new-private-value");await f.view.saveBootstrap();assert.equal(f.calls.length,1);f.node("settingsAcknowledgeRestart").checked=true;await f.view.saveBootstrap();assert.equal(f.calls.length,1);f.node("settingsAcknowledgeDBChange").checked=true;await f.view.saveBootstrap();assert.equal(f.calls.length,2);const body=JSON.parse(f.calls.at(-1).options.body);assert.equal(body.expected_file_revision,"file-sha");assert.equal(body.ack_restart,true);assert.equal(body.ack_storage_path_change,true);assert.equal(body.bootstrap.admin_token,"new-private-value");assert.equal(f.node("settingBootstrapAdminToken").value,"");assert.match(f.node("settingsBootstrapMessage").textContent,/热重载/);
});

test("environment lock and clear/set token conflict never issue a mutation",async()=>{
 const f=fixture(async()=>payload({bootstrap:bootstrap({db_path_locked_by_env:true})}));await f.view.enter();assert.equal(f.node("settingBootstrapDB").disabled,true);f.change("settingBootstrapAdminToken","new-value");f.change("settingBootstrapClearToken",true);f.node("settingsAcknowledgeRestart").checked=true;await f.view.saveBootstrap();assert.equal(f.calls.length,1);assert.match(f.node("settingsBootstrapMessage").textContent,/不能同时/);f.view.leave();assert.equal(f.node("settingBootstrapAdminToken").value,"");
});

test("navigation cards reuse existing key, policy and pricing editors",()=>{
 const f=fixture();for(const id of ["settingsJumpKeys","settingsJumpPolicy","settingsJumpPricing"])f.node(id).listeners.click();assert.deepEqual(f.navigation,["tab-keys","tab-routing","tab-pricing"]);
});

test("production client preserves an explicit fresh settings revision instead of stale overview",async()=>{
 let options;const client=Client.createClient({getKey:()=>"admin",getRevision:()=>2,fetchImpl:async(url,value)=>{options=value;return new Response(JSON.stringify(payload({ok:true,rules_revision:8})),{headers:{"Content-Type":"application/json"}});}});await client.request("/v0/management/key-guard/settings",{method:"PUT",headers:{"X-Key-Guard-Revision":"7"},body:"{}"});assert.equal(options.headers.get("X-Key-Guard-Revision"),"7");
});

test("unified page exposes grouped settings and honest bootstrap/media boundaries",()=>{
 const html=fs.readFileSync(path.join(__dirname,"index.html"),"utf8");for(const text of ["tab-settings","请求审计","用量与时间","模型价格同步","保存启动配置","不留存","不是 CPA 的 Management Key"])assert.ok(html.includes(text),text);assert.ok(html.includes('type="password" autocomplete="new-password"'));assert.ok(!html.includes('id="settingBootstrapAdminToken" value='));assert.ok(!fs.readFileSync(path.join(__dirname,"settings.js"),"utf8").includes("innerHTML"));
});

test("backend deprecated array and pending apply result render honestly",async()=>{
 const f=fixture(async(url,options)=>options.method==="GET"?payload({deprecated:["admin_token","storage.usage_file","audit.trusted_proxies"],readonly:{bootstrap:{usage_db_file:"data/active.db"}}}):payload({ok:true,settings:JSON.parse(options.body).settings,rules_revision:8,apply_status:{ok:false,error:"retry"}}));
 await f.view.enter();assert.ok(f.node("settingsDeprecated").children.some(el=>el.textContent.includes("不是 CPA")));assert.ok(f.node("settingsDeprecated").children.some(el=>el.textContent==="data/active.db"));f.change("settingAuditTotalMiB",128);await f.view.save();assert.match(f.node("settingsMessage").textContent,/已保存，但热应用未完成/);assert.equal(f.view.isDirty(),false);
});

test("URL empty query and bootstrap token control characters fail before mutation",async()=>{
 const current=config();current.pricing.sync_url="https://models.dev/api.json?";assert.throws(()=>Settings.validateSettings(current));
 const f=fixture();await f.view.enter();f.change("settingBootstrapAdminToken","unsafe"+String.fromCharCode(10)+"token");f.node("settingsAcknowledgeRestart").checked=true;await f.view.saveBootstrap();assert.equal(f.calls.length,1);assert.match(f.node("settingsBootstrapMessage").textContent,/控制字符/);
});

test("bootstrap save disables the entire group and restores env/availability constraints",async()=>{
 const pending=deferred();const f=fixture(async(url,options)=>options.method==="GET"?payload({bootstrap:bootstrap({db_path_locked_by_env:true})}):pending.promise);
 await f.view.enter();f.change("settingBootstrapPriority",1);f.node("settingsAcknowledgeRestart").checked=true;
 const saving=f.view.saveBootstrap();
 for(const id of ["settingBootstrapEnabled","settingBootstrapPriority","settingBootstrapDB","settingBootstrapAdminToken","settingBootstrapClearToken","settingsAcknowledgeRestart","settingsAcknowledgeDBChange"])assert.equal(f.node(id).disabled,true,id);
 pending.resolve({ok:true,requires_restart:true,bootstrap:bootstrap({db_path_locked_by_env:true,configured:{...bootstrap().configured,priority:1}})});await saving;
 assert.equal(f.node("settingBootstrapPriority").disabled,false);assert.equal(f.node("settingBootstrapAdminToken").disabled,false);assert.equal(f.node("settingBootstrapDB").disabled,true);assert.equal(f.node("settingsBootstrapSave").disabled,true);
});

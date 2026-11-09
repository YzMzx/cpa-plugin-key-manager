const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const Audit = require("./audit.js");
const State = require("./state.js");
const status = extra => ({enabled:true,retention_days:7,max_records:10000,max_body_bytes:65536,max_total_bytes:10485760,...extra});
const record = (id, extra={}) => ({id,request_id:"req-"+id,trace_id:"trace-"+id,started_at:"2026-11-09T12:00:00Z",completed_at:"2026-11-09T12:00:01Z",client_ip:"",peer_ip:"",ip_source:"unknown",key_label:"team",key_fingerprint:"fp",requested_model:"m",served_model:"m",outcome:"succeeded",status_code:200,duration_ms:1,body_state:"redacted",...extra});
const list = (items,extra={}) => ({items,total:items.length,limit:50,offset:0,status:status(),...extra});
const deferred = () => {let resolve;const promise=new Promise(done=>resolve=done);return {promise,resolve};};
const tick = () => new Promise(done=>setImmediate(done));
class Element {
 constructor(tag="div"){this.tagName=tag;this.children=[];this.value="";this._text="";this.dataset={};this.listeners={};this.disabled=false;this.className="";const classes=new Set();this.classList={add:x=>classes.add(x),remove:x=>classes.delete(x),contains:x=>classes.has(x)};}
 set textContent(value){this._text=String(value);this.children=[];}
 get textContent(){return this._text+this.children.map(c=>c.textContent).join("");}
 set innerHTML(value){throw new Error("audit must never render dynamic markup: "+value);}
 appendChild(child){this.children.push(child);return child;}
 replaceChildren(){this.children=[];this._text="";}
 addEventListener(type,fn){this.listeners[type]=fn;}
 setAttribute(name,value){(this.attributes ||= {})[name]=String(value);}
 getAttribute(name){return this.attributes?.[name]??null;}
 focus(){if(this.ownerDocument)this.ownerDocument.activeElement=this;}
 contains(node){return node===this||this.children.some(child=>child.contains&&child.contains(node));}
 querySelectorAll(){return this.focusable||[];}
}
function fixture(handler){
 const nodes=new Map();const doc={activeElement:null,getElementById:id=>{if(!nodes.has(id)){const el=new Element();el.ownerDocument=doc;nodes.set(id,el);}return nodes.get(id);},createElement:tag=>{const el=new Element(tag);el.ownerDocument=doc;return el;}};doc.body=new Element();doc.body.ownerDocument=doc;
 let auth=true;const calls=[];
 const request=async(url,options)=>{calls.push({url,options});if(url.endsWith("/status"))return {status:status({warning:"宿主未提供客户端IP"})};if(url.endsWith("/storage"))return {storage:{records:0,logical_bytes:0,request_body_bytes:0,max_total_bytes:10485760,db_file_bytes:4096,wal_file_bytes:0,expired_records:0}};return handler(url,options);};
 const view=Audit.create({document:doc,request,gate:State.createRequestGate(),isAuthenticated:()=>auth,getTimezone:()=>"UTC",getKeyOptions:()=>[{value:"a".repeat(64),label:"工作密钥 · sk-***1234"}]});
 return {view,calls,doc,node:id=>doc.getElementById(id),setAuth:value=>auth=value};
}

test("audit validates list without body and rejects malformed pagination/status",()=>{
 assert.equal(Audit.validateList(list([record("a")])).total,1);
 assert.throws(()=>Audit.validateList(list([record("a",{request_body:"sensitive"})])),/列表不得包含请求正文/);
 for(const extra of [{offset:-1},{limit:0},{total:NaN},{items:[{}]},{status:{enabled:true}}])assert.throws(()=>Audit.validateList(list([],extra)));
 assert.throws(()=>Audit.validateDetail({record:record("other"),status:status()},"a"),/不一致/);
 assert.equal(Audit.statusPayload({status:status()}).retention_days,7);
});

test("five filters encode literal values and omit removed identifiers/time fields",()=>{
 const params=new URLSearchParams(Audit.queryString({key_fingerprint:"a".repeat(64),key_label:"备注&'",model:"模型<x>",outcome:"failed",ip:"::1",request_id:"gone",trace_id:"gone",from:"invalid",to:"invalid"},50,0));
 assert.equal(params.get("key_label"),"备注&'");assert.equal(params.get("model"),"模型<x>");assert.equal(params.get("ip"),"::1");
 for(const key of ["request_id","trace_id","from","to"])assert.equal(params.has(key),false);
 assert.equal(Audit.timestamp(0,"UTC"),"未知");
});

test("JSON body is decoded read-only while non-JSON stays omitted",()=>{
 const value=Audit.bodyView(record("a",{request_body:'{"messages":[{"content":"<img onerror=evil()>"}]}'}));
 assert.match(value.json,/<img onerror=evil/);assert.ok(value.json.includes(String.fromCharCode(10)));
 assert.match(Audit.bodyView(record("a",{request_body:"not json"})).state,/解码失败/);
 assert.match(Audit.bodyView(record("a",{body_state:"omitted_input_limit",body_truncated:true})).state,/正文已略过/);
});

test("list loads metadata only and detail is fetched on explicit selection with text-only rendering",async()=>{
 const attack="<img src=x onerror=globalThis.pwned=true>";
 const f=fixture(async url=>url.includes("/detail?")?{record:record("a",{request_body:{messages:[{content:attack}]},ip_note:attack,path:attack,body_sha256:"hash"}),status:status()}:list([record("a",{key_label:attack})]));
 await f.view.enter();assert.equal(f.calls.filter(c=>c.url.includes("/detail?")).length,0);
 assert.match(f.node("auditListBody").textContent,/<img/);assert.match(f.node("auditListBody").textContent,/unknown/);assert.match(f.node("auditListBody").textContent,/未知/);
 await f.view.showDetail("a");assert.equal(f.calls.filter(c=>c.url.includes("/detail?")).length,1);assert.match(f.node("auditRequestBody").textContent,/<img/);assert.match(f.node("auditDetailMetadata").textContent,/<img/);assert.equal(f.node("auditBodyHash").textContent,"hash");
 assert.ok(f.calls.every(c=>c.url.startsWith("/v0/management/key-guard/audit")&&c.options.method==="GET"));
});

test("late detail cannot overwrite a new record or return after close",async()=>{
 const a=deferred(),b=deferred();const f=fixture(url=>url.includes("/detail?id=a")?a.promise:url.includes("/detail?id=b")?b.promise:Promise.resolve(list([record("a"),record("b")])));
 await f.view.enter();const first=f.view.showDetail("a");const second=f.view.showDetail("b");b.resolve({record:record("b",{request_body:{selected:"b"}}),status:status()});await second;
 a.resolve({record:record("a",{request_body:{selected:"a"}}),status:status()});await first;assert.match(f.node("auditRequestBody").textContent,/"b"/);assert.doesNotMatch(f.node("auditRequestBody").textContent,/"a"/);
 const c=deferred();const g=fixture(url=>url.includes("/detail?")?c.promise:Promise.resolve(list([record("a")])));await g.view.enter();const pending=g.view.showDetail("a");g.view.closeDetail();c.resolve({record:record("a",{request_body:{secret:"gone"}}),status:status()});await pending;assert.equal(g.node("auditRequestBody").textContent,"");assert.ok(g.node("auditDetail").classList.contains("hidden"));
});

test("late list cannot replace new filters even when transport ignores abort",async()=>{
 const first=deferred(),second=deferred();let n=0;const f=fixture(()=>++n===1?first.promise:second.promise);
 const one=f.view.enter();f.node("auditModel").value="new-model";const two=f.view.applyFilters();second.resolve(list([record("new")]));await two;first.resolve(list([record("old")]));await one;
 assert.match(f.node("auditListBody").textContent,/req-new/);assert.doesNotMatch(f.node("auditListBody").textContent,/req-old/);assert.ok(f.calls.some(c=>c.url.includes("model=new-model")));
});

test("pagination stays bounded and corrects an expired last page once",async()=>{
 const f=fixture(url=>{const offset=Number(new URL("http://test"+url).searchParams.get("offset"));return Promise.resolve(offset===50?list([],{offset:50,total:2}):list([record("a"),record("b")],{total:f.calls.filter(c=>!c.url.endsWith("/status")).length>1?2:51}));});
 await f.view.enter();assert.equal(f.node("auditPrevPage").disabled,true);assert.equal(f.node("auditNextPage").disabled,false);await f.view.page(1);assert.equal(f.node("auditNextPage").disabled,true);assert.equal(f.node("auditPrevPage").disabled,true);assert.match(f.node("auditPageInfo").textContent,/共 2 条/);
 const count=f.calls.length;await f.view.page(1);await f.view.page(-1);assert.equal(f.calls.length,count);
});

test("lock aborts audit requests and clears metadata, filters and decoded body",async()=>{
 const late=deferred();const f=fixture(url=>url.includes("/detail?")?late.promise:Promise.resolve(list([record("a")])));await f.view.enter();f.node("auditKeyLabel").value="sensitive request";const pending=f.view.showDetail("a");const signal=f.calls.at(-1).options.signal;
 f.setAuth(false);f.view.lock();assert.ok(signal.aborted);late.resolve({record:record("a",{request_body:{secret:"late"}}),status:status()});await pending;
 for(const id of ["auditRequestBody","auditDetailMetadata","auditBodyHash","auditKeyLabel"])assert.equal(id==="auditKeyLabel"?f.node(id).value:f.node(id).textContent,"");
 assert.doesNotMatch(f.node("auditListBody").textContent,/req-a/);const count=f.calls.length;await f.view.refresh();await f.view.showDetail("a");assert.equal(f.calls.length,count);
});

test("disabled audit and failures are explicit rather than fake records",async()=>{
 const f=fixture(()=>Promise.resolve(list([],{status:status({enabled:false})})));await f.view.enter();assert.match(f.node("auditStatus").textContent,/未启用/);assert.match(f.node("auditListBody").textContent,/未启用/);
 const g=fixture(()=>Promise.reject(new Error("offline")));await g.view.enter();assert.match(g.node("auditListMessage").textContent,/offline/);assert.equal(g.node("auditNextPage").disabled,true);
});

test("audit UI uses fixed drawer, five filters and no removed privacy banner",()=>{
 const html=fs.readFileSync(path.join(__dirname,"index.html"),"utf8");const source=fs.readFileSync(path.join(__dirname,"audit.js"),"utf8");const css=fs.readFileSync(path.join(__dirname,"app.css"),"utf8");
 for(const phrase of ["请求审计","保留 7 天","不记录响应","防篡改证明"])assert.ok(html.includes(phrase));
 assert.ok(!html.includes("请求正文可能包含对话、个人信息和业务数据。"));
 for(const id of ["auditKey","auditKeyLabel","auditModel","auditOutcome","auditIP"])assert.ok(html.includes('id="'+id+'"'));
 for(const id of ["auditRequestId","auditTraceId","auditKeyFingerprint","auditFrom","auditTo"])assert.ok(!html.includes('id="'+id+'"'));
 assert.match(html,/role="dialog" aria-modal="true"/);assert.match(css,/audit-drawer-overlay[^}]+position: fixed/);
 for(const forbidden of ["innerHTML","eval(","new Function","response_body"])assert.ok(!source.includes(forbidden));
});

test("invalid calendar dates are not normalized into different audit filters",()=>{
 for(const value of ["2026-02-30T00:00:00Z","2026-00-01T00:00:00Z","2026-11-09T25:00:00Z","2026-11-09T00:00:00+24:00"]) {assert.equal(Audit.timestamp(value,"UTC"),"未知");}
});

test("leaving audit cancels in-flight list and a late result stays invisible",async()=>{
 const pending=deferred();const f=fixture(()=>pending.promise);const entering=f.view.enter();const request=f.calls.find(call=>call.url.includes("/audit?"));f.view.leave();assert.ok(request.options.signal.aborted);pending.resolve(list([record("late")]));await entering;assert.doesNotMatch(f.node("auditListBody").textContent,/req-late/);
});

test("omitted or truncated body never displays accidental raw content",()=>{
 for(const body_state of ["omitted_encoding","omitted_non_json","omitted_invalid_json","omitted_input_limit","omitted_non_container","omitted_depth_limit","omitted_element_limit","omitted_string_limit","omitted_number_limit","omitted_ambiguous_json","omitted_output_limit","unknown"])assert.doesNotMatch(Audit.bodyView(record("a",{body_state,request_body:{secret:"must-not-render"}})).json,/must-not-render/);
 assert.doesNotMatch(Audit.bodyView(record("a",{body_truncated:true,request_body:{secret:"must-not-render"}})).json,/must-not-render/);
});

test("filter reset and page-size change restart at offset zero",async()=>{
 const f=fixture(url=>{const params=new URL("http://test"+url).searchParams;return Promise.resolve(list([record("a")],{total:201,limit:Number(params.get("limit")),offset:Number(params.get("offset"))}));});
 await f.view.enter();await f.view.page(1);f.node("auditPageSize").value="25";f.node("auditPageSize").listeners.change();await tick();
 let latest=f.calls.filter(call=>call.url.includes("/audit?")).at(-1).url;assert.ok(latest.includes("limit=25&offset=0"));
 f.node("auditModel").value="specific";await f.view.applyFilters();await f.view.page(1);await f.view.resetFilters();
 latest=f.calls.filter(call=>call.url.includes("/audit?")).at(-1).url;assert.ok(latest.includes("offset=0"));assert.ok(!latest.includes("model="));assert.equal(f.node("auditModel").value,"");
 f.node("auditKeyLabel").value="团队";await f.view.applyFilters();assert.ok(f.calls.at(-1).url.includes("key_label="));
});

test("detail response must match requested audit id",async()=>{
 const f=fixture(url=>Promise.resolve(url.includes("/detail?")?{record:record("wrong",{request_body:{secret:"wrong"}}),status:status()}:list([record("a")])));await f.view.enter();await f.view.showDetail("a");assert.match(f.node("auditDetailMessage").textContent,/不一致/);assert.equal(f.node("auditRequestBody").textContent,"");
});

test("audit status keeps capture failures visible after later successful reads",async()=>{
 const f=fixture(async()=>list([],{status:status({capture_failures:2,last_capture_failure_at:"2026-11-09T12:00:00Z"})}));
 await f.view.enter();assert.match(f.node("auditStatus").textContent,/采集失败 2 次/);
});

test("large stored JSON stays compact and omitted bodies remain hidden",()=>{
 const raw=JSON.stringify({messages:[{role:"user",content:"长提示词 ".repeat(70000)}]});
 const value=Audit.bodyView(record("large",{body_state:"stored",request_body:raw}));
 assert.equal(value.json,raw);assert.match(value.state,/紧凑/);
 const omitted=Audit.bodyView(record("large",{body_state:"omitted_output_limit",request_body:raw,body_truncated:true}));
 assert.notEqual(omitted.json,raw);
});

test("detail drawer opens in viewport, changes adjacent record, Esc restores trigger focus",async()=>{
 const f=fixture(async url=>url.includes("/detail?")?{record:record(new URL("http://test"+url).searchParams.get("id"),{body_state:"stored",request_body:'{"value":"safe"}'}),status:status()}:list([record("a"),record("b")]));
 await f.view.enter();
 const trigger=f.node("auditListBody").children[0].children[9].children[0];trigger.focus();
 await f.view.showDetail("a",trigger);
 assert.equal(f.node("auditDetail").classList.contains("hidden"),false);assert.equal(f.doc.body.classList.contains("audit-detail-open"),true);
 assert.equal(f.doc.activeElement,f.node("auditDetailClose"));assert.equal(f.node("auditDetailContent").scrollTop,0);assert.equal(f.node("auditDetailPrev").disabled,true);assert.equal(trigger.getAttribute("aria-expanded"),"true");
 await f.node("auditDetailNext").listeners.click();assert.ok(f.node("auditDetailPosition").textContent.includes("2 / 2"));assert.equal(f.node("auditDetailNext").disabled,true);
 let prevented=false;f.node("auditDetail").listeners.keydown({key:"Escape",preventDefault(){prevented=true},stopPropagation(){}});
 assert.equal(prevented,true);assert.equal(f.node("auditDetail").classList.contains("hidden"),true);assert.equal(f.doc.activeElement,trigger);assert.equal(f.doc.body.classList.contains("audit-detail-open"),false);assert.equal(f.node("auditRequestBody").textContent,"");
});

test("drawer backdrop closes while panel clicks do not; Tab remains inside",async()=>{
 const f=fixture(async url=>url.includes("/detail?")?{record:record("a",{request_body:"{}"}),status:status()}:list([record("a")]));
 await f.view.enter();await f.view.showDetail("a");
 f.node("auditDetail").listeners.click({target:f.node("auditDetailPanel")});assert.equal(f.node("auditDetail").classList.contains("hidden"),false);
 const first=f.node("auditDetailPrev"),last=f.node("auditRequestBody");f.node("auditDetailPanel").focusable=[first,last];last.focus();
 let trapped=false;f.node("auditDetail").listeners.keydown({key:"Tab",preventDefault(){trapped=true}});assert.equal(trapped,true);assert.equal(f.doc.activeElement,first);
 f.node("auditDetail").listeners.click({target:f.node("auditDetail")});assert.equal(f.node("auditDetail").classList.contains("hidden"),true);
});

test("API key selector sends only fingerprints and remark/model search text",async()=>{
 const f=fixture(async url=>list([record("a",{key_fingerprint:"a".repeat(64)})]));await f.view.enter();
 assert.match(f.node("auditKey").textContent,/工作密钥/);f.node("auditKey").value="a".repeat(64);f.node("auditKeyLabel").value="生产团队";f.node("auditModel").value="sonnet";
 await f.view.applyFilters();const url=f.calls.filter(call=>call.url.includes("/audit?")).at(-1).url;const p=new URL("http://t"+url).searchParams;
 assert.equal(p.get("key_fingerprint"),"a".repeat(64));assert.equal(p.get("key_label"),"生产团队");assert.equal(p.get("model"),"sonnet");assert.equal(p.has("api_key"),false);
});

test("cleanup previews count/bytes and requires explicit confirmation before single-use POST",async()=>{
 let apply=0;const f=fixture(async(url,opts)=>{
  if(url.endsWith("/cleanup/preview"))return{preview:{token:"safe-token",scope:"all",records:2,logical_bytes:2048,request_body_bytes:1024},storage:{records:2,logical_bytes:2048,request_body_bytes:1024,max_total_bytes:4096}};
  if(url.endsWith("/cleanup")){apply++;return{ok:true,deleted:{records:2,logical_bytes:2048,request_body_bytes:1024},storage:{records:0,logical_bytes:0,request_body_bytes:0,max_total_bytes:4096}};}
  return list([]);
 });await f.view.enter();assert.match(f.node("auditStorageSummary").textContent,/逻辑占用/);f.node("auditCleanupScope").value="all";
 await f.view.previewCleanup();assert.equal(apply,0);assert.match(f.node("auditCleanupMessage").textContent,/2 条/);assert.equal(f.node("auditCleanupConfirmation").classList.contains("hidden"),false);
 await f.view.confirmCleanup();assert.equal(apply,0);f.node("auditCleanupAcknowledge").checked=true;f.node("auditCleanupAcknowledge").listeners.change();assert.equal(f.node("auditCleanupConfirm").disabled,false);
 await f.view.confirmCleanup();await f.view.confirmCleanup();assert.equal(apply,1);const body=JSON.parse(f.calls.find(call=>call.url.endsWith("/cleanup")).options.body);assert.deepEqual(body,{token:"safe-token",confirm:true});assert.match(f.node("auditCleanupMessage").textContent,/已清理 2 条/);
});

test("cleanup date validation and range change invalidate the old preview",async()=>{
 const f=fixture(async url=>url.endsWith("/cleanup/preview")?{preview:{token:"t",records:1,logical_bytes:10,request_body_bytes:5},storage:{records:1,logical_bytes:10,request_body_bytes:5,max_total_bytes:1024}}:list([]));await f.view.enter();
 f.node("auditCleanupScope").value="custom";f.node("auditCleanupBefore").value="invalid";const before=f.calls.length;await f.view.previewCleanup();assert.equal(f.calls.length,before);assert.match(f.node("auditCleanupMessage").textContent,/RFC3339/);
 f.node("auditCleanupBefore").value="2026-01-01T00:00:00+08:00";await f.view.previewCleanup();const payload=JSON.parse(f.calls.at(-1).options.body);assert.equal(payload.before,"2026-01-01T00:00:00+08:00");
 f.node("auditCleanupScope").value="expired";f.node("auditCleanupScope").listeners.change();f.node("auditCleanupAcknowledge").checked=true;await f.view.confirmCleanup();assert.equal(f.calls.filter(call=>call.url.endsWith("/cleanup")).length,0);
});

test("lock cancels cleanup and clears confirmation tokens without replaying writes",async()=>{
 const delayed=deferred();const f=fixture(url=>url.endsWith("/cleanup/preview")?delayed.promise:Promise.resolve(list([])));await f.view.enter();f.node("auditCleanupScope").value="all";
 const pending=f.view.previewCleanup();const signal=f.calls.at(-1).options.signal;f.setAuth(false);f.view.lock();assert.equal(signal.aborted,true);
 delayed.resolve({preview:{token:"late",records:1,logical_bytes:10},storage:{records:1,logical_bytes:10,max_total_bytes:20}});await pending;
 assert.equal(f.node("auditCleanupConfirmation").classList.contains("hidden"),true);assert.equal(f.node("auditCleanupBefore").value,"");assert.match(f.node("auditStorageSummary").textContent,/授权/);
});

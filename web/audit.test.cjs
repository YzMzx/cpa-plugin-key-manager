const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const Audit = require("./audit.js");
const State = require("./state.js");
const status = extra => ({enabled:true,retention_days:7,max_records:10000,max_body_bytes:65536,max_total_bytes:10485760,...extra});
const record = (id, extra={}) => ({id,request_id:"req-"+id,trace_id:"trace-"+id,started_at:"2026-11-09T12:00:00Z",completed_at:"2026-11-09T12:00:01Z",key_label:"team",key_fingerprint:"fp",requested_model:"m",served_model:"m",outcome:"succeeded",status_code:200,duration_ms:1,body_state:"redacted",...extra});
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

test("four filters encode literal values and omit removed identifiers/time fields",()=>{
 const params=new URLSearchParams(Audit.queryString({key_fingerprint:"a".repeat(64),key_label:"备注&'",model:"模型<x>",outcome:"failed",ip:"::1",request_id:"gone",trace_id:"gone",from:"invalid",to:"invalid"},50,0));
 assert.equal(params.get("key_label"),"备注&'");assert.equal(params.get("model"),"模型<x>");assert.equal(params.has("ip"),false);
 for(const key of ["request_id","trace_id","from","to"])assert.equal(params.has(key),false);
 assert.equal(Audit.timestamp(0,"UTC"),"未知");
});

test("JSON body is decoded read-only while non-JSON stays omitted",()=>{
 const value=Audit.bodyView(record("a",{request_body:'{"messages":[{"content":"<img onerror=evil()>"}]}'}));
 assert.match(value.json,/<img onerror=evil/);assert.ok(value.json.includes(String.fromCharCode(10)));
 assert.equal(Audit.bodyView(record("a",{request_body:"not json"})).state,"未保存（格式异常）");
 assert.equal(Audit.bodyView(record("a",{body_state:"omitted_input_limit",body_truncated:true})).state,"未保存（超出限制）");
});

test("list loads metadata only and detail is fetched on explicit selection with text-only rendering",async()=>{
 const attack="<img src=x onerror=globalThis.pwned=true>";
 const f=fixture(async url=>url.includes("/detail?")?{record:record("a",{request_body:{messages:[{content:attack}]},path:attack,body_sha256:"hash"}),status:status()}:list([record("a",{key_label:attack})]));
 await f.view.enter();assert.equal(f.calls.filter(c=>c.url.includes("/detail?")).length,0);
 assert.match(f.node("auditListBody").textContent,/<img/);assert.equal(f.node("auditListBody").children[0].children.length,8);
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

test("audit UI uses fixed drawer, four filters and no removed privacy banner",()=>{
 const html=fs.readFileSync(path.join(__dirname,"index.html"),"utf8");const source=fs.readFileSync(path.join(__dirname,"audit.js"),"utf8");const css=fs.readFileSync(path.join(__dirname,"app.css"),"utf8");
 for(const phrase of ["请求审计","保留 7 天","不记录响应","防篡改证明"])assert.ok(html.includes(phrase));
 assert.ok(!html.includes("请求正文可能包含对话、个人信息和业务数据。"));
 for(const id of ["auditKey","auditKeyLabel","auditModel","auditOutcome"])assert.ok(html.includes('id="'+id+'"'));
 for(const id of ["auditRequestId","auditTraceId","auditKeyFingerprint","auditFrom","auditTo","auditIP"])assert.ok(!html.includes('id="'+id+'"'));
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
 assert.equal(value.json,raw);assert.equal(value.state,"已保存 JSON 明文");
 const omitted=Audit.bodyView(record("large",{body_state:"omitted_output_limit",request_body:raw,body_truncated:true}));
 assert.notEqual(omitted.json,raw);
});

test("detail drawer opens in viewport, changes adjacent record, Esc restores trigger focus",async()=>{
 const f=fixture(async url=>url.includes("/detail?")?{record:record(new URL("http://test"+url).searchParams.get("id"),{body_state:"stored",request_body:'{"value":"safe"}'}),status:status()}:list([record("a"),record("b")]));
 await f.view.enter();
 const trigger=f.node("auditListBody").children[0].children[7].children[0];trigger.focus();
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

test("partial redacted JSON remains visible with placeholders, retained bytes and hash",async()=>{
 const raw=JSON.stringify({messages:[{role:"user",content:"你好 <img onerror=evil()> [OMITTED:string_limit]"}]});
 const partial=record("partial",{body_state:"stored_partial",body_truncated:true,request_body:raw,body_sha256:"partial-digest"});
 const value=Audit.bodyView(partial);assert.equal(value.state,"已保存 JSON 明文");assert.match(value.info,/旧版部分留存/);assert.doesNotMatch(value.state,/正文已略过/);assert.equal(value.retainedBytes,Buffer.byteLength(raw));assert.match(value.json,/你好/);assert.match(value.json,/OMITTED:string_limit/);
 const f=fixture(async url=>url.includes("/detail?")?{record:partial,status:status()}:list([record("partial",{body_state:"stored_partial",body_truncated:true})]));await f.view.enter();assert.doesNotMatch(f.node("auditListBody").textContent,/超限略过|未保存正文/);await f.view.showDetail("partial");
 assert.match(f.node("auditRequestBody").textContent,/OMITTED:string_limit/);assert.match(f.node("auditRequestBody").textContent,/<img onerror=evil/);assert.equal(f.node("auditBodyState").textContent,"已保存 JSON 明文");assert.match(f.node("auditBodyInfo").textContent,/旧版部分留存/);assert.match(f.node("auditBodyInfo").textContent,/字节/);assert.equal(f.node("auditBodyHash").textContent,"partial-digest");
 const complete=Audit.bodyView(record("full",{body_state:"stored",request_body:raw}));assert.equal(complete.state,"已保存 JSON 明文");assert.match(complete.info,/旧版脱敏/);
});

test("legacy omitted element records remain unrecoverable and unknown states never reveal bodies",()=>{
 const legacy=Audit.bodyView(record("old",{body_state:"omitted_element_limit",body_truncated:true,request_body:'{"sensitive":"must-not-render"}'}));
 assert.equal(legacy.state,"未保存（超出限制）");assert.match(legacy.json,/无法恢复/);assert.doesNotMatch(legacy.json,/must-not-render/);assert.equal(legacy.retainedBytes,0);
 for(const body_state of ["unknown_future","omitted_string_limit","omitted_output_limit"]){const value=Audit.bodyView(record("x",{body_state,request_body:'{"secret":"must-not-render"}'}));assert.doesNotMatch(value.json,/must-not-render/);}
 const large=JSON.stringify({content:"部分正文 [OMITTED:limit] ".repeat(20000)});const shown=Audit.bodyView(record("large",{body_state:"stored_partial",body_truncated:true,request_body:large}));assert.equal(shown.json,large);assert.equal(shown.state,"已保存 JSON 明文");assert.match(shown.info,/旧版部分留存/);
});

test("IP metadata and legacy unknown-IP warnings are not rendered",async()=>{
 const legacy={client_ip:"203.0.113.88",peer_ip:"192.0.2.2",ip_source:"host_resolved",ip_note:"private-network-note"};
 const f=fixture(async url=>url.includes("/detail?")?{record:record("noip",{...legacy,body_state:"stored",request_body:"{}"}),status:status({warning:"宿主未提供客户端IP"})}:list([record("noip",legacy)],{status:status({warning:"宿主未提供客户端IP"})}));
 await f.view.enter();await f.view.showDetail("noip");
 for(const id of ["auditListBody","auditDetailMetadata","auditStatus"]){for(const value of ["203.0.113.88","192.0.2.2","host_resolved","private-network-note","宿主未提供客户端IP"]){assert.ok(!f.node(id).textContent.includes(value));}}
 const html=fs.readFileSync(path.join(__dirname,"index.html"),"utf8");assert.ok(!html.includes("来源 IP"));assert.ok(!html.includes("IP 来源"));assert.match(html,/colspan="8" class="cell-empty">尚未加载审计记录/);
});

test("raw plaintext JSON formats whitespace while preserving escapes credentials and literal markup",async()=>{
 const raw=' {\n  "api_key": "secretliteral", "escaped": "\\u4f60\\u597d", "content": "<img src=x onerror=evil()>"\n} ' ;
 const value=Audit.bodyView(record("raw",{body_state:"stored_raw",body_truncated:false,request_body:raw,body_sha256:"raw-digest"}));
 assert.equal(value.json,Audit.formatJSONText(raw));assert.equal(Audit.bodyView(record("raw",{body_state:"stored_raw",request_body:raw}),"original").json,raw);assert.equal(value.state,"已保存 JSON 明文");assert.equal(value.retainedBytes,Buffer.byteLength(raw));
 const f=fixture(async url=>url.includes("/detail?")?{record:record("raw",{body_state:"stored_raw",body_truncated:false,request_body:raw,body_sha256:"raw-digest"}),status:status()}:list([record("raw",{body_state:"stored_raw"})]));
 await f.view.enter();await f.view.showDetail("raw");assert.equal(f.node("auditRequestBody").textContent,Audit.formatJSONText(raw));f.node("auditBodyOriginal").listeners.click();assert.equal(f.node("auditRequestBody").textContent,raw);f.node("auditBodyFormatted").listeners.click();assert.equal(f.node("auditRequestBody").textContent,Audit.formatJSONText(raw));assert.match(f.node("auditDetailMessage").textContent,/明文可能含凭据/);assert.equal(f.node("auditBodyHash").textContent,"raw-digest");
 const html=fs.readFileSync(path.join(__dirname,"index.html"),"utf8");assert.ok(html.includes("请求 JSON 原文（只读）"));assert.ok(html.includes("已保存内容"));assert.ok(!html.includes("脱敏请求 JSON（只读）"));
 const rejected=Audit.bodyView(record("invalid-partial-raw",{body_state:"stored_raw",body_truncated:true,request_body:raw}));assert.notEqual(rejected.json,raw);
});

test("JSON formatting preserves tokens without parsing numeric values or limiting old element counts",()=>{
 const raw='{"many":['+Array.from({length:5000},(_,i)=>String(i)).join(",")+'],"secret":"literal"}';
 const value=Audit.bodyView(record("many",{body_state:"stored_raw",request_body:raw}));assert.equal(value.json,Audit.formatJSONText(raw));assert.ok(value.json.includes("\n    4999"));
 const large=JSON.stringify({content:"原文 secretliteral ".repeat(25000)});assert.equal(Audit.bodyView(record("large-raw",{body_state:"stored_raw",request_body:large})).json,Audit.formatJSONText(large));assert.equal(Audit.bodyView(record("large-raw",{body_state:"stored_raw",request_body:large}),"original").json,large);
 const legacy=Audit.bodyView(record("legacy",{body_state:"stored",request_body:"{}"}));assert.equal(legacy.state,"已保存 JSON 明文");assert.match(legacy.info,/旧版脱敏/);
});

test("whitespace formatter preserves field order duplicate keys arbitrary precision and escapes",()=>{
 const raw=' {"z":900719925474099312345678901234567890,"duplicate":1,"duplicate":2,"decimal":1.23000e+99,"negative":-0,"escaped":"\\u4f60\\u597d","punctuation":"a,{[\\\"x\\\"]}:","nested":[true,null,{}],"secret":"plaintext-value"} ';
 const pretty=Audit.formatJSONText(raw);
 assert.ok(pretty.includes('\n  "z": 900719925474099312345678901234567890'));
 assert.ok(pretty.includes('"duplicate": 1,\n  "duplicate": 2'));
 for(const lexeme of ['1.23000e+99','-0','\\u4f60\\u597d','plaintext-value'])assert.ok(pretty.includes(lexeme));
 assert.equal(Audit.formatJSONText(pretty),pretty);
 assert.doesNotThrow(()=>JSON.parse(pretty));
 assert.equal(Audit.formatJSONText(raw,raw.length),raw,"format expansion must not truncate content");
});

test("body format mode resets per record and lock clears both saved and formatted representations",async()=>{
 const raw='{"messages":[{"content":"plain secret"}]}';
 const f=fixture(async url=>url.includes("/detail?")?{record:record(new URL("http://t"+url).searchParams.get("id"),{body_state:"stored_raw",request_body:raw,body_sha256:"saved-content-hash"}),status:status()}:list([record("a"),record("b")]));
 await f.view.enter();await f.view.showDetail("a");assert.match(f.node("auditRequestBody").textContent,/\n/);
 f.node("auditBodyOriginal").listeners.click();assert.equal(f.node("auditRequestBody").textContent,raw);assert.equal(f.node("auditBodyOriginal").getAttribute("aria-pressed"),"true");
 await f.view.showDetail("b");assert.equal(f.node("auditBodyFormatted").getAttribute("aria-pressed"),"true");assert.match(f.node("auditRequestBody").textContent,/\n/);assert.equal(f.node("auditBodyHash").textContent,"saved-content-hash");
 f.setAuth(false);f.view.lock();f.node("auditBodyOriginal").listeners.click();assert.equal(f.node("auditRequestBody").textContent,"");assert.equal(f.node("auditBodyHash").textContent,"");
});

test("media-filtered plaintext JSON remains visible and identifies only the omitted payload",()=>{
 const raw='{"messages":[{"content":[{"type":"text","text":"保留文字"},{"type":"image_url","image_url":"[OMITTED:media]"}]}],"secret":"still-plaintext"}';
 const value=Audit.bodyView(record("media",{body_state:"stored_raw_media_filtered",body_truncated:false,request_body:raw,body_sha256:"saved-filtered-hash"}));
 assert.equal(value.state,"已保存 JSON 明文");assert.match(value.json,/保留文字/);assert.match(value.json,/still-plaintext/);assert.match(value.json,/OMITTED:media/);assert.equal(value.retainedBytes,Buffer.byteLength(raw));
});

test("system/developer filtered audit states remain readable with saved hash",()=>{
 const raw='{"messages":[{"role":"user","content":"保留文字"}]}';
 for(const state of ["stored_raw_system_filtered","stored_raw_system_media_filtered"]){const value=Audit.bodyView(record("roles",{body_state:state,request_body:raw,body_sha256:"saved-filtered-hash",body_truncated:false}));assert.equal(value.state,"已保存 JSON 明文");assert.match(value.json,/保留文字/);assert.ok(value.retainedBytes>0);assert.equal(Audit.bodyView(record("roles",{body_state:state,request_body:raw}),"original").json,raw);}
});

test("saved body states all use one concise label in list and detail without changing acceptance",async()=>{
 const states=["stored_raw","stored_raw_media_filtered","stored_raw_system_filtered","stored_raw_system_media_filtered","stored","redacted","captured","stored_partial"];
 const items=states.map((state,index)=>record("label-"+index,{body_state:state,body_truncated:state==="stored_partial"}));
 const f=fixture(async url=>url.includes("/detail?")?{record:{...items.find(item=>item.id===new URL("http://t"+url).searchParams.get("id")),request_body:'{"safe":"visible"}',body_sha256:"saved-hash"},status:status()}:list(items));
 await f.view.enter();
 for(let i=0;i<states.length;i++){
  assert.equal(f.node("auditListBody").children[i].children[6].textContent,"已保存 JSON 明文");
  await f.view.showDetail(items[i].id);assert.equal(f.node("auditBodyState").textContent,"已保存 JSON 明文");assert.match(f.node("auditRequestBody").textContent,/visible/);assert.equal(f.node("auditBodyHash").textContent,"saved-hash");
 }
 f.view.closeDetail();assert.equal(f.node("auditBodyInfo").textContent,"");
});

test("omitted body codes merge into actionable categories and never reveal accidental bodies",()=>{
 const groups={
  "无正文":["empty"],
  "未保存（超出限制）":["omitted_input_limit","omitted_output_limit","omitted_size","too_large","omitted_depth_limit","omitted_element_limit","omitted_string_limit","omitted_number_limit","omitted_secret_limit"],
  "未保存（格式不支持）":["omitted_encoding","omitted_non_json","omitted_non_container","omitted_unknown_schema","non_json"],
  "未保存（格式异常）":["omitted_invalid_json","omitted_ambiguous_json","invalid_json"],
  "未保存（采集关闭）":["omitted_disabled","disabled"],
  "未保存（采集繁忙）":["omitted_busy"],
  "未保存正文":["omitted","not_captured","omitted_secret_collision","unavailable","unknown_future",""]
 };
 for(const [expected,codes]of Object.entries(groups))for(const body_state of codes){
  const value=record("not-saved",{body_state,body_truncated:true,request_body:'{"secret":"must-not-render"}'});
  assert.equal(Audit.bodyStatus(value),expected);const view=Audit.bodyView(value);assert.equal(view.state,expected);assert.doesNotMatch(view.json,/must-not-render/);assert.equal(view.retainedBytes,0);
 }
 const contradictory=record("contradictory",{body_state:"stored_raw",body_truncated:true,request_body:'{"secret":"must-not-render"}'});
 assert.equal(Audit.bodyStatus(contradictory),"未保存正文");assert.doesNotMatch(Audit.bodyView(contradictory).json,/must-not-render/);
});

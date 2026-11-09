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
}
function fixture(handler){
 const nodes=new Map();const doc={getElementById:id=>{if(!nodes.has(id))nodes.set(id,new Element());return nodes.get(id);},createElement:tag=>new Element(tag)};
 let auth=true;const calls=[];
 const request=async(url,options)=>{calls.push({url,options});if(url.endsWith("/status"))return {status:status({warning:"宿主未提供客户端IP"})};return handler(url,options);};
 const view=Audit.create({document:doc,request,gate:State.createRequestGate(),isAuthenticated:()=>auth,getTimezone:()=>"UTC"});
 return {view,calls,node:id=>doc.getElementById(id),setAuth:value=>auth=value};
}

test("audit validates list without body and rejects malformed pagination/status",()=>{
 assert.equal(Audit.validateList(list([record("a")])).total,1);
 assert.throws(()=>Audit.validateList(list([record("a",{request_body:"sensitive"})])),/列表不得包含请求正文/);
 for(const extra of [{offset:-1},{limit:0},{total:NaN},{items:[{}]},{status:{enabled:true}}])assert.throws(()=>Audit.validateList(list([],extra)));
 assert.throws(()=>Audit.validateDetail({record:record("other"),status:status()},"a"),/不一致/);
 assert.equal(Audit.statusPayload({status:status()}).retention_days,7);
});

test("query encodes identifiers safely and requires explicit RFC3339 time zones",()=>{
 const params=new URLSearchParams(Audit.queryString({request_id:"a&b'",trace_id:"t",key_fingerprint:"fp",ip:"::1",model:"<x>",outcome:"running",from:"2026-11-09T00:00:00+08:00",to:"2026-11-10T00:00:00+08:00"},50,100));
 assert.equal(params.get("request_id"),"a&b'");assert.equal(params.get("offset"),"100");assert.equal(params.get("ip"),"::1");assert.equal(params.get("outcome"),"running");
 assert.throws(()=>Audit.queryString({from:"2026-11-09"},50,0),/RFC3339/);
 assert.throws(()=>Audit.queryString({from:"2026-11-10T00:00:00Z",to:"2026-11-09T00:00:00Z"},50,0),/晚于/);
 assert.equal(Audit.timestamp(0,"UTC"),"未知");assert.equal(Audit.timestamp("","UTC"),"未知");assert.notEqual(Audit.timestamp("2026-11-09T00:00:00Z","UTC"),"未知");
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
 const late=deferred();const f=fixture(url=>url.includes("/detail?")?late.promise:Promise.resolve(list([record("a")])));await f.view.enter();f.node("auditRequestId").value="sensitive request";const pending=f.view.showDetail("a");const signal=f.calls.at(-1).options.signal;
 f.setAuth(false);f.view.lock();assert.ok(signal.aborted);late.resolve({record:record("a",{request_body:{secret:"late"}}),status:status()});await pending;
 for(const id of ["auditRequestBody","auditDetailMetadata","auditBodyHash","auditRequestId"])assert.equal(id==="auditRequestId"?f.node(id).value:f.node(id).textContent,"");
 assert.doesNotMatch(f.node("auditListBody").textContent,/req-a/);const count=f.calls.length;await f.view.refresh();await f.view.showDetail("a");assert.equal(f.calls.length,count);
});

test("disabled audit and failures are explicit rather than fake records",async()=>{
 const f=fixture(()=>Promise.resolve(list([],{status:status({enabled:false})})));await f.view.enter();assert.match(f.node("auditStatus").textContent,/未启用/);assert.match(f.node("auditListBody").textContent,/未启用/);
 const g=fixture(()=>Promise.reject(new Error("offline")));await g.view.enter();assert.match(g.node("auditListMessage").textContent,/offline/);assert.equal(g.node("auditNextPage").disabled,true);
});

test("audit UI documents retention and sensitive data limitations without management actions",()=>{
 const html=fs.readFileSync(path.join(__dirname,"index.html"),"utf8");const source=fs.readFileSync(path.join(__dirname,"audit.js"),"utf8");
 for(const phrase of ["请求审计","保留 7 天","不记录响应","不保证消除所有个人信息","非 JSON","防篡改证明"])assert.ok(html.includes(phrase),phrase);
 for(const forbidden of ["innerHTML", "eval(", "new Function", "response_body"])assert.ok(!source.includes(forbidden));
 for(const method of ["POST","PUT","DELETE","PATCH"])assert.ok(!source.includes('method: "'+method+'"'));
 assert.ok(html.includes('id="tab-audit"'));assert.doesNotMatch(source,/X-Forwarded-For|Forwarded/);
});

test("invalid calendar dates are not normalized into different audit filters",()=>{
 for(const value of ["2026-02-30T00:00:00Z","2026-00-01T00:00:00Z","2026-11-09T25:00:00Z","2026-11-09T00:00:00+24:00"]) {assert.throws(()=>Audit.queryString({from:value},50,0),/RFC3339/);assert.equal(Audit.timestamp(value,"UTC"),"未知");}
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
 f.node("auditFrom").value="invalid";const before=f.calls.length;await f.view.applyFilters();assert.equal(f.calls.length,before);assert.match(f.node("auditListMessage").textContent,/RFC3339/);
});

test("detail response must match requested audit id",async()=>{
 const f=fixture(url=>Promise.resolve(url.includes("/detail?")?{record:record("wrong",{request_body:{secret:"wrong"}}),status:status()}:list([record("a")])));await f.view.enter();await f.view.showDetail("a");assert.match(f.node("auditDetailMessage").textContent,/不一致/);assert.equal(f.node("auditRequestBody").textContent,"");
});

test("audit status keeps capture failures visible after later successful reads",async()=>{
 const f=fixture(async()=>list([],{status:status({capture_failures:2,last_capture_failure_at:"2026-11-09T12:00:00Z"})}));
 await f.view.enter();assert.match(f.node("auditStatus").textContent,/采集失败 2 次/);
});

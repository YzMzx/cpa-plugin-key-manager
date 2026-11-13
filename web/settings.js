/* Unified configuration editor; independent drafts and no credential echo. */
(function(root,factory){const api=factory();if(typeof module==="object"&&module.exports)module.exports=api;else root.KeyGuardSettings=api;})(typeof globalThis!=="undefined"?globalThis:this,function(){
 "use strict";
 const BASE="/v0/management/key-guard/settings",MIB=1048576;
 const object=v=>v!==null&&typeof v==="object"&&!Array.isArray(v);
 const clone=v=>JSON.parse(JSON.stringify(v));
 const FIELDS=[
  ["audit.enabled","settingAuditEnabled","bool"],["audit.retention_days","settingAuditRetention","int",1,90],["audit.max_records","settingAuditRecords","int",1,100000],
  ["audit.max_body_bytes","settingAuditBodyMiB","mib",256,10*MIB],["audit.max_total_bytes","settingAuditTotalMiB","mib",MIB,10240*MIB],
  ["storage.flush_interval_seconds","settingFlushSeconds","int",1,3600],["storage.ledger_retention_days","settingLedgerRetention","int",1,3650],
  ["storage.timezone","settingTimezone","timezone"],["storage.pricing_cache_file","settingCacheFile","path"],
  ["pricing.sync_url","settingPricingURL","url"],["pricing.sync_interval_hours","settingPricingHours","int",1,720],["pricing.http_timeout_seconds","settingPricingTimeout","int",1,300],
  ["pricing.auto_inject_include_usage","settingIncludeUsage","bool"]
 ];
 const get=(v,path)=>path.split(".").reduce((value,key)=>value&&value[key],v);
 function put(v,path,value){const [group,key]=path.split(".");v[group][key]=value;}
 function validateSettings(value){
  if(!object(value)||!["audit","storage","pricing"].every(g=>object(value[g])))throw new Error("配置响应格式无效");
  const result={audit:{},storage:{},pricing:{}};
  for(const [path,,kind,min,max]of FIELDS){const current=get(value,path);
   if(kind==="bool"){if(typeof current!=="boolean")throw new Error("配置布尔值无效："+path);}
   else if(kind==="int"||kind==="mib"){if(!Number.isSafeInteger(current)||current<min||current>max)throw new Error("配置整数或范围无效："+path);}
   else if(typeof current!=="string"||!current.trim()||current.length>4096||/[\u0000-\u001f\u007f]/.test(current))throw new Error("配置文本无效："+path);
   if(kind==="timezone"){try{new Intl.DateTimeFormat("en-US",{timeZone:current}).format(0);}catch(_){throw new Error("请输入有效的 IANA 时区");}}
   if(kind==="url"){if(current.length>2048)throw new Error("同步地址不得超过 2048 字符");let u;try{u=new URL(current);}catch(_){throw new Error("请输入有效的价格同步 URL");}if(!["https:","http:"].includes(u.protocol)||u.username||u.password||u.search||u.hash||current.includes("?"))throw new Error("同步地址仅支持不含用户名、密码、查询参数和片段的 HTTP(S) URL");}
   put(result,path,current);
  }
  return result;
 }
 function validatePayload(value){if(!object(value)||!Number.isSafeInteger(value.rules_revision)||value.rules_revision<0)throw new Error("配置版本响应无效");return {settings:validateSettings(value.settings),rules_revision:value.rules_revision,bootstrap:bootstrapShape(value.bootstrap),apply_status:object(value.apply_status)?{ok:value.apply_status.ok===true,error:typeof value.apply_status.error==="string"?value.apply_status.error:""}:null,warning:typeof value.warning==="string"?value.warning:""};}
 function needsPrune(before,after){return ["audit.retention_days","audit.max_records","audit.max_total_bytes","storage.ledger_retention_days"].some(path=>get(after,path)<get(before,path));}
 function bootstrapShape(value){
  if(!object(value))return null;
  const current=v=>object(v)&&typeof v.enabled==="boolean"&&Number.isSafeInteger(v.priority)&&typeof v.usage_db_file==="string"?{enabled:v.enabled,priority:v.priority,usage_db_file:v.usage_db_file}:null;
  const effective=current(value.effective),configured=current(value.configured);
  if(!effective||!configured)return null;
  return {effective,configured,file_revision:typeof value.file_revision==="string"?value.file_revision:"",db_path_locked_by_env:value.db_path_locked_by_env===true,available:value.available===true};
 }
 function create({document:doc,request,gate,isAuthenticated,onSaved=async()=>{},navigate=()=>{}}){
  let active=false,baseline=null,draft=null,revision=null,dirty=false,saving=false,bootstrap=null,bootstrapDirty=false,bootstrapSaving=false;
  const el=id=>doc.getElementById(id),set=(id,value)=>{const n=el(id);if(n)n.textContent=value;};
  const message=(text,error=false)=>{set("settingsMessage",text);el("settingsMessage").style.color=error?"var(--error-color)":"var(--text-secondary)";};
  const show=(id,yes)=>{if(yes)el(id).classList.remove("hidden");else el(id).classList.add("hidden");};
  function paintForm(settings){for(const[path,id,kind]of FIELDS){const value=get(settings,path);if(kind==="bool")el(id).checked=value;else el(id).value=String(kind==="mib"?value/MIB:value);}}
  function readForm(){
   const next={audit:{},storage:{},pricing:{}};
   for(const[path,id,kind]of FIELDS){let value;if(kind==="bool")value=!!el(id).checked;else if(kind==="int"||kind==="mib"){const raw=el(id).value.trim();if(!raw)throw new Error("请填写所有数值设置");value=Number(raw);if(!Number.isFinite(value))throw new Error("数值必须是有限数字");if(kind==="mib")value*=MIB;}else value=el(id).value.trim();put(next,path,value);}
   return validateSettings(next);
  }
  function updateControls(){
   el("settingsSave").disabled=saving||!baseline||!dirty;el("settingsDiscard").disabled=saving||!baseline||!dirty;
   set("settingsDirtyState",!baseline?"尚未读取":saving?"正在保存…":dirty?"有未保存修改":"所有修改已保存");
   let prune=false;try{if(baseline)prune=needsPrune(baseline,readForm());}catch(_){}
   show("settingsPruneWarning",prune);if(!prune)el("settingsAcknowledgePrune").checked=false;
   for(const[,id]of FIELDS)el(id).disabled=saving||!baseline;
  }
  function changed(){if(!baseline)return;dirty=true;draft=null;try{draft=readForm();dirty=JSON.stringify(draft)!==JSON.stringify(baseline);}catch(_){}el("settingsAcknowledgePrune").checked=false;updateControls();}
  function renderBootstrap(value,force=false){
   const parsed=bootstrapShape(value);if(!parsed){if(!bootstrap){set("settingsBootstrapMessage","宿主未提供启动配置编辑能力；只可在宿主配置中修改并重启。");el("settingsBootstrapSave").disabled=true;}return;}
   if(bootstrapDirty&&!force){set("settingsBootstrapMessage","启动配置草稿已保留；放弃修改后可重新读取。");return;}
   bootstrap=parsed;bootstrapDirty=false;const {effective,configured}=parsed,node=el("settingsBootstrap");node.replaceChildren();
   for(const[label,key,format]of [["当前启用状态","enabled",v=>v?"启用":"禁用"],["当前优先级","priority",String],["当前数据库路径","usage_db_file",String]]){const dt=doc.createElement("dt"),dd=doc.createElement("dd");dt.textContent=label;dd.textContent=effective[key]===undefined?"未提供":format(effective[key]);node.appendChild(dt);node.appendChild(dd);}
   el("settingBootstrapEnabled").checked=!!configured.enabled;el("settingBootstrapPriority").value=String(configured.priority??0);el("settingBootstrapDB").value=String(configured.usage_db_file||"");
   el("settingsAcknowledgeRestart").checked=false;el("settingsAcknowledgeDBChange").checked=false;
   const enabled=parsed.available;for(const id of ["settingBootstrapEnabled","settingBootstrapPriority","settingsAcknowledgeRestart"])el(id).disabled=!enabled;
   el("settingBootstrapDB").disabled=!enabled||parsed.db_path_locked_by_env;set("settingsDBLockNote",parsed.db_path_locked_by_env?"数据库路径由环境变量锁定，不能在这里修改。":"变更路径不会自动复制旧数据。");
   set("settingsBootstrapMessage",enabled?"启动设置单独保存；需重载或重启，宿主监听器可能提前应用。":"宿主配置文件不可编辑，请检查宿主配置入口。");bootstrapControls();
  }
  function bootstrapControls(){const editable=!!bootstrap&&bootstrap.available&&!bootstrapSaving;for(const id of ["settingBootstrapEnabled","settingBootstrapPriority","settingsAcknowledgeRestart","settingsAcknowledgeDBChange"])el(id).disabled=!editable;el("settingBootstrapDB").disabled=!editable||!!(bootstrap&&bootstrap.db_path_locked_by_env);const changedPath=!!bootstrap&&el("settingBootstrapDB").value.trim()!==String(bootstrap.configured.usage_db_file||"");show("settingsPathChangeWarning",changedPath);if(!changedPath)el("settingsAcknowledgeDBChange").checked=false;el("settingsBootstrapSave").disabled=!bootstrap||!bootstrap.available||!bootstrapDirty||bootstrapSaving;}
  function bootstrapChanged(){bootstrapDirty=true;el("settingsAcknowledgeRestart").checked=false;el("settingsAcknowledgeDBChange").checked=false;bootstrapControls();}
  async function load(force=false){
   if(!active||!isAuthenticated())return;if((dirty||bootstrapDirty)&&!force){message("保留未保存草稿；如需服务器最新值，请先放弃修改再重新加载。");return;}
   const ticket=gate.begin("settings-read");el("settingsReload").disabled=true;message("正在读取统一配置…");
   try{const payload=validatePayload(await request(BASE,{method:"GET",signal:ticket.signal}));if(!ticket.current()||!active||!isAuthenticated())return;
    if((dirty||bootstrapDirty)&&!force){message("读取期间产生的未保存草稿已保留。");return;}baseline=clone(payload.settings);draft=clone(payload.settings);revision=payload.rules_revision;dirty=false;paintForm(draft);renderBootstrap(payload.bootstrap,force);el("settingsAcknowledgePrune").checked=false;message("配置已读取。常规配置保存后热应用，启动配置需重载或重启。");updateControls();
   }catch(error){if(ticket.current()&&active&&isAuthenticated()&&error.name!=="AbortError")message("配置读取失败："+error.message,true);}finally{if(ticket.current())el("settingsReload").disabled=false;ticket.finish();}
  }
  async function save(){
   if(!active||!isAuthenticated()||saving||!baseline)return;let next;try{next=readForm();}catch(error){message(error.message,true);return;}
   if(needsPrune(baseline,next)&&!el("settingsAcknowledgePrune").checked){message("降低保留或容量设置可能清理历史数据，请先勾选确认。",true);return;}
   saving=true;updateControls();const ticket=gate.begin("settings-save");message("正在保存热配置…");
   try{const payload=await request(BASE,{method:"PUT",headers:{"X-Key-Guard-Revision":String(revision)},body:JSON.stringify({settings:next,expected_revision:revision,ack_prune:!!el("settingsAcknowledgePrune").checked}),signal:ticket.signal});
    if(!ticket.current()||!active||!isAuthenticated())return;if(payload.ok!==true)throw new Error("服务器未确认配置保存成功");const checked=validatePayload(payload);baseline=clone(checked.settings);draft=clone(checked.settings);revision=checked.rules_revision;dirty=false;paintForm(draft);el("settingsAcknowledgePrune").checked=false;renderBootstrap(checked.bootstrap);message("热配置已保存。"+(checked.apply_status&&checked.apply_status.ok===false?" 应用尚未完成，请刷新检查状态。":""));
    try{await onSaved(checked);if(ticket.current()&&active&&isAuthenticated())message(checked.apply_status&&checked.apply_status.ok===false?"配置已保存，但热应用未完成，请刷新检查。":"热配置已保存，页面数据已同步。"+(checked.warning?" "+String(checked.warning):""),!!(checked.apply_status&&checked.apply_status.ok===false));}catch(_){if(ticket.current()&&active&&isAuthenticated())message("热配置已保存，但页面刷新失败；请稍后刷新，不要重复保存。",true);}
   }catch(error){if(ticket.current()&&active&&isAuthenticated()&&error.name!=="AbortError")message(error.status===409?"配置已被其它会话更新，草稿已保留。请先重新加载配置后再提交。":"配置未确认保存："+error.message,true);}finally{saving=false;if(active&&isAuthenticated())updateControls();ticket.finish();}
  }
  async function saveBootstrap(){
   if(!active||!isAuthenticated()||bootstrapSaving||!bootstrap||!bootstrap.available)return;
   const priority=Number(el("settingBootstrapPriority").value.trim()),path=el("settingBootstrapDB").value.trim();
   if(!el("settingBootstrapPriority").value.trim()||!Number.isSafeInteger(priority)||priority < -10000||priority>10000||!path||path.length>4096||/[\u0000-\u001f\u007f]/.test(path)){set("settingsBootstrapMessage","请填写有效的整数优先级和数据库路径。");return;}
   if(!el("settingsAcknowledgeRestart").checked){set("settingsBootstrapMessage","请先确认保存后需要重启 CPA。");return;}
   const changedPath=path!==String(bootstrap.configured.usage_db_file||"");if(changedPath&&!el("settingsAcknowledgeDBChange").checked){set("settingsBootstrapMessage","请先确认数据库路径变化不会自动迁移数据。");return;}
   if(bootstrap.db_path_locked_by_env&&changedPath){set("settingsBootstrapMessage","数据库路径由环境变量锁定，不能修改。");return;}
   const values={enabled:!!el("settingBootstrapEnabled").checked,priority,usage_db_file:path};
   bootstrapSaving=true;bootstrapControls();const ticket=gate.begin("settings-bootstrap-save");set("settingsBootstrapMessage","正在保存启动配置，宿主可能随后自动重载…");
   try{const result=await request(BASE+"/bootstrap",{method:"PUT",body:JSON.stringify({expected_file_revision:bootstrap.file_revision,bootstrap:values,ack_restart:true,ack_storage_path_change:changedPath}),signal:ticket.signal});
    if(!ticket.current()||!active||!isAuthenticated())return;if(result.ok!==true||result.requires_restart!==true)throw new Error("服务器未确认启动配置保存");renderBootstrap(result.bootstrap,true);set("settingsBootstrapMessage","启动配置已保存；宿主可能热重载，禁用可能使页面失效。数据库路径需重启且数据未自动迁移。");
   }catch(error){if(ticket.current()&&active&&isAuthenticated()&&error.name!=="AbortError")set("settingsBootstrapMessage",error.status===409?"宿主配置文件已变化，请重新加载后重试。":"启动配置未确认保存，请重新加载检查结果。");}finally{bootstrapSaving=false;if(active&&isAuthenticated())bootstrapControls();ticket.finish();}
  }
  function discard(){if(saving||bootstrapSaving)return;dirty=false;bootstrapDirty=false;if(baseline){draft=clone(baseline);paintForm(draft);}el("settingsAcknowledgePrune").checked=false;updateControls();return load(true);}
  function leave(){active=false;gate.cancel("settings-read");gate.cancel("settings-save");gate.cancel("settings-bootstrap-save");saving=false;bootstrapSaving=false;}
  function lock(){leave();baseline=null;draft=null;revision=null;dirty=false;bootstrap=null;bootstrapDirty=false;for(const[,id,kind]of FIELDS){if(kind==="bool")el(id).checked=false;else el(id).value="";}for(const id of ["settingBootstrapPriority","settingBootstrapDB"])el(id).value="";for(const id of ["settingBootstrapEnabled","settingsAcknowledgeRestart","settingsAcknowledgeDBChange","settingsAcknowledgePrune"])el(id).checked=false;el("settingsBootstrap").replaceChildren();set("settingsBootstrapMessage","");message("需要管理员授权后读取配置。");updateControls();el("settingsBootstrapSave").disabled=true;}
  function enter(){active=true;updateControls();return load();}
  for(const[,id]of FIELDS){el(id).addEventListener("input",changed);el(id).addEventListener("change",changed);}
  el("settingsForm").addEventListener("submit",event=>{event.preventDefault();save();});el("settingsReload").addEventListener("click",()=>load());el("settingsDiscard").addEventListener("click",discard);
  el("settingsBootstrapForm").addEventListener("submit",event=>{event.preventDefault();saveBootstrap();});
  for(const id of ["settingBootstrapEnabled","settingBootstrapPriority","settingBootstrapDB"]){el(id).addEventListener("input",bootstrapChanged);el(id).addEventListener("change",bootstrapChanged);}
  for(const[id,tab]of [["settingsJumpKeys","tab-keys"],["settingsJumpPolicy","tab-routing"],["settingsJumpPricing","tab-pricing"]])el(id).addEventListener("click",()=>navigate(tab));
  updateControls();bootstrapControls();return{enter,leave,lock,refresh:()=>load(),save,saveBootstrap,discard,isDirty:()=>dirty||bootstrapDirty};
 }
 return{create,validateSettings,validatePayload,needsPrune,MIB};
});

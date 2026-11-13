/* Full-snapshot cleanup jobs. Tokens and task state stay in memory only. */
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.KeyGuardCleanupJobs = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";
  const BASE = "/v0/management/key-guard/audit/cleanup/jobs", MIB = 1048576;
  const object = v => v !== null && typeof v === "object" && !Array.isArray(v);
  const integer = v => Number.isSafeInteger(v) && v >= 0;
  const timestamp = v => typeof v === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[.]\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(v) && Number.isFinite(Date.parse(v));
  const activeJob = job => !!job && (job.state === "queued" || job.state === "running");
  const expiredJob = job => !!job && job.state === "failed" && job.error_code === "snapshot_expired";
  const resumable = job => !!job && job.state === "failed" && !expiredJob(job);
  const stateName = job => expiredJob(job) ? "快照已过期，不可继续" : names[job.state];
  const names = {queued:"排队中",running:"清理中",completed:"已完成",canceled:"已取消",failed:"失败，可继续同一快照"};
  const batchValid = v => Number.isSafeInteger(v.batch_max_records) && v.batch_max_records >= 1 && v.batch_max_records <= 5000 && Number.isSafeInteger(v.batch_max_bytes) && v.batch_max_bytes >= 16*MIB && v.batch_max_bytes <= 128*MIB;
  const bytes = v => (v / MIB).toLocaleString("zh-CN", {maximumFractionDigits:2}) + " MiB";
  function validatePreview(payload, selection) {
    const v = object(payload) && payload.preview;
    if (payload.ok !== true || !object(v) || typeof v.token !== "string" || !v.token || !timestamp(v.expires_at) || !["records","logical_bytes","request_body_bytes"].every(k => integer(v[k])) || !batchValid(v) || !["all","expired","before"].includes(v.scope) || v.scope !== selection.scope || (v.scope === "all" && !!v.before) || (v.scope === "expired" && !timestamp(v.before)) || (v.scope === "before" && (!timestamp(v.before) || !timestamp(selection.before) || Date.parse(v.before) !== Date.parse(selection.before)))) throw new Error("全量清理预览响应无效或范围不一致");
    return {token:v.token,expires_at:v.expires_at,records:v.records,logical_bytes:v.logical_bytes,request_body_bytes:v.request_body_bytes,batch_max_records:v.batch_max_records,batch_max_bytes:v.batch_max_bytes,scope:v.scope,...(v.before ? {before:v.before} : {})};
  }
  function validateJob(v) {
    const counters = ["total_records","processed_records","deleted_records","skipped_records","remaining_records","deleted_logical_bytes","deleted_body_bytes","batches"];
    if (!object(v) || typeof v.id !== "string" || !v.id || !Object.prototype.hasOwnProperty.call(names,v.state) || !counters.every(k => integer(v[k])) || !batchValid(v) || !timestamp(v.created_at) || !timestamp(v.updated_at) || typeof v.error_code !== "string" || v.processed_records > v.total_records || v.remaining_records !== v.total_records-v.processed_records || v.deleted_records > v.processed_records || v.skipped_records !== v.processed_records-v.deleted_records) throw new Error("清理任务响应格式无效");
    // Pick explicit safe fields; do not retain unexpected credentials/body/token extras.
    const result = {id:v.id,state:v.state,created_at:v.created_at,updated_at:v.updated_at,error_code:v.error_code,batch_max_records:v.batch_max_records,batch_max_bytes:v.batch_max_bytes};
    for (const key of counters) result[key] = v[key];
    return result;
  }
  function validateList(payload) {
    if (!object(payload) || !Array.isArray(payload.jobs)) throw new Error("清理任务列表响应无效");
    const jobs = payload.jobs.map(validateJob);
    if (new Set(jobs.map(v => v.id)).size !== jobs.length) throw new Error("清理任务列表存在重复 ID");
    return jobs;
  }
  function create({document:doc, request, gate, isAuthenticated, selection, onChanged = async () => {}, getTimezone = () => "Asia/Shanghai", now = () => Date.now(), schedule = (fn, ms) => setTimeout(fn, ms), unschedule = id => clearTimeout(id)}) {
    let active = false, epoch = 0, timer = null, reading = null, busy = false, unsupported = false;
    let preview = null, previewSelection = "", uncertain = false, jobs = [], selectedId = "";
    const el = id => doc.getElementById(id), set = (id,value) => { el(id).textContent = value; };
    const visible = (id, yes) => { if (yes) el(id).classList.remove("hidden"); else el(id).classList.add("hidden"); };
    const current = generation => generation === epoch && active && isAuthenticated();
    const selected = () => jobs.find(job => job.id === selectedId);
    const selectionIdentity = () => JSON.stringify({choice:el("auditCleanupScope").value || "expired",before:el("auditCleanupScope").value === "custom" ? el("auditCleanupBefore").value.trim() : ""});
    function stopRead() { gate.cancel("audit-jobs-read"); reading = null; stopTimer(); }
    function stopTimer() { if (timer !== null) unschedule(timer); timer = null; }
    function controls() {
      el("auditCleanupPreview").disabled = !active || busy || unsupported || uncertain;
      el("auditCleanupConfirm").disabled = !active || busy || unsupported || !preview || !el("auditCleanupAcknowledge").checked;
      el("auditCleanupConfirm").textContent = uncertain ? "使用同一快照重试启动" : "确认全部快照并后台清理";
      for (const id of ["auditCleanupScope","auditCleanupBefore","auditCleanupAcknowledge"]) el(id).disabled = busy || uncertain;
      el("auditCleanupCancel").disabled = busy;
      el("auditCleanupJobsRefresh").disabled = !active || busy || !!reading || unsupported;
      el("auditCleanupJobSelect").disabled = !active || busy || !jobs.length;
      const job = selected();
      el("auditCleanupJobCancel").disabled = !active || busy || !activeJob(job);
      el("auditCleanupCancelAcknowledge").disabled = !active || busy || !activeJob(job);
      el("auditCleanupJobResume").disabled = !active || busy || !resumable(job);
    }
    const count = value => value.toLocaleString("zh-CN");
    function displayTime(value) {
      try { return new Intl.DateTimeFormat("zh-CN", { timeZone: getTimezone(), month:"2-digit",day:"2-digit",hour:"2-digit",minute:"2-digit",hour12:false }).format(new Date(value)); }
      catch (_) { return value; }
    }
    function render() {
      const select = el("auditCleanupJobSelect"); select.replaceChildren();
      for (const job of jobs) { const option = doc.createElement("option"); option.value = job.id; option.textContent = stateName(job) + " · " + displayTime(job.created_at) + " · " + (job.id.length > 20 ? job.id.slice(0,8) + "…" + job.id.slice(-4) : job.id); option.title = job.id; select.appendChild(option); }
      select.value = selectedId;
      const job = selected(), progress = el("auditCleanupProgress");
      visible("auditCleanupJobDetails", !!job);
      if (job) {
        progress.max = Math.max(1,job.total_records); progress.value = job.total_records === 0 && job.state === "completed" ? 1 : job.processed_records;
        progress.setAttribute("value",String(progress.value)); progress.setAttribute("max",String(Math.max(1,job.total_records)));
        progress.setAttribute("aria-valuetext", "已处理 " + job.processed_records + " / " + job.total_records + " 条，" + stateName(job));
        set("auditCleanupJobState", stateName(job) + " · 已处理 " + job.processed_records + " / " + job.total_records + " 条");
        const percent = job.total_records ? 100 * job.processed_records / job.total_records : job.state === "completed" ? 100 : 0;
        set("auditCleanupPercent", percent.toFixed(1) + "%");
        set("auditCleanupJobBadge", stateName(job));
        el("auditCleanupJobBadge").setAttribute("data-state", expiredJob(job) ? "expired" : job.state);
        set("auditCleanupMetricProcessed", count(job.processed_records) + " / " + count(job.total_records));
        set("auditCleanupMetricDeleted", count(job.deleted_records));
        set("auditCleanupMetricSkipped", count(job.skipped_records));
        set("auditCleanupMetricRemaining", count(job.remaining_records));
        set("auditCleanupMetricBytes", bytes(job.deleted_logical_bytes));
        set("auditCleanupMetricBatches", count(job.batches));
        set("auditCleanupJobStats", "已删除 " + job.deleted_records + " 条，跳过 " + job.skipped_records + " 条（记录已不存在）；正文合计 " + bytes(job.deleted_body_bytes) + "。逻辑删除不保证文件立即缩小。");
        set("auditCleanupJobMeta", "任务 ID：" + job.id + "\n创建：" + displayTime(job.created_at) + " · 更新：" + displayTime(job.updated_at) + "\n每批最多 " + count(job.batch_max_records) + " 条 / " + bytes(job.batch_max_bytes));
        set("auditCleanupJobError", expiredJob(job) ? "快照已过期，不可恢复或继续；已删除记录不可恢复。如仍需清理，请手动重新预览当前范围并重新勾选确认，不会自动新建任务。" : job.state === "failed" ? "安全错误码：" + (job.error_code || "未提供") + "。继续仅恢复同一快照，不重新预览或纳入新记录。" : "");
      } else {
        progress.removeAttribute("value"); progress.removeAttribute("max"); progress.removeAttribute("aria-valuetext");
        for (const id of ["auditCleanupJobState","auditCleanupJobStats","auditCleanupJobError","auditCleanupJobBadge","auditCleanupPercent","auditCleanupMetricProcessed","auditCleanupMetricDeleted","auditCleanupMetricSkipped","auditCleanupMetricRemaining","auditCleanupMetricBytes","auditCleanupMetricBatches","auditCleanupJobMeta"]) set(id,"");
        el("auditCleanupJobBadge").removeAttribute("data-state");
      }
      controls();
    }
    function schedulePoll() {
      stopTimer();
      if (!active || !isAuthenticated() || unsupported || reading || busy || !jobs.some(activeJob)) return;
      const generation = epoch;
      timer = schedule(() => { timer = null; if (current(generation)) refresh(); },1000);
    }
    function replaceJob(job) {
      const old = selected(); const at = jobs.findIndex(v => v.id === job.id);
      if (at < 0) jobs.unshift(job); else jobs[at] = job;
      selectedId = job.id;
      if (!old || old.id !== job.id || old.state !== job.state) el("auditCleanupCancelAcknowledge").checked = false;
      render();
    }
    function invalidate(message = "先预览全部影响范围；确认一次后由后台分批执行，不影响规则和用量账本。") {
      gate.cancel("audit-jobs-preview"); preview = null; previewSelection = ""; uncertain = false;
      el("auditCleanupAcknowledge").checked = false; visible("auditCleanupConfirmation",false);
      set("auditCleanupMessage",message); controls();
    }
    async function refresh(detailId = "", verify = false) {
      if (!active || !isAuthenticated() || unsupported || (busy && !verify)) return;
      if (reading) return reading;
      stopTimer(); const generation = epoch, ticket = gate.begin("audit-jobs-read");
      const task = (async () => {
        try {
          const payload = await request(detailId ? BASE + "/detail?id=" + encodeURIComponent(detailId) : BASE,{method:"GET",signal:ticket.signal});
          if (!ticket.current() || !current(generation)) return;
          const previousJobs = new Map(jobs.map(job => [job.id,job]));
          if (detailId) { const job = validateJob(payload.job); if (job.id !== detailId) throw new Error("清理任务 ID 不一致"); replaceJob(job); }
          else {
            const previous = selected(); jobs = validateList(payload);
            if (!jobs.some(v => v.id === selectedId)) selectedId = (jobs.find(activeJob) || jobs[0] || {}).id || "";
            const job = selected(); if (!previous || !job || previous.id !== job.id || previous.state !== job.state) el("auditCleanupCancelAcknowledge").checked = false;
            render();
          }
          let refreshed = true;
          if (jobs.some(job => activeJob(previousJobs.get(job.id)) && !activeJob(job))) refreshed = await notify(generation);
          if (!ticket.current() || !current(generation)) return;
          if (refreshed) set("auditCleanupJobMessage", jobs.length ? "任务状态已从服务端恢复；离开页面不会取消后台任务。取消后已删除记录不可恢复。" : "当前管理会话没有清理任务。离开页面不会取消已启动任务。");
        } catch (error) {
          if (!ticket.current() || !current(generation) || error.name === "AbortError") return;
          unsupported = !detailId && (error.status === 404 || error.status === 405 || error.status === 501);
          set("auditCleanupJobMessage", unsupported ? "当前后端不支持全量后台清理任务，请升级后端；不会自动退回旧单批清理。" : "任务状态读取失败：" + error.message + "。保留上次状态，可手动刷新核实。");
        } finally {
          ticket.finish();
          if (current(generation) && reading === task) { reading = null; controls(); schedulePoll(); }
        }
      })();
      reading = task; controls(); return task;
    }
    async function notify(generation) {
      try { await onChanged(); return true; } catch (_) { if (current(generation)) set("auditCleanupJobMessage","后台任务状态已确认，但审计列表/占用刷新失败；请手动刷新，不要重复启动。"); return false; }
    }
    async function makePreview() {
      if (!active || !isAuthenticated() || busy || unsupported || uncertain) return;
      invalidate(); let choice;
      try { choice = selection(); } catch (error) { set("auditCleanupMessage",error.message); el("auditCleanupBefore").setAttribute("aria-invalid","true"); el("auditCleanupBefore").focus(); return; }
      el("auditCleanupBefore").removeAttribute("aria-invalid");
      const generation = epoch, ticket = gate.begin("audit-jobs-preview"); busy = true; controls();
      set("auditCleanupMessage","正在计算全部快照，尚未删除记录…");
      try {
        const payload = await request(BASE+"/preview",{method:"POST",body:JSON.stringify(choice),signal:ticket.signal});
        if (!ticket.current() || !current(generation)) return;
        const checked = validatePreview(payload,choice);
        if (Date.parse(checked.expires_at) <= now()) throw new Error("预览已过期，请手动重新预览并确认");
        preview = checked; previewSelection = selectionIdentity();
        set("auditCleanupMessage","将永久删除全部快照中的 " + checked.records + " 条 · 逻辑占用 " + bytes(checked.logical_bytes) + " · 正文 " + bytes(checked.request_body_bytes) + "。确认一次后后台分批，每批最多 " + checked.batch_max_records + " 条 / " + bytes(checked.batch_max_bytes) + "；预览后新增记录不纳入，不自动扩大范围。预览到期 " + checked.expires_at + (checked.before ? " · 截止 " + checked.before : ""));
        visible("auditCleanupConfirmation",checked.records > 0);
      } catch (error) { if (ticket.current() && current(generation) && error.name !== "AbortError") invalidate("全量清理预览失败：" + error.message); }
      finally { if (current(generation)) { busy = false; controls(); schedulePoll(); } ticket.finish(); }
    }
    async function start() {
      if (!active || !isAuthenticated() || busy || !preview || !el("auditCleanupAcknowledge").checked) return;
      if (!uncertain) {
        const choice = selectionIdentity();
        if (choice !== previewSelection || Date.parse(preview.expires_at) <= now()) { invalidate("范围已变化或预览已过期，请手动重新预览并确认。"); return; }
      }
      stopRead();
      const generation = epoch, ticket = gate.begin("audit-jobs-write"), token = preview.token;
      busy = true; controls(); set("auditCleanupMessage","正在启动已确认的全部快照任务…");
      try {
        const payload = await request(BASE,{method:"POST",body:JSON.stringify({token,confirm:true}),signal:ticket.signal});
        if (!ticket.current() || !current(generation)) return;
        if (payload.ok !== true) throw new Error("服务端未确认任务启动");
        const job = validateJob(payload.job); invalidate("后台清理任务已启动；仅处理本次已确认快照。退出页面不会取消任务。"); replaceJob(job); await notify(generation);
      } catch (error) {
        if (!ticket.current() || !current(generation) || error.name === "AbortError") return;
        uncertain = true;
        set("auditCleanupMessage","启动结果未确认：" + error.message + "。正在查询任务列表核实；不会自动重放写请求。保留同一快照 token，可核实后人工点击同一快照重试（服务端幂等），也可明确放弃本地确认。");
        await refresh("",true);
      } finally { if (current(generation)) { busy = false; controls(); schedulePoll(); } ticket.finish(); }
    }
    async function mutate(action) {
      const job = selected();
      if (!active || !isAuthenticated() || busy || !job || (action === "cancel" ? !activeJob(job) : !resumable(job))) return;
      if (action === "cancel" && !el("auditCleanupCancelAcknowledge").checked) { set("auditCleanupJobMessage","取消仅停止剩余清理；已删除的记录不可恢复，请先勾选确认。"); el("auditCleanupCancelAcknowledge").focus(); return; }
      stopRead(); const generation = epoch, ticket = gate.begin("audit-jobs-write"); busy = true; controls();
      try {
        const payload = await request(BASE+"/"+action,{method:"POST",body:JSON.stringify({id:job.id}),signal:ticket.signal});
        if (!ticket.current() || !current(generation)) return;
        if (payload.ok !== true) throw new Error("服务器未确认任务操作");
        const checked = validateJob(payload.job); if (checked.id !== job.id) throw new Error("清理任务 ID 不一致");
        replaceJob(checked); set("auditCleanupJobMessage",action === "cancel" ? "取消状态已确认；已删除记录不可恢复。" : "已继续同一快照任务，未新建预览或扩大范围。"); await notify(generation);
      } catch (error) { if (ticket.current() && current(generation) && error.name !== "AbortError") { set("auditCleanupJobMessage","操作结果未确认：" + error.message + "；请刷新任务核实，不会自动重复提交。"); await refresh("",true); } }
      finally { if (current(generation)) { busy = false; controls(); schedulePoll(); } ticket.finish(); }
    }
    function leave() {
      active = false; epoch++; stopTimer();
      for (const scope of ["audit-jobs-read","audit-jobs-preview","audit-jobs-write"]) gate.cancel(scope);
      reading = null; busy = false; invalidate(); el("auditCleanupCancelAcknowledge").checked = false; controls();
    }
    function lock() { leave(); jobs = []; selectedId = ""; unsupported = false; render(); set("auditCleanupJobMessage",""); set("auditCleanupMessage",""); }
    function enter() { active = true; unsupported = false; render(); return refresh(); }
    el("auditCleanupPreview").addEventListener("click",makePreview);
    el("auditCleanupStartForm").addEventListener("submit",event => { event.preventDefault(); start(); });
    el("auditCleanupCancel").addEventListener("click",() => { if (!busy) invalidate(); });
    el("auditCleanupScope").addEventListener("change",() => { invalidate(); visible("auditCleanupBeforeLabel",el("auditCleanupScope").value === "custom"); });
    el("auditCleanupBefore").addEventListener("input",() => { invalidate(); el("auditCleanupBefore").removeAttribute("aria-invalid"); });
    el("auditCleanupAcknowledge").addEventListener("change",controls);
    el("auditCleanupJobsRefresh").addEventListener("click",() => refresh());
    el("auditCleanupJobSelect").addEventListener("change",() => { if (busy) return; selectedId = el("auditCleanupJobSelect").value; el("auditCleanupCancelAcknowledge").checked = false; render(); refresh(selectedId); });
    el("auditCleanupJobCancel").addEventListener("click",() => mutate("cancel"));
    el("auditCleanupJobResume").addEventListener("click",() => mutate("resume"));
    controls();
    return {enter,leave,lock,refresh,preview:makePreview,start,cancel:() => mutate("cancel"),resume:() => mutate("resume"),invalidate};
  }
  return {create,validatePreview,validateJob,validateList};
});

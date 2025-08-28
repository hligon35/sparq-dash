// Storage Allocation Manager (modular, resizable panel)
// Provides CRUD over allocations, global thresholds, disk stats, and overcommit warnings.
(function(){
  if (window.StorageManager) return;

  const BASE = (function(){
    try {
      const p = window.location.pathname || '';
      return p.startsWith('/portal') ? '/portal' : '';
    } catch(_) { return ''; }
  })();

  function candidateFetch(paths, init){
    const cands = [];
    for (const p of paths){
      const clean = p.startsWith('/') ? p : '/' + p;
      cands.push(clean);
      if (!clean.startsWith('/portal/')) cands.push('/portal' + clean);
      try { if (typeof window.__withBase__==='function') cands.push(window.__withBase__(clean.replace(/^\//,''))); } catch(_){ }
    }
    let lastErr;
    return (async ()=>{
      for (const url of cands){
        try { const r = await fetch(url, { credentials:'include', ...(init||{}) }); if (r.ok) return r; lastErr = new Error('HTTP '+r.status); } catch(e){ lastErr = e; }
      }
      throw lastErr || new Error('All candidates failed');
    })();
  }

  const tpl = `
  <div id="smgr-panel" role="dialog" aria-label="Storage Allocation Manager" style="position:fixed; right:20px; bottom:90px; width:720px; height:480px; background:#fff; border:1px solid #dee2e6; border-radius:12px; box-shadow:0 18px 40px rgba(0,0,0,.2); display:none; z-index:9998; overflow:hidden;">
    <div id="smgr-titlebar" style="cursor:move; display:flex; align-items:center; justify-content:space-between; padding:10px 12px; background:linear-gradient(90deg,#1a78d8,#3aa0ff); color:#fff;">
      <div style="font-weight:700;">Storage Allocation Manager</div>
      <div>
        <button id="smgr-close" aria-label="Close" title="Close" style="background:rgba(255,255,255,.2); color:#fff; border:0; border-radius:8px; padding:6px 10px; cursor:pointer;">✕</button>
      </div>
    </div>
    <div style="display:flex; height:calc(100% - 46px); gap:12px;">
      <div style="flex:1; display:flex; flex-direction:column; padding:10px; overflow:auto;">
        <div id="smgr-warnings" style="display:none; margin:0 0 8px 0; padding:8px 10px; border-radius:8px; background:#fff3cd; color:#664d03; border:1px solid #ffecb5;"></div>
        <div style="display:flex; gap:10px; align-items:center; margin-bottom:8px;">
          <div id="smgr-disk" style="font-size:12px; color:#495057;">Disk: —</div>
          <div id="smgr-alloc-summary" style="font-size:12px; color:#495057;">Allocations: —</div>
          <div style="margin-left:auto;">
            <button id="smgr-add" class="btn" style="padding:6px 10px; border-radius:8px; border:1px solid #ced4da; background:#f8f9fa; cursor:pointer;">➕ Add</button>
          </div>
        </div>
        <div style="border:1px solid #e9ecef; border-radius:8px; overflow:hidden;">
          <table style="width:100%; border-collapse:collapse; font-size:13px;">
            <thead style="background:#f8f9fa;">
              <tr>
                <th style="text-align:left; padding:8px; border-bottom:1px solid #e9ecef;">Client</th>
                <th style="text-align:left; padding:8px; border-bottom:1px solid #e9ecef;">Purpose</th>
                <th style="text-align:right; padding:8px; border-bottom:1px solid #e9ecef;">Allocated (GB)</th>
                <th style="text-align:right; padding:8px; border-bottom:1px solid #e9ecef;">Used (GB)</th>
                <th style="text-align:right; padding:8px; border-bottom:1px solid #e9ecef;">Remain</th>
                <th style="text-align:center; padding:8px; border-bottom:1px solid #e9ecef;">Actions</th>
              </tr>
            </thead>
            <tbody id="smgr-rows"></tbody>
          </table>
        </div>
      </div>
      <div style="width:260px; border-left:1px solid #e9ecef; padding:10px; overflow:auto;">
        <div style="font-weight:700; margin-bottom:8px;">Global Alerts</div>
        <label style="display:block; font-size:12px; color:#495057;">Warn at ≤ 20%<input id="smgr-t20" type="number" min="1" max="99" style="width:100%; padding:6px; border:1px solid #ced4da; border-radius:8px; margin-top:4px;"/></label>
        <label style="display:block; font-size:12px; color:#495057; margin-top:8px;">Warn at ≤ 10%<input id="smgr-t10" type="number" min="1" max="99" style="width:100%; padding:6px; border:1px solid #ced4da; border-radius:8px; margin-top:4px;"/></label>
        <label style="display:block; font-size:12px; color:#495057; margin-top:8px;">Warn at ≤ 5%<input id="smgr-t5" type="number" min="1" max="99" style="width:100%; padding:6px; border:1px solid #ced4da; border-radius:8px; margin-top:4px;"/></label>
        <button id="smgr-save-th" class="btn" style="margin-top:10px; width:100%; padding:8px 10px; border-radius:8px; border:1px solid #ced4da; background:#e7f1ff; cursor:pointer;">💾 Save Thresholds</button>
        <div style="margin-top:14px; font-size:12px; color:#6c757d;">Emails are sent via your configured SMTP (falls back to mock transport).</div>
      </div>
    </div>
    <div id="smgr-resize" style="position:absolute; right:0; bottom:0; width:16px; height:16px; cursor:nwse-resize; background:transparent;"></div>
  </div>`;

  function el(id){ return document.getElementById(id); }
  function ensurePanel(){
    if (!el('smgr-panel')){
      const wrap = document.createElement('div');
      wrap.innerHTML = tpl;
      document.body.appendChild(wrap.firstElementChild);
      wireDrag();
      wireResize();
    }
  }

  function wireDrag(){
    const panel = el('smgr-panel'); const bar = el('smgr-titlebar'); if (!panel || !bar) return;
    let dragging=false, sx=0, sy=0, sl=0, st=0;
    bar.addEventListener('mousedown', (e)=>{ dragging=true; sx=e.clientX; sy=e.clientY; const r = panel.getBoundingClientRect(); sl=r.left; st=r.top; e.preventDefault(); });
    window.addEventListener('mousemove', (e)=>{ if (!dragging) return; const dx=e.clientX-sx, dy=e.clientY-sy; panel.style.left=(sl+dx)+'px'; panel.style.top=(st+dy)+'px'; panel.style.right='auto'; panel.style.bottom='auto'; });
    window.addEventListener('mouseup', ()=> dragging=false);
  }
  function wireResize(){
    const panel = el('smgr-panel'); const gr = el('smgr-resize'); if (!panel || !gr) return;
    let resizing=false, sx=0, sy=0, sw=0, sh=0;
    gr.addEventListener('mousedown', (e)=>{ resizing=true; sx=e.clientX; sy=e.clientY; const r=panel.getBoundingClientRect(); sw=r.width; sh=r.height; e.preventDefault(); });
    window.addEventListener('mousemove', (e)=>{ if (!resizing) return; const dx=e.clientX-sx, dy=e.clientY-sy; panel.style.width=Math.max(520, sw+dx)+'px'; panel.style.height=Math.max(360, sh+dy)+'px'; });
    window.addEventListener('mouseup', ()=> resizing=false);
  }

  function percentRemaining(a){
    const alloc = Number(a.allocatedGB||a.totalGB||0) || 0;
    const used = Number(a.usedGB||0) || 0;
    if (!alloc) return 100;
    return Math.max(0, Math.round(((alloc - used)/alloc)*100));
  }

  async function loadState(){
    const r = await candidateFetch(['/api/storage/allocations']);
    const data = await r.json();
    return data || { allocations:[], globalThresholds:{warn20:20,warn10:10,warn5:5}, disk:{totalGB:0, freeGB:0} };
  }
  async function saveThresholds(t){
    const r = await candidateFetch(['/api/storage/thresholds'], { method:'PUT', headers:{'Content-Type':'application/json'}, body: JSON.stringify(t) });
    return r.json();
  }
  async function upsertAllocation(a){
    const method = a.id ? 'PUT' : 'POST';
    const url = a.id ? `/api/storage/allocations/${a.id}` : '/api/storage/allocations';
    const r = await candidateFetch([url], { method, headers:{'Content-Type':'application/json'}, body: JSON.stringify(a) });
    return r.json();
  }
  async function deleteAllocation(id){
    const r = await candidateFetch([`/api/storage/allocations/${id}`], { method:'DELETE' });
    return r.json();
  }

  function renderRows(state){
    const tb = el('smgr-rows'); if (!tb) return;
    tb.innerHTML='';
    (state.allocations||[]).forEach(a=>{
      const tr = document.createElement('tr');
      const alloc = Number(a.allocatedGB||0); const used = Number(a.usedGB||0); const remain = Math.max(0, alloc-used);
      const pct = percentRemaining(a);
      tr.innerHTML = `
        <td style="padding:8px; border-bottom:1px solid #f1f3f5;">${(a.client||'').toString().slice(0,60)}</td>
        <td style="padding:8px; border-bottom:1px solid #f1f3f5; color:#6c757d;">${(a.purpose||'').toString().slice(0,80)}</td>
        <td style="padding:8px; border-bottom:1px solid #f1f3f5; text-align:right;">${alloc}</td>
        <td style="padding:8px; border-bottom:1px solid #f1f3f5; text-align:right;">${used}</td>
        <td style="padding:8px; border-bottom:1px solid #f1f3f5; text-align:right; ${pct<=10?'color:#dc3545; font-weight:700;':pct<=20?'color:#fd7e14;':''}">${remain} (${pct}%)</td>
        <td style="padding:6px; border-bottom:1px solid #f1f3f5; text-align:center; white-space:nowrap;">
          <button data-id="${a.id}" class="smgr-edit" title="Edit" style="border:1px solid #ced4da; background:#f8f9fa; border-radius:6px; padding:4px 8px; cursor:pointer;">✏️</button>
          <button data-id="${a.id}" class="smgr-del" title="Delete" style="border:1px solid #ced4da; background:#fff; border-radius:6px; padding:4px 8px; cursor:pointer; margin-left:6px;">🗑️</button>
        </td>`;
      tb.appendChild(tr);
    });
  }

  function overcommitWarnings(state){
    const warnEl = el('smgr-warnings'); if (!warnEl) return;
    const disk = state.disk||{totalGB:0, freeGB:0};
    const allocTotal = (state.allocations||[]).reduce((s,a)=> s + (Number(a.allocatedGB||0)||0), 0);
    const usedTotal = (state.allocations||[]).reduce((s,a)=> s + (Number(a.usedGB||0)||0), 0);
    const needed = Math.max(0, allocTotal - usedTotal);
    const msgs = [];
    if (allocTotal > (disk.totalGB||0)) msgs.push(`Allocated ${allocTotal}GB exceeds total disk capacity ${disk.totalGB||0}GB.`);
    if (needed > (disk.freeGB||0)) msgs.push(`Planned remaining need ${needed}GB exceeds current free space ${disk.freeGB||0}GB.`);
    warnEl.style.display = msgs.length ? 'block' : 'none';
    warnEl.textContent = msgs.join(' ');
  }

  function updateMeta(state){
    const disk = state.disk||{}; const allocs = state.allocations||[];
    const allocTotal = allocs.reduce((s,a)=> s + (Number(a.allocatedGB||0)||0), 0);
    const usedTotal = allocs.reduce((s,a)=> s + (Number(a.usedGB||0)||0), 0);
    const d = el('smgr-disk'); if (d) d.textContent = `Disk: Total ${disk.totalGB||0}GB · Free ${disk.freeGB||0}GB`;
    const s = el('smgr-alloc-summary'); if (s) s.textContent = `Allocations: ${allocs.length} · Alloc ${allocTotal}GB · Used ${usedTotal}GB`;
  }

  function fillThresholds(t){
    el('smgr-t20').value = Number(t?.warn20 ?? 20);
    el('smgr-t10').value = Number(t?.warn10 ?? 10);
    el('smgr-t5').value  = Number(t?.warn5  ?? 5);
  }

  function openEditor(existing){
    const panel = el('smgr-panel'); if (!panel) return;
    const overlay = document.createElement('div');
    overlay.style.cssText = 'position:absolute; inset:46px 0 0 0; background:rgba(0,0,0,.12); display:flex; align-items:center; justify-content:center; z-index:3;';
    const card = document.createElement('div');
    card.style.cssText = 'background:#fff; width:520px; max-width:calc(100% - 40px); border:1px solid #dee2e6; border-radius:12px; padding:12px; box-shadow:0 10px 24px rgba(0,0,0,.2);';
    card.innerHTML = `
      <div style="font-weight:700; margin-bottom:8px;">${existing?'Edit':'Add'} Allocation</div>
      <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px;">
        <label style="font-size:12px; color:#495057;">Client<input id="smgr-e-client" type="text" style="width:100%; padding:8px; border:1px solid #ced4da; border-radius:8px;" value="${existing?.client||''}"></label>
        <label style="font-size:12px; color:#495057;">Email (alerts)<input id="smgr-e-email" type="email" style="width:100%; padding:8px; border:1px solid #ced4da; border-radius:8px;" value="${existing?.email||''}"></label>
        <label style="font-size:12px; color:#495057; grid-column:1 / span 2;">Purpose<input id="smgr-e-purpose" type="text" style="width:100%; padding:8px; border:1px solid #ced4da; border-radius:8px;" value="${existing?.purpose||''}"></label>
        <label style="font-size:12px; color:#495057;">Allocated (GB)<input id="smgr-e-alloc" type="number" min="0" style="width:100%; padding:8px; border:1px solid #ced4da; border-radius:8px;" value="${Number(existing?.allocatedGB||existing?.totalGB||0)}"></label>
        <label style="font-size:12px; color:#495057;">Used (GB)<input id="smgr-e-used" type="number" min="0" style="width:100%; padding:8px; border:1px solid #ced4da; border-radius:8px;" value="${Number(existing?.usedGB||0)}"></label>
        <label style="font-size:12px; color:#495057; grid-column:1 / span 2;">Server Path (auto-track usage on Linux)<input id="smgr-e-path" type="text" placeholder="e.g., /home/sparqd/sites/example.com" style="width:100%; padding:8px; border:1px solid #ced4da; border-radius:8px;" value="${existing?.path||''}"></label>
        <label style="font-size:12px; color:#495057; display:flex; align-items:center; gap:8px;">
          <input id="smgr-e-auto" type="checkbox" ${existing?.autoTrack !== false ? 'checked' : ''}>
          Auto-update Used from Path
        </label>
        <div style="grid-column:1 / span 2; display:grid; grid-template-columns:repeat(3, 1fr); gap:10px; margin-top:6px;">
          <label style="font-size:12px; color:#495057;">Warn ≤ 20%<input id="smgr-e-t20" type="number" min="1" max="99" style="width:100%; padding:6px; border:1px solid #ced4da; border-radius:8px;" value="${Number(existing?.thresholds?.warn20 ?? '')}"></label>
          <label style="font-size:12px; color:#495057;">Warn ≤ 10%<input id="smgr-e-t10" type="number" min="1" max="99" style="width:100%; padding:6px; border:1px solid #ced4da; border-radius:8px;" value="${Number(existing?.thresholds?.warn10 ?? '')}"></label>
          <label style="font-size:12px; color:#495057;">Warn ≤ 5%<input id="smgr-e-t5" type="number" min="1" max="99" style="width:100%; padding:6px; border:1px solid #ced4da; border-radius:8px;" value="${Number(existing?.thresholds?.warn5 ?? '')}"></label>
        </div>
      </div>
      <div style="display:flex; justify-content:flex-end; gap:8px; margin-top:12px;">
        <button id="smgr-e-cancel" class="btn" style="padding:8px 12px; border:1px solid #ced4da; border-radius:8px; background:#fff; cursor:pointer;">Cancel</button>
        <button id="smgr-e-save" class="btn" style="padding:8px 12px; border:1px solid #ced4da; border-radius:8px; background:#e7f1ff; cursor:pointer;">Save</button>
      </div>`;
    overlay.appendChild(card);
    panel.appendChild(overlay);
    const close = ()=> overlay.remove();
    el('smgr-e-cancel').onclick = close;
    el('smgr-e-save').onclick = async ()=>{
      const payload = {
        id: existing?.id,
        client: el('smgr-e-client').value.trim(),
        email: el('smgr-e-email').value.trim(),
        purpose: el('smgr-e-purpose').value.trim(),
        allocatedGB: Number(el('smgr-e-alloc').value || 0),
        usedGB: Number(el('smgr-e-used').value || 0),
        path: el('smgr-e-path').value.trim(),
        autoTrack: !!el('smgr-e-auto').checked
      };
      const t20 = Number(el('smgr-e-t20').value); const t10 = Number(el('smgr-e-t10').value); const t5 = Number(el('smgr-e-t5').value);
      if (Number.isFinite(t20) || Number.isFinite(t10) || Number.isFinite(t5)){
        payload.thresholds = {
          warn20: Number.isFinite(t20) ? t20 : undefined,
          warn10: Number.isFinite(t10) ? t10 : undefined,
          warn5:  Number.isFinite(t5)  ? t5  : undefined
        };
      }
      try { await upsertAllocation(payload); await StorageManager.refresh(); close(); } catch(_){ alert('Save failed'); }
    };
  }

  async function render(){
    ensurePanel();
    const state = await loadState();
    fillThresholds(state.globalThresholds||{});
    renderRows(state);
    updateMeta(state);
    overcommitWarnings(state);
    // actions
    const panel = el('smgr-panel');
    panel.querySelectorAll('.smgr-edit').forEach(btn=>{
      btn.addEventListener('click', ()=>{
        const id = btn.getAttribute('data-id');
        const cur = (state.allocations||[]).find(x=>x.id===id);
        openEditor(cur);
      });
    });
    panel.querySelectorAll('.smgr-del').forEach(btn=>{
      btn.addEventListener('click', async ()=>{
        const id = btn.getAttribute('data-id');
        if (!confirm('Delete this allocation?')) return;
        try { await deleteAllocation(id); await StorageManager.refresh(); } catch(_){ alert('Delete failed'); }
      });
    });
  }

  const StorageManager = {
    open: async function(){ ensurePanel(); const p = el('smgr-panel'); p.style.display='block'; await render(); },
    close: function(){ const p = el('smgr-panel'); if (p) p.style.display='none'; },
    refresh: render,
    init: function(){
      ensurePanel();
      const p = el('smgr-panel');
      el('smgr-close').onclick = StorageManager.close;
      el('smgr-add').onclick = ()=> openEditor(null);
      el('smgr-save-th').onclick = async ()=>{
        const t = { warn20:Number(el('smgr-t20').value||20), warn10:Number(el('smgr-t10').value||10), warn5:Number(el('smgr-t5').value||5) };
        try { await saveThresholds(t); await StorageManager.refresh(); } catch(_){ alert('Save failed'); }
      };
    }
  };

  window.StorageManager = StorageManager;

  // optional: auto-inject a launcher if none exists
  function injectLauncher(){
    if (document.getElementById('smgr-launcher')) return;
    const div = document.createElement('div');
    div.id = 'smgr-launcher';
    div.style.cssText = 'position:fixed; left:20px; bottom:20px; z-index:9999;';
    div.innerHTML = '<button id="smgr-open" title="Storage Allocation Manager" style="background:#343a40; color:#fff; border:0; border-radius:999px; padding:10px 14px; box-shadow:0 10px 24px rgba(0,0,0,.2); cursor:pointer;">📦 Storage</button>';
    document.body.appendChild(div);
    document.getElementById('smgr-open').addEventListener('click', ()=> StorageManager.open());
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', ()=>{ StorageManager.init(); injectLauncher(); });
  } else { StorageManager.init(); injectLauncher(); }
})();

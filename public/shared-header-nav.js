(function(){
  try {
    // Skip on login pages
    if (document.getElementById('login-form') || document.body.classList.contains('no-shared-nav')) return;

    // Idempotency guards
    if (document.getElementById('portal-shared-header-style')) return injectUI(true);

    // Ensure base path helper exists
    if (typeof window.__withBase__ !== 'function') {
      window.__withBase__ = function(path){
        try {
          const p = String(path || '').replace(/^\/+/,'');
          const under = (window.location.pathname||'').startsWith('/portal');
          return (under?'/portal/':'/') + p;
        } catch(_) { return '/' + String(path||'').replace(/^\/+/,''); }
      };
    }

    // Style block mirroring index.html header/nav look
    const css = `
:root { --primary-orange:#f59c28; --secondary-orange:#f7b626; --primary-blue:#1a78d8; --secondary-blue:#1a78d8; --white:#fff; --off-white:#f8f9fa; --light-gray:#e9ecef; --dark-gray:#343a40; }
.shared-header { background: linear-gradient(135deg, var(--primary-blue) 0%, var(--secondary-blue) 100%); color:#fff; padding:18px 24px; text-align:center; }
.shared-header h1 { font-size: 2.0em; margin-bottom: 6px; }
.shared-header p { opacity:.9; }
.top-nav { display:flex; gap:8px; padding:14px 18px; background:#fff; border-bottom:1px solid var(--light-gray); align-items:center; flex-wrap:wrap; overflow-x:auto; -webkit-overflow-scrolling:touch; justify-content:center; }
.top-nav .nav-item { display:inline-flex; align-items:center; width:auto; padding:10px 14px; margin:6px 4px; font-size:.98em; white-space:nowrap; scroll-snap-align:start; text-align:center; border-radius:999px; border:1px solid #e5e7eb; background:#fff; color:#333; position:relative; box-shadow:0 1px 2px rgba(0,0,0,.04); transition:color .2s, background .2s, border-color .2s, transform .15s; text-decoration:none; }
.top-nav .nav-item:hover { background:#f8fafc; border-color:#cbd5e1; color:#111; transform: translateY(-1px); box-shadow:0 2px 4px rgba(0,0,0,.06); }
.top-nav .nav-item.active { background:#eff6ff; color:var(--primary-blue); border-color:var(--primary-blue); box-shadow:0 2px 6px rgba(26,120,216,.12); }
.top-nav .nav-item::before { content:''; display:inline-block; width:8px; height:8px; border-radius:999px; background:#cbd5e1; margin-right:8px; box-shadow:0 0 0 2px #fff; }
.top-nav .nav-item.active::before { background:var(--primary-blue); box-shadow:0 0 0 2px #eff6ff; }
.userbar { display:flex; flex-direction:column; align-items:center; gap:6px; position:fixed; top:10px; right:14px; padding:0; background:transparent; border:none; z-index:1000; }
.userbar .user-pill { display:inline-flex; align-items:center; gap:10px; padding:6px 12px; border:1px solid #e5e7eb; border-radius:999px; background:#fff; color:#111; box-shadow:0 2px 8px rgba(0,0,0,.10); font-size:14px; }
.userbar .online-dot { width:10px; height:10px; border-radius:999px; background:#f59e0b; box-shadow:0 0 0 2px #fff inset; }
.userbar .logout-link { background:transparent; border:none; color:inherit; cursor:pointer; font-weight:600; padding:0; }
.userbar .logout-link:hover { text-decoration: underline; }
.userbar .user-time { font-size:12px; color:#ffffff; text-align:center; text-shadow:0 1px 2px rgba(0,0,0,.25); }
`;
    const style = document.createElement('style');
    style.id = 'portal-shared-header-style';
    style.appendChild(document.createTextNode(css));
    document.head.appendChild(style);

    injectUI(false);

    function injectUI(alreadyStyled){
      // Don’t duplicate if a header is already present
      if (document.querySelector('.header, .shared-header')) return;
      const frag = document.createDocumentFragment();

      const header = document.createElement('div');
      header.className = 'shared-header';
      header.innerHTML = '<h1>Sparq Dashboard</h1><p>Account Management</p>';

      const nav = document.createElement('div');
      nav.className = 'top-nav';
      const items = [
        ['Dashboard','dashboard'],
        ['Create Domain Email','create-domain'],
        ['Webpage Setup','webpage-setup'],
        ['Manage Emails','manage-emails'],
        ['Storage Management','storage'],
        ['DNS Manager','dns-manager'],
        ['Client Portal','client-portal'],
        ['System Debug Panel','system-logs'],
        ['Settings','settings'],
      ];
      items.forEach(([label,hash],i)=>{
        const a = document.createElement('a');
        a.className = 'nav-item' + (i===0?' active':'');
        a.href = window.__withBase__('/index.html#' + hash);
        a.textContent = label;
        nav.appendChild(a);
      });

      const userbar = document.createElement('div');
      userbar.className = 'userbar';
      userbar.innerHTML = '<div class="user-pill"><span class="online-dot" aria-hidden="true"></span><span id="user-pill-label">Signed In</span><span aria-hidden="true">•</span><button type="button" class="logout-link" title="Logout">Logout</button></div><div class="user-time" id="user-time">—</div>';

      frag.appendChild(header);
      frag.appendChild(nav);
      document.body.insertBefore(frag, document.body.firstChild);
      document.body.appendChild(userbar);

      // Wire logout if available globally
      userbar.querySelector('.logout-link')?.addEventListener('click', function(){
        if (typeof window.logout === 'function') return window.logout();
        // fallback: hit /api/auth/logout then redirect to login
        try { fetch('/api/auth/logout', { method:'POST', credentials:'include' }).finally(()=>{ window.location.assign(window.__withBase__('/login.html')); }); } catch(_) { window.location.assign(window.__withBase__('/login.html')); }
      });

      // Timestamp updater
      function format12(d){
        try { const mm=String(d.getMonth()+1).padStart(2,'0'); const dd=String(d.getDate()).padStart(2,'0'); const yyyy=d.getFullYear(); let h=d.getHours(); const m=String(d.getMinutes()).padStart(2,'0'); const ampm=h>=12?'PM':'AM'; h=h%12; if(h===0)h=12; return `${mm}/${dd}/${yyyy} ${String(h).padStart(2,'0')}:${m} ${ampm}`; } catch(_) { return ''; }
      }
      function tick(){ const el=document.getElementById('user-time'); if (el) el.textContent = format12(new Date()); }
      tick(); setInterval(tick, 30000);

      // Fill label minimally
      (async function(){
        try { const r = await fetch('/api/auth/me', { credentials: 'include' }); if (r.ok){ const lbl = document.getElementById('user-pill-label'); if (lbl) lbl.textContent = 'Signed In'; } } catch(_){}
      })();
    }
  } catch (e) { /* no-op */ }
})();

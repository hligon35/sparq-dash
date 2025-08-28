(function(){
  try {
    // Skip on login pages or when explicitly disabled
    if (document.getElementById('login-form') || document.body.classList.contains('no-shared-nav')) return;

    // Idempotency: don't add styles twice
    if (document.getElementById('portal-shared-header-style')) return;

    // Ensure base path helper exists (no-op for style-only, but kept for consistency)
    if (typeof window.__withBase__ !== 'function') {
      window.__withBase__ = function(path){
        try {
          const p = String(path || '').replace(/^\/+/,'');
          const under = (window.location.pathname||'').startsWith('/portal');
          return (under?'/portal/':'/') + p;
        } catch(_) { return '/' + String(path||'').replace(/^\/+/,''); }
      };
    }

    // Inject shared visual styles only; pages control their own markup and links
    const css = `
:root { --primary-orange:#f59c28; --secondary-orange:#f7b626; --primary-blue:#1a78d8; --secondary-blue:#1a78d8; --white:#fff; --off-white:#f8f9fa; --light-gray:#e9ecef; --dark-gray:#343a40; }
/* Hide legacy header overlay user info injected by admin-dashboard.js */
.header .user-info { display:none !important; }
.shared-header { background: linear-gradient(135deg, var(--primary-blue) 0%, var(--secondary-blue) 100%); color:#fff; padding:18px 24px; text-align:center; position:relative; }
.header { position:relative; }
.shared-header h1 { font-size: 2.0em; margin-bottom: 6px; }
.shared-header p { opacity:.9; }
.top-nav { display:flex; gap:8px; padding:14px 18px; background:#fff; border-bottom:1px solid var(--light-gray); align-items:center; flex-wrap:wrap; overflow-x:auto; -webkit-overflow-scrolling:touch; justify-content:center; }
.top-nav .nav-item { display:inline-flex; align-items:center; width:auto; padding:10px 14px; margin:6px 4px; font-size:.98em; white-space:nowrap; scroll-snap-align:start; text-align:center; border-radius:999px; border:1px solid #e5e7eb; background:#fff; color:#333; position:relative; box-shadow:0 1px 2px rgba(0,0,0,.04); transition:color .2s, background .2s, border-color .2s, transform .15s; text-decoration:none; cursor:pointer; }
.top-nav .nav-item:hover { background:#f8fafc; border-color:#cbd5e1; color:#111; transform: translateY(-1px); box-shadow:0 2px 4px rgba(0,0,0,.06); }
.top-nav .nav-item.active { background:#eff6ff; color:var(--primary-blue); border-color:var(--primary-blue); box-shadow:0 2px 6px rgba(26,120,216,.12); }
.top-nav .nav-item::before { content:''; display:inline-block; width:8px; height:8px; border-radius:999px; background:#cbd5e1; margin-right:8px; box-shadow:0 0 0 2px #fff; }
.top-nav .nav-item.active::before { background:var(--primary-blue); box-shadow:0 0 0 2px #eff6ff; }
/* CTA button style (optional for pages that add a highlighted action) */
.top-nav .nav-item.cta { background: var(--primary-orange); color:#fff; border-color: var(--primary-orange); box-shadow:0 2px 6px rgba(245,156,40,.25); }
.top-nav .nav-item.cta:hover { background: var(--secondary-orange); border-color: var(--secondary-orange); color:#fff; }
/* Optional userbar style only (pages may render it if desired) */
.userbar { display:flex; flex-direction:column; align-items:center; gap:4px; position:absolute; top:18px; right:14px; padding:0; background:transparent; border:none; z-index:1000; }
.userbar .user-pill { display:inline-flex; align-items:center; gap:8px; padding:4px 9px; border:1px solid #e5e7eb; border-radius:999px; background:#fff; color:#111; box-shadow:0 2px 8px rgba(0,0,0,.10); font-size:11px; }
.userbar .online-dot { width:8px; height:8px; border-radius:999px; background:#f59e0b; box-shadow:0 0 0 2px #fff inset; }
.userbar .logout-link { background:transparent; border:none; color:inherit; cursor:pointer; font-weight:600; padding:0; }
.userbar .logout-link:hover { text-decoration: underline; }
.userbar .user-time { font-size:9px; color:#ffffff; text-align:center; text-shadow:0 1px 2px rgba(0,0,0,.25); }
/* Fallback if a page lacks a header: keep it visible in the corner */
body > .userbar { position:fixed; top:8px; right:14px; }
`;

    const style = document.createElement('style');
    style.id = 'portal-shared-header-style';
    style.appendChild(document.createTextNode(css));
    document.head.appendChild(style);
  } catch (e) { /* no-op */ }
})();

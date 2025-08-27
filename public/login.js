(function(){
  // Base path support when served under /portal
  const BASE = window.__PORTAL_BASE__ || '';

  // Role selector functionality
  document.querySelectorAll('.role-option').forEach(option => {
    option.addEventListener('click', function() {
      document.querySelectorAll('.role-option').forEach(opt => opt.classList.remove('active'));
      this.classList.add('active');
      // Update form based on role
      const role = this.dataset.role;
      updateFormForRole(role);
    });
  });

  function updateFormForRole(role) {
    const usernameInput = document.getElementById('username');
    const passwordInput = document.getElementById('password');
    // Set generic placeholders for all roles
    usernameInput.placeholder = 'Username or Email';
    passwordInput.placeholder = 'Password';
  }

  // Login form submission
  document.getElementById('login-form').addEventListener('submit', async function(e) {
    e.preventDefault();
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const loginBtn = document.getElementById('login-btn');
    // Show loading state
    loginBtn.disabled = true;
    loginBtn.textContent = '🔄 Signing In...';
    hideAlerts();
    try {
      const response = await fetch(`${BASE}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ username, password })
      });
      const result = await response.json();
      if (response.ok) {
        showAlert('success', '✅ Login successful! Redirecting...');
        // Store token and user info
        localStorage.setItem('authToken', result.token);
        localStorage.setItem('currentUser', JSON.stringify(result.user));
        // Check if password change is required
        if (result.requirePasswordChange) {
          showAlert('success', '⚠️ Password change required. Redirecting...');
          setTimeout(() => { window.location.replace(window.__withBase__('change-password')); }, 1000);
        } else {
          // Redirect to dashboard or SSO returnTo target
          const params = new URLSearchParams(window.location.search);
          const sso = params.get('sso');
          const rt = params.get('returnTo');
          const isSafeRt = rt && /^https:\/\/(sparqplug\.getsparqd\.com|.*\.getsparqd\.com)/.test(rt);
          const dest = (sso === '1' && isSafeRt) ? rt : window.__withBase__('dashboard');
          setTimeout(() => { window.location.replace(dest); }, 1000);
        }
      } else {
        showAlert('error', result.error || 'Login failed');
      }
    } catch (error) {
      showAlert('error', 'Network error. Please try again.');
    } finally {
      loginBtn.disabled = false;
      loginBtn.textContent = '🔐 Sign In';
    }
  });

  function showAlert(type, message) {
    const alert = document.getElementById(`${type}-alert`);
    alert.textContent = message;
    alert.style.display = 'block';
  }

  function hideAlerts() {
    document.querySelectorAll('.alert').forEach(alert => { alert.style.display = 'none'; });
  }

  // ---- Redirect loop & token validation guard ----
  (function(){
    const LOOP_KEY = 'redirectLoopLoginDashboard';
    async function tokenValid() {
      try {
        const r = await fetch(`${BASE}/api/auth/me`, { credentials: 'include' });
        if (r.ok) return true;
      } catch(e){ console.warn('Token validation network error, skipping auto-redirect'); }
      return false;
    }
    function recordLoopAttempt(){
      try {
        const now = Date.now();
        let data = JSON.parse(sessionStorage.getItem(LOOP_KEY) || 'null');
        if (!data || (now - data.first) > 8000) { data = { first: now, count: 0 }; }
        data.count += 1;
        sessionStorage.setItem(LOOP_KEY, JSON.stringify(data));
        return data;
      } catch(e){ return { first: Date.now(), count: 1 }; }
    }
    function clearAuthWithNotice(reason){
      console.warn('Clearing auth to break redirect loop:', reason);
      localStorage.removeItem('authToken');
      localStorage.removeItem('currentUser');
      const alert = document.getElementById('error-alert');
      if (alert){
        alert.textContent = 'Session reset to stop a redirect loop. Please log in again.';
        alert.style.display = 'block';
      }
    }
    async function maybeRedirect(){
      if (localStorage.getItem('justLoggedOut') === 'true') {
        console.log('User just logged out, clearing logout flag');
        localStorage.removeItem('justLoggedOut');
        return; // stay on login
      }
      const token = localStorage.getItem('authToken');
      if (!token) return; // nothing to do
      const loopData = recordLoopAttempt();
      if (loopData.count > 3 && (Date.now() - loopData.first) < 8000) {
        clearAuthWithNotice('loop threshold exceeded');
        return; // abort redirect
      }
      if (await tokenValid()) {
        console.log('Valid token detected, redirecting to dashboard');
        window.location.replace(window.__withBase__('dashboard'));
      } else {
        console.log('Stored token invalid; removing and staying on login');
        clearAuthWithNotice('invalid token');
      }
    }
    setTimeout(maybeRedirect, 50);
  })();
  // ---- End guard ----

  // Initialize form
  updateFormForRole('admin');

  // Forgot password functionality
  document.getElementById('forgot-password-link').addEventListener('click', function(e) {
    e.preventDefault();
    showPasswordResetForm();
  });

  function showPasswordResetForm() {
    const resetForm = `
      <div style="margin-top: 20px; padding: 20px; background: white; border: 1px solid #e9ecef; border-radius: 8px;">
        <h4>🔑 Password Reset</h4>
        <div style="margin: 15px 0;">
          <label>Username:</label>
          <input type="text" id="reset-username" style="width: 100%; padding: 8px; margin: 5px 0;" placeholder="Enter your username">
        </div>
        <div style="margin: 15px 0;">
          <label>Email:</label>
          <input type="email" id="reset-email" style="width: 100%; padding: 8px; margin: 5px 0;" placeholder="Enter your registered email">
        </div>
        <button id="send-reset" style="background: var(--gradient-primary); color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer;">Send Reset Token</button>
        <button id="cancel-reset" style="background: #6c757d; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; margin-left: 10px;">Cancel</button>
      </div>`;
    document.querySelector('.login-form').insertAdjacentHTML('beforeend', resetForm);
    document.getElementById('send-reset').addEventListener('click', async function() {
      const username = document.getElementById('reset-username').value;
      const email = document.getElementById('reset-email').value;
      if (!username || !email) { showAlert('error', 'Please enter both username and email'); return; }
      try {
        const response = await fetch('/api/auth/request-reset', {
          method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username, email })
        });
        const result = await response.json();
        showAlert('success', result.message);
        if (result.resetToken) { showPasswordResetTokenForm(result.resetToken); }
      } catch (error) { showAlert('error', 'Reset request failed'); }
    });
    document.getElementById('cancel-reset').addEventListener('click', function() {
      document.querySelector('.login-form > div:last-child').remove();
    });
  }

  function showPasswordResetTokenForm(token) {
    const tokenForm = `
      <div style="margin-top: 20px; padding: 20px; background: white; border: 1px solid #e9ecef; border-radius: 8px;">
        <h4>🔐 Reset Password</h4>
        <p style="margin: 10px 0; font-size: 0.9em;">Reset token: <code>${token}</code></p>
        <div style="margin: 15px 0;">
          <label>New Password:</label>
          <input type="password" id="new-password" style="width: 100%; padding: 8px; margin: 5px 0;" placeholder="Enter new password (minimum 8 characters)">
        </div>
        <div style="margin: 15px 0;">
          <label>Confirm Password:</label>
          <input type="password" id="confirm-password" style="width: 100%; padding: 8px; margin: 5px 0;" placeholder="Confirm your new password">
        </div>
        <button id="complete-reset" style="background: #28a745; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer;">Reset Password</button>
      </div>`;
    document.querySelector('.login-form').insertAdjacentHTML('beforeend', tokenForm);
    document.getElementById('complete-reset').addEventListener('click', async function() {
      const newPassword = document.getElementById('new-password').value;
      const confirmPassword = document.getElementById('confirm-password').value;
      if (newPassword !== confirmPassword) { showAlert('error', 'Passwords do not match'); return; }
      if (newPassword.length < 8) { showAlert('error', 'Password must be at least 8 characters long'); return; }
      try {
        const response = await fetch('/api/auth/reset-password', {
          method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token, newPassword })
        });
        const result = await response.json();
        if (response.ok) {
          showAlert('success', 'Password reset successfully! You can now login.');
          document.querySelectorAll('.login-form > div:nth-last-child(-n+2)').forEach(el => el.remove());
        } else {
          showAlert('error', result.error);
        }
      } catch (error) { showAlert('error', 'Password reset failed'); }
    });
  }
})();

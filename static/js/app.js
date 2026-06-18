/* ═════════════════════════════════════════════════════════════
   SecureVote — app.js
   Shared utilities: theme, navigation, toasts, spinners, helpers
   ═════════════════════════════════════════════════════════════ */

// ── Theme ────────────────────────────────────────────────────

function initTheme() {
  const saved = localStorage.getItem('sv-theme') || 'dark';
  setTheme(saved, false);
}

function setTheme(theme, save = true) {
  document.documentElement.setAttribute('data-theme', theme);
  if (save) localStorage.setItem('sv-theme', theme);

  const isDark = theme === 'dark';

  // Sidebar toggle
  const icon  = document.getElementById('themeIcon');
  const label = document.getElementById('themeLabel');
  if (icon)  icon.className  = isDark ? 'bi bi-sun-fill' : 'bi bi-moon-stars-fill';
  if (label) label.textContent = isDark ? 'Light Mode' : 'Dark Mode';

  // Mobile toggle icon
  const mIcon = document.getElementById('themeIconMobile');
  if (mIcon) mIcon.className = isDark ? 'bi bi-sun-fill' : 'bi bi-moon-stars-fill';
}

function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme');
  setTheme(current === 'dark' ? 'light' : 'dark');
}

// ── Mobile Sidebar ───────────────────────────────────────────

function initMobileNav() {
  const btn     = document.getElementById('mobileMenuBtn');
  const sidebar = document.getElementById('sidebar');
  if (!btn || !sidebar) return;

  btn.addEventListener('click', () => sidebar.classList.toggle('open'));

  // Close on outside click
  document.addEventListener('click', e => {
    if (!sidebar.contains(e.target) && !btn.contains(e.target)) {
      sidebar.classList.remove('open');
    }
  });
}

// ── Toast ────────────────────────────────────────────────────

function showToast(message, type = 'info') {
  const toastEl = document.getElementById('liveToast');
  const body    = document.getElementById('toastBody');
  if (!toastEl || !body) return;

  body.textContent = message;
  toastEl.classList.remove('success-toast', 'error-toast', 'info-toast');

  if (type === 'success') {
    toastEl.classList.add('success-toast');
    toastEl.style.background = '#166534';
  } else if (type === 'error') {
    toastEl.classList.add('error-toast');
    toastEl.style.background = '#9f1239';
  } else {
    toastEl.style.background = '#1e3a5f';
  }

  const toast = bootstrap.Toast.getOrCreateInstance(toastEl, { delay: 4000 });
  toast.show();
}

// ── Loading state helper ─────────────────────────────────────

function setLoading(btnId, contentId, spinnerId, loading) {
  const btn     = document.getElementById(btnId);
  const content = document.getElementById(contentId);
  const spinner = document.getElementById(spinnerId);
  if (!btn) return;

  btn.disabled = loading;
  if (content) content.classList.toggle('hidden', loading);
  if (spinner) spinner.classList.toggle('hidden', !loading);
}

// ── Nav session badges ────────────────────────────────────────

function updateNavStatus() {
  fetch('/api/status').then(r => r.json()).then(d => {
    const regBadge   = document.getElementById('nav-reg-badge');
    const votedBadge = document.getElementById('nav-voted-badge');
    if (regBadge)   regBadge.classList.toggle('show', d.registered);
    if (votedBadge) votedBadge.classList.toggle('show', d.voted);
  }).catch(() => {});
}

// ── Sleep helper ──────────────────────────────────────────────

function sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }

// ── Boot ─────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  initMobileNav();
  updateNavStatus();

  // Wire theme toggles
  const desktopToggle = document.getElementById('themeToggle');
  const mobileToggle  = document.getElementById('themeToggleMobile');
  if (desktopToggle) desktopToggle.addEventListener('click', toggleTheme);
  if (mobileToggle)  mobileToggle.addEventListener('click', toggleTheme);
});

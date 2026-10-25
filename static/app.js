const $ = s => document.querySelector(s);
const steps = [...document.querySelectorAll('.pipeline li')];
const wait = ms => new Promise(r => setTimeout(r, ms));
const COLORS = {Clean: '#5cffc8', 'Low risk': '#5cffc8', Suspicious: '#ffb84d', Malicious: '#ff4d6d'};
const SUB = {
  Clean: 'No suspicious indicators were found.',
  'Low risk': 'Only minor indicators were found.',
  Suspicious: 'Several warning signs were found. Do not open this on your main device.',
  Malicious: 'Strong signs of malware. Do not open this.'
};

document.querySelectorAll('.tabs button').forEach(b => b.onclick = () => {
  document.querySelectorAll('.tabs button').forEach(x => x.setAttribute('aria-selected', x === b));
  document.querySelectorAll('.panel').forEach(p => p.hidden = p.dataset.panel !== b.dataset.tab);
});

const fileInput = $('#fileInput'), drop = $('#drop');
fileInput.onchange = () => { if (fileInput.files[0]) $('#dropText').textContent = fileInput.files[0].name; };
['dragover', 'dragenter'].forEach(e => drop.addEventListener(e, ev => { ev.preventDefault(); drop.classList.add('over'); }));
['dragleave', 'drop'].forEach(e => drop.addEventListener(e, () => drop.classList.remove('over')));
drop.addEventListener('drop', ev => { ev.preventDefault(); fileInput.files = ev.dataTransfer.files; fileInput.onchange(); });

async function animate(promise) {
  steps.forEach(s => s.className = '');
  for (let i = 0; i < 3; i++) { steps[i].className = 'run'; await wait(120); steps[i].className = 'done'; }
  steps[3].className = 'run';
  const res = await promise;
  steps[3].className = 'done'; steps[4].className = 'done';
  return res;
}

function dl(el, obj) {
  el.innerHTML = '';
  for (const [k, v] of Object.entries(obj)) {
    if (v === null || v === undefined || v === '' || (Array.isArray(v) && !v.length)) continue;
    const dt = document.createElement('dt'), dd = document.createElement('dd');
    dt.textContent = k.replace(/_/g, ' ');
    dd.textContent = typeof v === 'object' ? JSON.stringify(v) : String(v);
    el.append(dt, dd);
  }
}

function render(r) {
  const box = $('#result'); box.hidden = false;
  const v = $('#verdict');
  if (r.rejected) {
    v.className = 'verdict Malicious';
    $('#scoreNum').textContent = '-'; $('#arc').style.strokeDashoffset = 326.7;
    $('#verdictText').textContent = 'Not scanned';
    $('#verdictSub').textContent = r.errors.join(' ');
    $('#evidence').innerHTML = ''; $('#steps').innerHTML = '<li>Fix the issue above and scan again.</li>';
  } else {
    v.className = 'verdict ' + r.verdict;
    $('#scoreNum').textContent = r.score;
    $('#arc').style.stroke = COLORS[r.verdict];
    requestAnimationFrame(() => $('#arc').style.strokeDashoffset = 326.7 * (1 - r.score / 100));
    $('#verdictText').textContent = r.verdict;
    $('#verdictSub').textContent = SUB[r.verdict];
    const ev = $('#evidence'); ev.innerHTML = '';
    if (!r.evidence.length) ev.innerHTML = '<li><span class="w lo">0</span><span>No indicators found.</span></li>';
    r.evidence.forEach(e => {
      const li = document.createElement('li');
      const w = document.createElement('span'); w.className = 'w ' + (e.weight >= 50 ? 'hi' : e.weight < 25 ? 'lo' : ''); w.textContent = e.weight;
      const t = document.createElement('span'); t.textContent = e.evidence;
      const s = document.createElement('small'); s.textContent = e.category;
      t.append(s); li.append(w, t); ev.append(li);
    });
    $('#steps').innerHTML = '';
    r.next_steps.forEach(s => { const li = document.createElement('li'); li.textContent = s; $('#steps').append(li); });
  }
  renderExtras(r);
  dl($('#props'), r.properties); dl($('#meta'), r.metadata || {});
  const blocks = (r.entropy && r.entropy.blocks) || [];
  $('#ent').innerHTML = ''; $('#ent').hidden = $('#entH').hidden = !blocks.length;
  blocks.forEach(b => { const i = document.createElement('i'); i.style.height = (b / 8 * 100) + '%'; i.title = b + ' bits/byte'; $('#ent').append(i); });
  box.scrollIntoView({behavior: 'smooth'});
}

function httpMsg(status) {
  return status === 502 || status === 503 || status === 504 ? 'The server is busy or restarting. Please try again in a moment.'
       : status === 429 ? 'Too many requests. Please wait a little and try again.'
       : 'The server returned an unexpected response (HTTP ' + status + '). Please try again.';
}
async function fetchTimeout(url, opts, ms = 90000) {      // never leave the person waiting forever
  const ctl = new AbortController(), t = setTimeout(() => ctl.abort(), ms);
  try { return await fetch(url, {...opts, signal: ctl.signal}); }
  catch (e) { throw new Error(e.name === 'AbortError' ? 'The scan took too long. Try a smaller file.' : 'Could not reach the server. Check your connection and try again.'); }
  finally { clearTimeout(t); }
}

async function submit(btn, req) {
  btn.disabled = true;
  try {
    const r = await animate(req());
    render(r);
  } catch (e) {
    render({rejected: true, errors: [e.message || 'Scan failed. Try again.'], properties: {}});
  } finally { btn.disabled = false; }
}
const post = async (url, opts) => {
  const r = await fetchTimeout(url, opts);
  let j;
  try { j = await r.json(); } catch { throw new Error(httpMsg(r.status)); }
  if (j.error) throw new Error(j.error);
  return j;
};

$('#fileForm').onsubmit = e => {
  e.preventDefault();
  if (!fileInput.files[0]) return render({rejected: true, errors: ['Choose a file to scan.'], properties: {}});
  const fd = new FormData(); fd.append('file', fileInput.files[0]);
  submit(e.submitter, () => post('/api/scan/file', {method: 'POST', body: fd}));
};
$('#urlForm').onsubmit = e => {
  e.preventDefault();
  submit(e.submitter, () => post('/api/scan/url', {method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({url: $('#urlInput').value})}));
};


/* ---------- Hide & reveal tools ---------- */
function el(tag, cls, text) { const e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; return e; }

function showDownload(out, r) {
  if (r.mime.startsWith('image/')) { const img = el('img'); img.src = 'data:' + r.mime + ';base64,' + r.data; img.alt = 'Result preview'; out.append(img); }
  const a = el('a', 'dl', 'Download ' + r.filename);
  a.href = 'data:' + r.mime + ';base64,' + r.data; a.download = r.filename; out.append(a);
  if (r.note) out.append(el('p', 'hint', r.note));
}

function showIndicators(out, list) {
  if (!list || !list.length) return;
  const ul = el('ul');
  list.forEach(i => { const li = el('li'); li.append(el('span', 'tag ' + i.confidence, i.confidence), document.createTextNode(i.evidence)); ul.append(li); });
  out.append(el('p', 'no', 'Indicators'), ul);
}

const renderers = {
  file: (out, r) => showDownload(out, r),
  reveal: (out, r) => {
    if (r.found) { out.append(el('p', 'ok', 'Hidden message found'), el('div', 'msg', r.message)); }
    else out.append(el('p', 'no', 'No GhostScan message found'));
    showIndicators(out, r.indicators);
    const st = r.statistics || {};
    if (st.lsb_chi_square_p !== undefined) out.append(el('p', 'hint', 'Chi-square p = ' + st.lsb_chi_square_p + (st.lsb_rs_estimate != null ? ', RS estimate = ' + st.lsb_rs_estimate : '')));
    if (!r.found && r.note) out.append(el('p', 'hint', r.note));
  },
  detect: (out, r) => {
    if (r.found) out.append(el('p', 'ok', 'GhostScan watermark found (' + r.confidence + ' confidence)'), el('div', 'msg', r.text));
    else out.append(el('p', 'no', r.reason === 'too_small' ? 'Image too small to check' : 'No GhostScan watermark found'),
      el('p', 'hint', 'Watermarks from other tools or services need their own decoder. A missing mark does not prove an image is unmarked.'));
    const pv = r.provenance || {};
    const keys = Object.keys(pv);
    if (keys.length) { const dl = el('dl'); keys.forEach(k => { dl.append(el('dt', '', k.replace(/_/g, ' ')), el('dd', '', pv[k])); }); out.append(el('p', 'no', 'Provenance markers'), dl); }
    else out.append(el('p', 'hint', 'No C2PA or rights metadata found.'));
  }
};

document.querySelectorAll('form.tool').forEach(form => {
  form.addEventListener('submit', async e => {
    e.preventDefault();
    const out = form.querySelector('.out'), btn = form.querySelector('button');
    out.replaceChildren(el('p', 'hint', 'Working...')); btn.disabled = true;
    try {
      const res = await fetchTimeout(form.dataset.endpoint, {method: 'POST', body: new FormData(form)});
      let j; try { j = await res.json(); } catch { throw new Error(httpMsg(res.status)); }
      if (j.error) throw new Error(j.error);
      out.replaceChildren(); renderers[form.dataset.kind](out, j);
    } catch (err) { out.replaceChildren(el('p', 'err', err.message)); }
    finally { btn.disabled = false; }
  });
});


/* ---------- Services menu, service chooser ---------- */
const workspaces = {malware: $('#ws-malware'), watermark: $('#ws-watermark'), secret: $('#ws-secret')};
const serviceCards = [...document.querySelectorAll('.service-card')];
const svcBtn = $('#svcBtn'), svcMenu = $('#svcMenu');

function closeMenu() { svcMenu.hidden = true; svcBtn.setAttribute('aria-expanded', 'false'); }
svcBtn.addEventListener('click', e => {
  e.stopPropagation();
  const open = svcMenu.hidden;
  svcMenu.hidden = !open; svcBtn.setAttribute('aria-expanded', String(open));
  if (open) svcMenu.querySelector('button').focus();
});
document.addEventListener('click', e => { if (!svcMenu.hidden && !svcMenu.contains(e.target)) closeMenu(); });
document.addEventListener('keydown', e => { if (e.key === 'Escape' && !svcMenu.hidden) { closeMenu(); svcBtn.focus(); } });

function chooseService(name) {
  if (!workspaces[name]) return;
  Object.entries(workspaces).forEach(([k, w]) => { w.hidden = k !== name; });
  serviceCards.forEach(c => c.setAttribute('aria-pressed', String(c.dataset.service === name)));
  if (name !== 'malware') $('#result').hidden = true;     // a malware report only belongs to that service
  closeMenu();
  workspaces[name].scrollIntoView({behavior: 'smooth', block: 'start'});
  const first = workspaces[name].querySelector('input, button.tabs button, [role=tab]');
  if (first) setTimeout(() => first.focus({preventScroll: true}), 350);
}
document.querySelectorAll('[data-service]').forEach(b => b.addEventListener('click', () => chooseService(b.dataset.service)));


/* ---------- Malware report extras: checks, engines, contents ---------- */
function mk(tag, cls, text) { const e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; return e; }
const stClass = s => 'st-' + String(s).toLowerCase().replace(/[^a-z]/g, '');

function renderExtras(r) {
  const label = $('#detLabel');
  label.hidden = !r.label; label.textContent = r.label ? 'Detection label: ' + r.label + ' (GhostScan heuristic name)' : '';
  const checks = $('#checks'); checks.replaceChildren();
  const eng = $('#engines'); eng.replaceChildren();
  const cont = $('#contents'); cont.replaceChildren();
  if (r.rejected) return;

  const t = mk('table', 'tbl'); const hd = mk('tr');
  ['Check', 'Result', 'Details'].forEach(h => hd.append(mk('th', '', h))); t.append(hd);
  (r.checks || []).forEach(c => {
    const tr = mk('tr'); const pill = mk('span', 'pill ' + stClass(c.status), c.status);
    const td = mk('td'); td.append(pill);
    tr.append(mk('td', '', c.name), td, mk('td', 'muted', c.detail)); t.append(tr);
  });
  checks.append(t);

  const e = r.engines || {};
  const cl = e.clamav || {};
  const crow = mk('p', 'eng-row'); crow.append(mk('b', '', 'ClamAV: '),
    mk('span', 'pill ' + stClass(cl.status === 'detected' ? 'Detected' : cl.status === 'clean' ? 'Clean' : 'Not available'),
       cl.status === 'detected' ? 'Detected' : cl.status === 'clean' ? 'Undetected' : cl.status === 'error' ? 'Error' : 'Not available'));
  eng.append(crow, mk('p', 'hint', cl.detail || ''));
  const vt = e.virustotal || {};
  const vh = mk('p', 'eng-row'); vh.append(mk('b', '', 'VirusTotal: '),
    mk('span', 'pill ' + stClass(vt.status === 'found' ? ((vt.stats || {}).malicious ? 'Detected' : 'Clean') : 'Not available'),
       vt.status === 'found' ? (((vt.stats || {}).malicious || 0) + ' / ' + Object.values(vt.stats || {}).reduce((a, b) => a + b, 0)) : 'Not available'));
  eng.append(vh, mk('p', 'hint', vt.detail || ''));
  if (vt.status === 'found') {
    const flagged = vt.engines.filter(x => x.category === 'malicious' || x.category === 'suspicious');
    const rest = vt.engines.filter(x => !(x.category === 'malicious' || x.category === 'suspicious'));
    const mkTable = list => { const tb = mk('table', 'tbl'); list.forEach(x => { const tr = mk('tr'); const td = mk('td'); td.append(mk('span', 'pill ' + stClass(x.label), x.label));
      tr.append(mk('td', '', x.engine), td, mk('td', 'muted', x.result)); tb.append(tr); }); return tb; };
    if (flagged.length) eng.append(mkTable(flagged));
    if (rest.length) { const d = mk('details'); d.append(mk('summary', '', 'Show ' + rest.length + ' engines with no detection'), mkTable(rest)); eng.append(d); }
  }
  eng.append(mk('p', 'hint', 'Only the file hash is ever sent to VirusTotal, never the file. Engines other than ClamAV are not run by GhostScan itself.'));

  const secs = r.contents || [];
  if (secs.length) {
    cont.append(mk('h3', 'sec-title', 'What is inside the file'));
    secs.forEach(sc => {
      const card = mk('div', 'card'); card.append(mk('h3', '', sc.title));
      if (sc.note) card.append(mk('p', 'hint', sc.note));
      const wrap = mk('div', 'scroll'); const tb = mk('table', 'tbl'); const h = mk('tr');
      sc.columns.forEach(c => h.append(mk('th', '', c))); tb.append(h);
      sc.rows.forEach(rw => { const tr = mk('tr', rw.flag ? 'flag-' + rw.flag : ''); rw.cells.forEach(c => tr.append(mk('td', '', c))); tb.append(tr); });
      wrap.append(tb); card.append(wrap); cont.append(card);
    });
  }
}

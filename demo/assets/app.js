const esc=s=>String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const $=id=>document.getElementById(id);
let cursor=0, older=0, started=false, filter='';
let serverFilter={};  // active quick-view (e.g. {method:'SSH',event:'command'}); sent to the feed
const fq=()=>Object.entries(serverFilter).map(([k,v])=>encodeURIComponent(k)+'='+encodeURIComponent(v)).join('&');
const BASE=(typeof window!=='undefined'&&window.FP_BASE)||'/';  // feed/admin live here (/ public, hidden path in stealth)
const seen=new Set();
const key=r=>[r.ts,r.ip,r.method,r.path,r.severity||''].join('|');
let map=null, markers=null;
function initMap(){
  if(!window.L||map)return;
  map=L.map('map',{worldCopyJump:true}).setView([25,10],2);
  L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',{maxZoom:6,subdomains:'abcd',attribution:'&copy; OpenStreetMap &copy; CARTO'}).addTo(map);
  markers=L.layerGroup().addTo(map);
}
function plot(r){
  if(!markers||r.lat==null||r.lon==null)return;
  const m=L.circleMarker([r.lat,r.lon],{radius:4,color:'#f0b400',weight:1,fillColor:'#f0b400',fillOpacity:.7}).addTo(markers);
  const layers=markers.getLayers();if(layers.length>300)markers.removeLayer(layers[0]);
  setTimeout(()=>{try{m.setStyle({fillOpacity:.2,opacity:.3});}catch(e){}},4000);
}
function applyFilter(){document.querySelectorAll('#rows tr').forEach(tr=>tr.classList.toggle('hide', filter!=='' && !(tr.dataset.ip||'').includes(filter)));}
// Which layer answered this hit, derived from the served template ids / event. Precedence order
// (nuclei-exact > CRS-class > custom attack > LLM) is mirrored here so the label names what served.
function detectSource(r){
  if(r.method==='VNC'||r.proto==='vnc') return 'VNC';
  if(r.method==='SIP'||r.proto==='sip') return 'SIP';
  if(r.event==='llm-fake') return 'LLM';
  if(r.event==='ai-api') return 'AI';
  if(r.event==='decoy-archive') return 'Decoy';
  const ids=r.templates||[];
  if(ids.some(id=>id.indexOf('attack-crs-')===0)) return 'CRS';
  if(ids.some(id=>id.indexOf('attack-')===0)) return 'Custom';
  if(ids.some(id=>id.indexOf('payload-')===0)) return 'Payload';  // classifier caught an attack on an unmatched path
  if(ids.length) return 'Nuclei';
  return '';
}
function rowEl(r){
  const tr=document.createElement('tr');tr.dataset.ip=r.ip||'';
  const badge=r.matched?`<span class="badge scan">SCAN ${esc((r.severity||'').toUpperCase())}</span>`:'<span class="badge miss">404</span>';
  const src=detectSource(r);
  const srcBadge=src?` <span class="badge src src-${src.toLowerCase()}" title="which layer produced the response">${src}</span>`:'';
  const ids=(r.templates&&r.templates.length)?`<div class="ids">${esc(r.templates.join(', '))}</div>`:'';
  const bodyLabel=r.event==='llm-fake'?'response':'payload';
  const payload=r.body?`<div class="payload"><b>${bodyLabel}:</b> ${esc(r.body)}</div>`:'';
  const audio=r.recording?`<div class="call-player"><audio controls preload="none" src="${esc(r.recording)}"></audio></div>`:'';
  const served=r.served?'<span class="served">served</span>':'&mdash;';
  const cc=r.cc?` <span class="ids">${esc(r.cc)}</span>`:'';
  const known=r.known_attacker?' <span class="badge known" title="known attacker (threat-intel blocklist)">known</span>':'';
  const t=(r.ts||'').substr(11,8);
  tr.innerHTML=`<td>${t}</td><td>${esc(r.ip)}${cc}${known}</td><td class="path"><b>${esc(r.method)}</b> ${esc(r.path)}${ids}${payload}${audio}</td><td>${badge}${srcBadge}</td><td>${served}</td>`;
  return tr;
}
const empty=()=>{$('rows').innerHTML='<tr><td colspan=5 class=empty>No hits yet &mdash; point a scanner at this host.</td></tr>';};
function renderWidgets(w){
  if(!w)return;
  $('w_talkers').innerHTML=(w.talkers||[]).map(t=>`<li class="click" data-ip="${esc(t.ip)}"><span>${esc(t.ip)}${t.cc?' <span class=ids>'+esc(t.cc)+'</span>':''}</span><span class="n">${t.n}</span></li>`).join('')||'<li>&mdash;</li>';
  const cmax=Math.max(1,...(w.countries||[]).map(c=>c.n));
  $('w_countries').innerHTML=(w.countries||[]).map(c=>`<div class="bar"><i style="width:${Math.round(c.n/cmax*100)}%"></i><label><span>${esc(c.cc)}</span><span>${c.n}</span></label></div>`).join('')||'&mdash;';
  $('w_templates').innerHTML=(w.templates||[]).map(t=>`<li><span>${esc(t.t)}</span><span class="n">${t.n}</span></li>`).join('')||'<li>&mdash;</li>';
  const hmax=Math.max(1,...(w.histogram||[]).map(h=>h.n));
  $('w_hist').innerHTML=(w.histogram||[]).map(h=>`<div style="height:${Math.round(h.n/hmax*100)}%" title="${esc(h.h)}: ${h.n}"></div>`).join('');
  document.querySelectorAll('#w_talkers li.click').forEach(li=>li.onclick=()=>{filter=li.dataset.ip;$('filter').value=filter;applyFilter();});
}
async function tick(){
  try{
    const d=await (await fetch(BASE+'?feed=1&after='+cursor+(fq()?'&'+fq():''),{cache:'no-store'})).json();
    const tb=$('rows');
    if(d.reset){tb.innerHTML='';seen.clear();older=0;if(markers)markers.clearLayers();}
    d.rows.forEach(r=>{const k=key(r);if(seen.has(k))return;seen.add(k);const el=rowEl(r);if(started)el.classList.add('flash');tb.insertBefore(el,tb.firstChild);plot(r);});
    while(tb.children.length>500)tb.removeChild(tb.lastChild);
    cursor=d.cursor;
    if(d.stats)['total','detections','served','ips','harvested'].forEach(k=>$(k).textContent=d.stats[k]);
    renderWidgets(d.widgets);
    if(!tb.children.length)empty();else applyFilter();
    started=true;$('live').classList.add('on');
  }catch(e){$('live').classList.remove('on');}
}
async function loadOlder(){
  const b=$('older');b.disabled=true;
  try{
    const d=await (await fetch(BASE+'?feed=older&skip='+older+(fq()?'&'+fq():''),{cache:'no-store'})).json();
    const tb=$('rows');
    d.rows.forEach(r=>{const k=key(r);if(seen.has(k))return;seen.add(k);tb.appendChild(rowEl(r));});
    older+=d.rows.length;applyFilter();
    b.style.display=d.more?'':'none';
  }finally{b.disabled=false;}
}
function token(){let t=sessionStorage.getItem('fp_admin');if(!t){t=prompt('Admin password')||'';if(t)sessionStorage.setItem('fp_admin',t);}return t;}
async function adminReq(action,body){
  const t=token();if(!t)return null;
  const r=await fetch(BASE+'?admin='+action,{method:'POST',headers:{'X-Admin-Token':t,'Content-Type':'application/x-www-form-urlencoded'},body:body||''});
  if(r.status===403){sessionStorage.removeItem('fp_admin');alert('Admin disabled server-side, or wrong password.');return null;}
  return r.json();
}
async function admin(action,body){const j=await adminReq(action,body);if(!j)return;alert(JSON.stringify(j));cursor=0;older=0;seen.clear();tick();}
// --- emulation catalog panel: read the catalog + toggle what funnypot serves ---
const KIND_LABEL={attack:'Attack classes',service:'Protocol services',route:'Product decoys',corpus:'Nuclei corpus'};
let vChanges={};
const vstat=()=>{const n=Object.keys(vChanges).length;$('vstat').textContent=n?n+' change(s) pending':'';};
function setVuln(row,on){vChanges[row.dataset.id]=on;row.classList.toggle('off',!on);vstat();}
async function openVulns(){
  const j=await adminReq('vulns');if(!j)return;if(!j.ok){alert('No catalog compiled.');return;}
  vChanges={};
  const groups={};(j.vulns||[]).forEach(v=>{(groups[v.kind]=groups[v.kind]||[]).push(v);});
  let html='';
  ['attack','service','route','corpus'].forEach(kind=>{
    const items=groups[kind];if(!items)return;
    const on=items.filter(v=>v.enabled).length;
    html+=`<div class=vgroup><span>${esc(KIND_LABEL[kind]||kind)} <span class=ids>(${on}/${items.length})</span></span><span class=grow></span><span class=ga data-k="${kind}" data-on=1>all on</span><span class=ga data-k="${kind}" data-on=0>all off</span></div>`;
    items.forEach(v=>{
      const cve=v.cve?` <span class=cve>${esc(v.cve)}</span>`:'';
      const ports=(v.ports&&v.ports.length)?' :'+v.ports.join(','):'';
      html+=`<div class="vrow${v.enabled?'':' off'}" data-id="${esc(v.id)}" data-kind="${kind}"><div class=vt><div class=vn>${esc(v.title||v.id)}${cve}</div><div class=vm>${esc(v.id)} &middot; ${esc(v.severity||'')}${esc(ports)}</div></div><label class=sw><input type=checkbox ${v.enabled?'checked':''}><i></i></label></div>`;
    });
  });
  $('vlist').innerHTML=html||'<p class=empty>No catalog compiled.</p>';
  $('vlist').querySelectorAll('.vrow input').forEach(inp=>inp.onchange=()=>setVuln(inp.closest('.vrow'),inp.checked));
  $('vlist').querySelectorAll('.ga').forEach(a=>a.onclick=()=>{const on=a.dataset.on==='1';$('vlist').querySelectorAll('.vrow[data-kind="'+a.dataset.k+'"]').forEach(r=>{const inp=r.querySelector('input');if(inp.checked!==on){inp.checked=on;setVuln(r,on);}});});
  vstat();$('vmodal').hidden=false;
}
async function saveVulns(){
  if(!Object.keys(vChanges).length){$('vmodal').hidden=true;return;}
  const j=await adminReq('vulns-save','changes='+encodeURIComponent(JSON.stringify(vChanges)));
  if(j&&j.ok){$('vstat').textContent='saved '+(j.saved||0)+' — service changes need a listener restart';vChanges={};setTimeout(()=>{$('vmodal').hidden=true;},1100);}
  else{$('vstat').textContent='save failed';}
}
// --- LLM cache browser: list the generated fakes, read each body, delete bad ones ---
const fmtBytes=n=>n<1024?n+' B':(n<1048576?(n/1024).toFixed(1)+' KB':(n/1048576).toFixed(1)+' MB');
function llmRow(e){
  const st=e.status===401?'miss':'served';            // 401 = auth-looking path, 200 = page
  const when=esc((e.last_served_at||'').replace('T',' ').slice(0,19));
  // Every field escaped; the body is model output rendered as TEXT (inside <pre>), never as HTML.
  return `<div class=vrow data-key="${esc(e.key)}"><div class=vt>`
    +`<div class=vn>${esc(e.key)}</div>`
    +`<div class=vm><span class="badge ${st}">${e.status}</span> &middot; ${fmtBytes(e.bytes)} &middot; served ${e.served_count}&times; &middot; ${when}</div>`
    +`<details class=llmbody><summary>view response</summary><pre>${esc(e.body)}</pre></details>`
    +`</div><button class="btn lldel" data-key="${esc(e.key)}" title="delete this cached response">delete</button></div>`;
}
async function openLlmCache(){
  const j=await adminReq('llm-cache');if(!j)return;
  if(!j.enabled){$('llist').innerHTML='<p class=empty>LLM fakes are disabled (set FUNNYPOT_LLM=1).</p>';$('lstat').textContent='';$('lmodal').hidden=false;return;}
  const es=j.entries||[],s=j.stats||{};
  $('llist').innerHTML=es.length?es.map(llmRow).join(''):'<p class=empty>No cached responses yet.</p>';
  $('lstat').textContent=(s.entries||0)+' entr'+(s.entries===1?'y':'ies')+' · '+fmtBytes(s.bytes||0)+' · '+(s.served||0)+' serves';
  $('llist').querySelectorAll('.lldel').forEach(b=>b.onclick=()=>{if(confirm('Delete this cached response? It will regenerate on the next hit.'))llmDelete(b.dataset.key);});
  $('lmodal').hidden=false;
}
async function llmDelete(key){
  const j=await adminReq('llm-cache-delete','key='+encodeURIComponent(key));
  if(j&&j.ok)openLlmCache();else alert('delete failed');
}
$('older').onclick=loadOlder;
$('prune').onclick=()=>{if(confirm('Prune to the newest 1000 events?'))admin('prune','keep=1000');};
$('clear').onclick=()=>{if(confirm('Delete ALL captured data? This cannot be undone.'))admin('clear');};
$('emul').onclick=openVulns;
$('vclose').onclick=()=>{$('vmodal').hidden=true;};
$('vsave').onclick=saveVulns;
$('vsearch').oninput=e=>{const q=e.target.value.toLowerCase();$('vlist').querySelectorAll('.vrow').forEach(r=>{r.style.display=r.textContent.toLowerCase().includes(q)?'':'none';});};
$('llmcache').onclick=openLlmCache;
$('lclose').onclick=()=>{$('lmodal').hidden=true;};
$('lclear').onclick=async()=>{if(!confirm('Delete ALL cached LLM responses? They will regenerate on the next hit.'))return;const j=await adminReq('llm-cache-clear');if(j)openLlmCache();};
$('lsearch').oninput=e=>{const q=e.target.value.toLowerCase();$('llist').querySelectorAll('.vrow').forEach(r=>{r.style.display=r.textContent.toLowerCase().includes(q)?'':'none';});};
$('filter').oninput=e=>{filter=e.target.value.trim();applyFilter();};
// Quick views: each button carries a filter object in data-f; clicking one reloads the feed
// narrowed server-side (e.g. "SSH commands" = method=SSH + event=command).
function setView(btn){
  try{serverFilter=JSON.parse(btn.dataset.f||'{}');}catch(e){serverFilter={};}
  document.querySelectorAll('.qv').forEach(b=>b.classList.toggle('on',b===btn));
  cursor=0;older=0;seen.clear();$('rows').innerHTML='';if(markers)markers.clearLayers();
  tick();
}
document.querySelectorAll('.qv').forEach(b=>b.onclick=()=>setView(b));
initMap();tick();setInterval(tick,3000);

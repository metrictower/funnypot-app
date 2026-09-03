const esc=s=>String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const $=id=>document.getElementById(id);
let cursor=0, older=0, started=false, filter='', scannersOnly=false;
// Classified reconnaissance tools (scanners / wardialers) — mirrors SipServer::classifyTool. These are
// the high-intel probes: we lure them in and want them to STAND OUT on the dashboard. Softphones and
// PBX relays are deliberately excluded (they are not scanners).
const SCANNERS=new Set(['sipvicious','sipcli','sip-scan','pplsip-scanner','vaxsip-masscaller','sipsak','warvox','iwar-wardialer','sundayddr-wardialer','sipp','metasploit-sip','nmap-sip']);
const isScanner=r=>!!(r&&r.tool&&SCANNERS.has(r.tool));
let serverFilter={};  // active quick-view (e.g. {method:'SSH',event:'command'}); sent to the feed
const fq=()=>Object.entries(serverFilter).map(([k,v])=>encodeURIComponent(k)+'='+encodeURIComponent(v)).join('&');
const BASE=(typeof window!=='undefined'&&window.FP_BASE)||'/';  // feed/admin live here (/ public, hidden path in stealth)
const seen=new Set();
const key=r=>[r.ts,r.ip,r.method,r.path,r.severity||''].join('|');
let map=null, markers=null;
// FP-0250 (2.1): no CDN tile layer (was CARTO dark_all raster tiles — a second external load + Referer
// leak of the hidden dashboard path on every authed page view). The vendored, same-origin world-outline
// GeoJSON (window.FP_WORLD_OUTLINE, inlined into the shell response) draws a tile-free basemap instead;
// L.circleMarker (below) needs no image assets either, so this map makes zero network requests.
function initMap(){
  if(!window.L||map)return;
  map=L.map('map',{worldCopyJump:true,attributionControl:false}).setView([25,10],2);
  if(window.FP_WORLD_OUTLINE){L.geoJSON(window.FP_WORLD_OUTLINE,{style:{color:'#3a3226',weight:1,fillColor:'#241f18',fillOpacity:1}}).addTo(map);}
  markers=L.layerGroup().addTo(map);
}
function plot(r){
  if(!markers||r.lat==null||r.lon==null)return;
  const m=L.circleMarker([r.lat,r.lon],{radius:4,color:'#f0b400',weight:1,fillColor:'#f0b400',fillOpacity:.7}).addTo(markers);
  const layers=markers.getLayers();if(layers.length>300)markers.removeLayer(layers[0]);
  setTimeout(()=>{try{m.setStyle({fillOpacity:.2,opacity:.3});}catch(e){}},4000);
}
function applyFilter(){
  const q=(filter||'').toLowerCase();
  document.querySelectorAll('#rows tr').forEach(tr=>{
    const textFail=q!=='' && !(tr.dataset.ip||'').toLowerCase().includes(q) && !(tr.textContent||'').toLowerCase().includes(q);
    const scanFail=scannersOnly && !SCANNERS.has(tr.dataset.tool||'');
    tr.classList.toggle('hide', textFail||scanFail);
  });
}
// Which layer answered this hit, derived from the served template ids / event. Precedence order
// (nuclei-exact > CRS-class > custom attack > LLM) is mirrored here so the label names what served.
function detectSource(r){
  if(r.method==='VNC'||r.proto==='vnc') return 'VNC';
  if(r.method==='SIP'||r.proto==='sip') return 'SIP';
  if(r.event==='llm-fake') return 'LLM';
  if(r.event==='ai-api') return 'AI';
  if(r.event==='docker') return 'Docker';
  if(r.event==='decoy-archive') return 'Decoy';
  if(r.event==='panel') return 'Panel';
  const ids=r.templates||[];
  if(ids.some(id=>id.indexOf('attack-crs-')===0)) return 'CRS';
  if(ids.some(id=>id.indexOf('attack-')===0)) return 'Custom';
  if(ids.some(id=>id.indexOf('payload-')===0)) return 'Payload';  // classifier caught an attack on an unmatched path
  if(ids.length) return 'Nuclei';
  return '';
}
function rowEl(r){
  const scanner=isScanner(r);
  const tr=document.createElement('tr');tr.dataset.ip=r.ip||'';tr.dataset.tool=(r.tool||'');
  if(scanner)tr.classList.add('scanner-row');
  const badge=r.matched?`<span class="badge scan">SCAN ${esc((r.severity||'').toUpperCase())}</span>`:'<span class="badge miss">404</span>';
  const src=detectSource(r);
  const srcBadge=src?` <span class="badge src src-${src.toLowerCase()}" title="which layer produced the response">${src}</span>`:'';
  const toolName=r.tool||(r.ua?(r.ua.length>22?r.ua.substr(0,21)+'…':r.ua):'');
  const toolTitle=scanner?('Reconnaissance tool (lured + captured): '+r.tool):(r.ua?('User-Agent: '+r.ua):(r.tool?('Tool: '+r.tool):''));
  const toolBadge=toolName?` <span class="badge tool${scanner?' tool-scan':''}" title="${esc(toolTitle)}">${scanner?'&#128269; ':''}${esc(toolName)}</span>`:'';
  const ids=(r.templates&&r.templates.length)?`<div class="ids">${esc(r.templates.join(', '))}</div>`:'';
  const bodyLabel=r.event==='llm-fake'?'response':'payload';
  const payload=r.body?`<div class="payload"><b>${bodyLabel}:</b> ${esc(r.body)}</div>`:'';
  const audio=r.recording?`<div class="call-player"><audio controls preload="none" src="${esc(r.recording)}"></audio></div>`:'';
  const served=r.served?'<span class="served">served</span>':'&mdash;';
  const cc=r.cc?` <span class="ids">${esc(r.cc)}</span>`:'';
  const known=r.known_attacker?' <span class="badge known" title="known attacker (threat-intel blocklist)">known</span>':'';
  const t=(r.ts||'').substr(11,8);
  const blk=r.ip?` <button class="blockbtn" title="Block this IP everywhere, permanently">block</button>`:'';
  tr.innerHTML=`<td>${t}</td><td>${esc(r.ip)}${cc}${known}${blk}</td><td class="path"><b>${esc(r.method)}</b> ${esc(r.path)}${toolBadge}${ids}${payload}${audio}</td><td>${badge}${srcBadge}</td><td>${served}</td>`;
  const tbEl=tr.querySelector('.badge.tool');
  if(tbEl){tbEl.onclick=(e)=>{e.stopPropagation();filter=r.tool||r.ua;$('filter').value=filter;applyFilter();};}
  const blkEl=tr.querySelector('.blockbtn');
  if(blkEl){blkEl.onclick=(e)=>{e.stopPropagation();if(confirm('Block '+(r.ip||'')+' permanently, across every service?'))adminBlock(r.ip);};}
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
// Admin auth (FP-0242b): a server-side session cookie (sent automatically, same-origin) + a
// per-session CSRF token. On a 403 an unauthenticated viewer is bounced to the login knock.
// FP-0250 (2.2): the token arrives as a <meta name=fp-csrf> tag (authed pages only), read ONCE here
// into this closure-scoped const and the node then removed from the DOM — it is no longer a
// `window.*` global reachable by enumerating window, and a later DOM query finds nothing either.
const FP_CSRF=(function(){
  const m=document.querySelector('meta[name=fp-csrf]');
  const v=m?m.getAttribute('content')||'':'';
  if(m)m.remove();
  return v;
})();
function adminBody(body){const c='csrf='+encodeURIComponent(FP_CSRF);return body?(body+'&'+c):c;}
async function adminReq(action,body){
  const r=await fetch(BASE+'?admin='+action,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:adminBody(body),cache:'no-store'});
  if(r.status===403){if(!window.FP_AUTHED){location.href=BASE+'?admin=login';}else{alert('Action denied — session expired or CSRF mismatch. Reloading.');location.reload();}return null;}
  try{return await r.json();}catch(e){return null;}
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
async function adminBlock(ip){
  const j=await adminReq('block-ip','ip='+encodeURIComponent(ip));
  if(j&&j.ok){cursor=0;older=0;seen.clear();tick();}else alert('block failed');
}
async function openBlocked(){
  const j=await adminReq('blocked');if(!j)return;
  const b=j.blocked||[];
  $('blist').innerHTML=b.length?b.map(x=>`<div class="lrow"><code>${esc(x.ip)}</code> <span class=ids>${esc((x.added_at||'').substr(0,10))}${x.note?' &middot; '+esc(x.note):''}</span> <button class="blunbl btn" data-ip="${esc(x.ip)}">unblock</button></div>`).join(''):'<p class=empty>No IPs blocked.</p>';
  $('blist').querySelectorAll('.blunbl').forEach(bt=>bt.onclick=()=>unblockIp(bt.dataset.ip));
  $('bmodal').hidden=false;
}
async function unblockIp(ip){
  const j=await adminReq('unblock-ip','ip='+encodeURIComponent(ip));
  if(j&&j.ok)openBlocked();else alert('unblock failed');
}
// --- runtime config panel (FP-0242b): list registry knobs grouped, edit via ConfigStore::set/reset,
//     view the change audit log. Secret values are shown set/unset only, never rendered. ---
function cfgRow(r){
  const badge=`<span class="badge ${esc(r.source)}">${esc(r.source)}</span>`;
  const live=r.live?'<span class="badge served">live</span>':'<span class="badge miss">restart</span>';
  let input;
  if(r.secret){input=`<span class=ids>${r.is_set?'set':'unset'}</span>`;}
  else if(r.enum){input=`<select data-k="${esc(r.key)}">`+r.enum.map(o=>`<option${o===r.value?' selected':''}>${esc(o)}</option>`).join('')+`</select>`;}
  else if(r.type==='bool'){const on=r.value==='1';input=`<select data-k="${esc(r.key)}"><option value="1"${on?' selected':''}>on</option><option value="0"${on?'':' selected'}>off</option></select>`;}
  else{input=`<input data-k="${esc(r.key)}" value="${esc(r.value==null?'':r.value)}">`;}
  const rst=r.source==='stored'?`<button class="btn creset" data-k="${esc(r.key)}" title="reset to env/default">reset</button>`:'';
  const setBtn=r.secret?'':`<button class="btn cset" data-k="${esc(r.key)}">set</button>`;
  return `<div class="vrow cfg" data-key="${esc(r.key)}"><div class=vt><div class=vn>${esc(r.key)} ${live}</div><div class=vm>${badge} &middot; ${esc(r.type)}${r.env?' &middot; '+esc(r.env):''}</div></div>${input}${setBtn}${rst}</div>`;
}
async function openConfig(){
  const j=await adminReq('config-list');if(!j||!j.ok)return;
  $('cauditbox').hidden=true;$('clist').hidden=false;
  let html='';
  Object.keys(j.groups).forEach(g=>{
    html+=`<div class=vgroup><span>${esc(g)}</span></div>`;
    (j.groups[g]||[]).forEach(r=>{html+=cfgRow(r);});
  });
  $('clist').innerHTML=html||'<p class=empty>No config keys.</p>';
  $('cstat').textContent='';
  $('clist').querySelectorAll('.cset').forEach(b=>b.onclick=()=>cfgSet(b));
  $('clist').querySelectorAll('.creset').forEach(b=>b.onclick=()=>cfgReset(b));
  $('cmodal').hidden=false;
}
function cfgFieldValue(row){const el=row.querySelector('select[data-k],input[data-k]');return el?el.value:'';}
async function cfgSet(b){
  const val=cfgFieldValue(b.closest('.vrow'));
  const j=await adminReq('config-set','key='+encodeURIComponent(b.dataset.k)+'&value='+encodeURIComponent(val));
  if(j&&j.ok){$('cstat').textContent='set '+b.dataset.k;openConfig();}else{$('cstat').textContent=(j&&j.error)||'set failed';}
}
async function cfgReset(b){
  if(!confirm('Reset '+b.dataset.k+' to env/default?'))return;
  const j=await adminReq('config-reset','key='+encodeURIComponent(b.dataset.k));
  if(j&&j.ok){$('cstat').textContent='reset '+b.dataset.k;openConfig();}else{$('cstat').textContent=(j&&j.error)||'reset failed';}
}
async function openConfigAudit(){
  const j=await adminReq('config-audit');if(!j||!j.ok)return;
  const a=j.audit||[];
  $('cauditbox').innerHTML=a.length?a.map(x=>`<div class=lrow><code>${esc(x.key)}</code> <span class=ids>${esc((x.ts||'').replace('T',' ').slice(0,19))} &middot; ${esc(x.actor)}${x.source_ip?' &middot; '+esc(x.source_ip):''}</span> <span class=vm>${x.old_value==null?'&empty;':esc(x.old_value)} &rarr; ${x.new_value==null?'&empty;':esc(x.new_value)}</span></div>`).join(''):'<p class=empty>No config changes recorded.</p>';
  $('clist').hidden=true;$('cauditbox').hidden=false;
}
$('older').onclick=loadOlder;
$('prune').onclick=()=>{if(confirm('Prune to the newest 1000 events?'))admin('prune','keep=1000');};
$('clear').onclick=()=>{if(confirm('Delete ALL captured data? This cannot be undone.'))admin('clear');};
$('emul').onclick=openVulns;
// Config panel + session controls (FP-0242b). Guarded: these ride the same shell but stay inert if a
// build ever omits them.
if($('config'))$('config').onclick=openConfig;
if($('cclose'))$('cclose').onclick=()=>{$('cmodal').hidden=true;};
if($('crefresh'))$('crefresh').onclick=openConfig;
if($('caudit'))$('caudit').onclick=openConfigAudit;
if($('csearch'))$('csearch').oninput=e=>{const q=e.target.value.toLowerCase();$('clist').querySelectorAll('.vrow.cfg').forEach(r=>{r.style.display=r.textContent.toLowerCase().includes(q)?'':'none';});};
if($('alogin'))$('alogin').onclick=()=>{location.href=BASE+'?admin=login';};
if($('alogout'))$('alogout').onclick=async()=>{await adminReq('logout');location.href=BASE;};
$('vclose').onclick=()=>{$('vmodal').hidden=true;};
$('vsave').onclick=saveVulns;
$('vsearch').oninput=e=>{const q=e.target.value.toLowerCase();$('vlist').querySelectorAll('.vrow').forEach(r=>{r.style.display=r.textContent.toLowerCase().includes(q)?'':'none';});};
$('llmcache').onclick=openLlmCache;
$('lclose').onclick=()=>{$('lmodal').hidden=true;};
$('lclear').onclick=async()=>{if(!confirm('Delete ALL cached LLM responses? They will regenerate on the next hit.'))return;const j=await adminReq('llm-cache-clear');if(j)openLlmCache();};
$('blocked').onclick=openBlocked;
$('bclose').onclick=()=>{$('bmodal').hidden=true;};
$('badd').onclick=async()=>{const ip=($('bip').value||'').trim();if(!ip)return;const j=await adminReq('block-ip','ip='+encodeURIComponent(ip));if(j&&j.ok){$('bip').value='';openBlocked();}else alert('block failed');};
$('lsearch').oninput=e=>{const q=e.target.value.toLowerCase();$('llist').querySelectorAll('.vrow').forEach(r=>{r.style.display=r.textContent.toLowerCase().includes(q)?'':'none';});};
$('filter').oninput=e=>{filter=e.target.value.trim();applyFilter();};
// Scanners toggle (client-side): show only classified recon-tool rows among what's loaded. Distinct from
// the server-side quick-views because "is a scanner" is a set membership, not one exact field value.
if($('qscan'))$('qscan').onclick=()=>{scannersOnly=!scannersOnly;$('qscan').classList.toggle('on',scannersOnly);applyFilter();};
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

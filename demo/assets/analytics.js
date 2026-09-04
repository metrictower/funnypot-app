// Operator analytics view (FP-0243b). Rollup-backed breakdowns, events-over-time (vendored uPlot,
// same-origin — no CDN), top-N tables and at-a-glance tiles. The panel is gated OPEN behind the
// operator session, exactly like the emulations / llm-cache modals: it fetches ?admin=analytics
// through adminReq(), so it is served only to a logged-in operator (Argon2id session, FP-0242b) and
// never on the deception surface. Clicking a breakdown bar or a top-N row drills the existing raw-log feed via
// the shared serverFilter path (defined in app.js); brushing the time-series adds a ts range. No
// new log view, no new external fetch. Helper/state names live inside this IIFE; the cross-file
// bindings it reaches (serverFilter, cursor, older, seen, tick, markers, $, esc, adminReq) are the
// script-global ones app.js declares.
(function () {
  if (typeof $ !== 'function' || !$('analytics')) return; // inert unless the dashboard shell is present

  const A = { win: 86400, gran: 'h' };
  let uplot = null;
  // Reused for every protocol line; house amber first, then the same accent hues the badges use.
  const COLORS = ['#f0b400', '#5a96ff', '#3cc8a0', '#e8873a', '#b478ff', '#ff6b5e', '#38bdf8'];

  // Drill the raw feed: set the shared serverFilter, drop the quick-view highlight, close the panel
  // and reload. Mirrors app.js setView() but driven by an analytics click instead of a .qv button.
  function drill(f) {
    serverFilter = f || {};
    document.querySelectorAll('.qv').forEach(b => b.classList.toggle('on', false));
    cursor = 0; older = 0; seen.clear();
    $('rows').innerHTML = '';
    if (typeof markers !== 'undefined' && markers) markers.clearLayers();
    $('amodal').hidden = true;
    if (uplot) { uplot.destroy(); uplot = null; }
    tick();
    const tb = $('rows');
    if (tb) window.scrollTo({ top: tb.getBoundingClientRect().top + window.scrollY - 90, behavior: 'smooth' });
  }

  // A ts-range bound formatted like PHP gmdate('c') ('...+00:00'), so it compares lexicographically
  // against the ISO-8601 `ts` column the store stores (a '.000Z' suffix would sort wrong).
  const isoBound = sec => new Date(Math.round(sec) * 1000).toISOString().replace(/\.\d+Z$/, '+00:00');

  function tiles(a) {
    const items = [
      ['events/sec', (a.rate || 0).toFixed(2)],
      ['events (' + Math.round((a.window_s || 0) / 60) + 'm)', a.events || 0],
      ['unique IPs', a.unique_ips || 0],
      ['new IPs', a.new || 0],
      ['returning IPs', a.returning || 0],
    ];
    $('atiles').innerHTML = items.map(([l, v]) => `<div class=atile><b>${esc(String(v))}</b><span>${esc(l)}</span></div>`).join('');
  }

  // House-style CSS bars (the w_countries pattern), NOT a vendor chart. filterKey!=null makes each
  // bar a drill-down into the raw feed on that field.
  function bars(el, rows, filterKey) {
    rows = rows || [];
    const max = Math.max(1, ...rows.map(r => r.n));
    el.innerHTML = rows.length
      ? rows.map(r => {
        const w = Math.round(r.n / max * 100);
        return `<div class="abar" data-v="${esc(r.val)}"><i style="width:${w}%"></i><label><span>${esc(r.val || '(none)')}</span><span>${r.n}</span></label></div>`;
      }).join('')
      : '<div class=aempty>&mdash;</div>';
    if (filterKey) {
      el.classList.add('adrill');
      el.querySelectorAll('.abar').forEach(b => { const v = b.dataset.v; if (v) b.onclick = () => drill({ [filterKey]: v }); });
    }
  }

  function topTable(el, rows, filterKey) {
    rows = rows || [];
    el.innerHTML = rows.length
      ? rows.map(r => `<div class="arow${filterKey ? ' adrill' : ''}" data-v="${esc(r.val)}"><span class=av>${esc(r.val)}</span><span class=n>${r.n}</span></div>`).join('')
      : '<div class=aempty>&mdash;</div>';
    if (filterKey) el.querySelectorAll('.arow').forEach(row => { const v = row.dataset.v; if (v) row.onclick = () => drill({ [filterKey]: v }); });
  }

  // Flatten {val:[{bucket,n}]} into uPlot's [xs, series0, series1, ...] columns over the union of
  // buckets, ascending, missing points filled with 0.
  function toColumns(series) {
    const names = Object.keys(series || {});
    const xset = new Set();
    names.forEach(n => (series[n] || []).forEach(p => xset.add(p.bucket)));
    const xs = [...xset].sort((a, b) => a - b);
    const idx = {}; xs.forEach((x, i) => { idx[x] = i; });
    const cols = [xs];
    names.forEach(n => {
      const col = new Array(xs.length).fill(0);
      (series[n] || []).forEach(p => { col[idx[p.bucket]] = p.n; });
      cols.push(col);
    });
    return { names, data: cols };
  }

  function drawChart(series) {
    const el = $('achart');
    if (uplot) { uplot.destroy(); uplot = null; }
    const { names, data } = toColumns(series);
    if (typeof uPlot === 'undefined' || !names.length || !data[0].length) {
      el.innerHTML = '<div class=aempty>no series data yet &mdash; the rollup worker needs a few ticks</div>';
      return;
    }
    el.innerHTML = '';
    const axis = { stroke: '#a8987a', grid: { stroke: '#2e2a20', width: 1 }, ticks: { stroke: '#2e2a20' } };
    const opts = {
      width: el.clientWidth || 760,
      height: 260,
      scales: { x: { time: true } },
      axes: [axis, Object.assign({ size: 44 }, axis)],
      series: [{}].concat(names.map((n, i) => ({ label: n, stroke: COLORS[i % COLORS.length], width: 2, points: { show: false } }))),
      legend: { show: true },
      // Brush to select (setScale:false → select without zooming), then apply the range as a ts
      // filter on the raw feed via setSelect.
      cursor: { drag: { x: true, y: false, setScale: false } },
      hooks: {
        setSelect: [u => {
          if (u.select.width <= 2) return;
          const x0 = u.posToVal(u.select.left, 'x');
          const x1 = u.posToVal(u.select.left + u.select.width, 'x');
          drill({ ts_from: isoBound(Math.min(x0, x1)), ts_to: isoBound(Math.max(x0, x1)) });
        }],
      },
    };
    uplot = new uPlot(opts, data, el);
  }

  // Engagement-episode formatting is nullable-aware: a ratio with a zero denominator arrives as null
  // (the store's rule) and must read as a dash — the `||0` idiom in tiles() would print 0 and claim a
  // measurement that was never made. Anything derived rather than measured is labelled "(est.)".
  const nv = v => (v === null || v === undefined) ? '—' : String(v);
  const pct = v => (v === null || v === undefined) ? '—' : Math.round(v * 100) + '%';
  const span = s => (s === null || s === undefined) ? '—' : (s >= 3600 ? (s / 3600).toFixed(1) + 'h' : s >= 60 ? Math.round(s / 60) + 'm' : s + 's');
  const bytes = b => { b = b || 0; return b >= 1048576 ? (b / 1048576).toFixed(1) + ' MiB' : b >= 1024 ? Math.round(b / 1024) + ' KiB' : b + ' B'; };
  const clear = ids => ids.forEach(id => { const el = $(id); if (el) el.innerHTML = ''; });

  function engagement(e, recent) {
    if (!$('aeng')) return;
    e = e || {};
    if (!e.enabled) {
      $('e_status').textContent = e.reason === 'key-unavailable'
        ? 'engagement metrics are enabled but have no install-local key (FUNNYPOT_ANALYTICS_KEY is a placeholder, or the host secret could not be persisted) — nothing is recorded'
        : 'engagement metrics are off (FUNNYPOT_ENGAGEMENT=1 enables them)';
      clear(['e_tiles', 'e_stage', 'e_identity', 'e_lures', 'e_health', 'e_recent']);
      return;
    }
    $('e_status').textContent = '';
    const llm = e.llm || {};
    const est = e.estimated || {};
    const items = [
      ['episodes', nv(e.episodes)],
      ['events', nv(e.events)],
      ['events / episode', nv(e.events_per_episode)],
      ['evidence keys', nv(e.evidence_keys)],
      ['continuation (keys seen again)', pct(e.continuation_ratio)],
      ['avg active span', span(e.avg_active_span_s)],
      ['longest active span', span(e.max_active_span_s)],
      ['polls', nv(e.polls)],
      ['tool turns', nv(e.tool_turns)],
      ['artifact reuse', nv(e.artifact_reuse)],
      ['bytes out', bytes(e.bytes_out)],
      ['server wall', nv(e.server_wall_ms) + ' ms'],
      ['server LLM calls (' + nv(llm.episodes_unknown) + ' ep. unknown)', nv(llm.calls)],
      ['server LLM tokens', nv(llm.tokens)],
      ['context tokens (est.)', nv(est.context_tokens)],
      ['est. tokens / server ms (est.)', nv(est.context_tokens_per_server_ms)],
    ];
    $('e_tiles').innerHTML = items.map(([l, v]) => `<div class=atile><b>${esc(String(v))}</b><span>${esc(l)}</span></div>`).join('');
    bars($('e_stage'), Object.entries(e.deepest_stage || {}).map(([val, n]) => ({ val, n })), null);
    bars($('e_identity'), (e.identity || []).map(m => ({ val: m.basis + ' · ' + m.confidence, n: m.episodes })), null);
    bars($('e_lures'), Object.entries(e.lures || {}).map(([val, n]) => ({ val, n })), null);
    const h = e.health || {};
    topTable($('e_health'), ['event_rows', 'bytes_total', 'shed_episode_cap', 'shed_global_rows', 'shed_global_bytes', 'clock_rollback', 'fault', 'db_bytes']
      .map(k => ({ val: k, n: h[k] === undefined ? 0 : h[k] })), null);
    recent = recent || [];
    $('e_recent').innerHTML = recent.length
      ? recent.map(r => `<div class=arow><span class=av>${esc(r.id_short)} · ${esc(r.basis)} / ${esc(r.confidence)} · ${esc(r.deepest_stage)} · span ${esc(span(r.active_span_s))} · ${esc(String(r.lures))} lure(s)</span>`
        + `<span class=n>${esc(String(r.events))} ev · ${esc(bytes(r.bytes_out))} · ${esc(String(r.server_wall_ms))} ms · LLM ${esc(nv(r.llm_calls))} · ${esc(nv(r.estimated_context_tokens))} tok (est.)</span></div>`).join('')
      : '<div class=aempty>&mdash;</div>';
  }

  function render(j) {
    tiles(j.ataglance || {});
    engagement(j.engagement, j.engagement_recent);
    const b = j.breakdown || {};
    bars($('a_protocol'), b.protocol, 'method');
    bars($('a_status'), b.status, null);
    bars($('a_severity'), b.severity, 'severity');
    bars($('a_event'), b.event, 'event');
    drawChart(j.series || {});
    const t = j.topN || {};
    topTable($('t_ip'), t.ip, 'ip');
    topTable($('t_asn'), t.asn, null);
    topTable($('t_cc'), t.cc, 'cc');
    topTable($('t_tool'), t.tool, 'tool');
    topTable($('t_path'), t.path, 'q'); // path has no exact filter; the free-text `q` covers it
  }

  async function reload() {
    const btn = $('arefresh'); if (btn) btn.disabled = true;
    try {
      const j = await adminReq('analytics&win=' + A.win + '&gran=' + A.gran);
      if (!j) { $('amodal').hidden = true; return; } // no token / 403 — adminReq already handled it
      render(j);
    } catch (e) {
      $('atiles').innerHTML = '<div class=aempty>analytics unavailable</div>';
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  $('analytics').onclick = () => { $('amodal').hidden = false; reload(); };
  $('aclose').onclick = () => { $('amodal').hidden = true; if (uplot) { uplot.destroy(); uplot = null; } };
  $('awin').onchange = e => { A.win = parseInt(e.target.value, 10) || 86400; reload(); };
  $('agran').onchange = e => { A.gran = e.target.value; reload(); };
  $('arefresh').onclick = reload;
})();

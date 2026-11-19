// CCRW Rollcall API — Cloudflare Worker + D1.
// Every /api route except /api/health needs the desk passcode in the `x-passcode` header.

// The Vercel copy of the site calls this API from another origin. Auth is a header, not a cookie, so open CORS is safe.
const CORS = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET, POST, OPTIONS',
  'access-control-allow-headers': 'content-type, x-passcode, x-device',
  'access-control-max-age': '86400',
};
const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store', ...CORS },
  });

async function sha256(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

const clientIp = (req) => req.headers.get('cf-connecting-ip') || 'unknown';

// Lock out an address after 10 wrong passcodes in 15 minutes.
async function checkPasscode(env, req) {
  const ip = clientIp(req);
  const now = Date.now();
  const failKey = 'fail:' + ip;
  const row = await env.DB.prepare('SELECT value FROM settings WHERE key = ?').bind(failKey).first();
  let fails = row ? JSON.parse(row.value) : { n: 0, since: now };
  if (now - fails.since > 15 * 60 * 1000) fails = { n: 0, since: now };
  if (fails.n >= 10) return { ok: false, status: 429 };

  const given = req.headers.get('x-passcode') || '';
  const stored = await env.DB.prepare("SELECT value FROM settings WHERE key = 'passcode_sha256'").first();
  if (stored && given && (await sha256(given.trim())) === stored.value) {
    if (row) await env.DB.prepare('DELETE FROM settings WHERE key = ?').bind(failKey).run();
    return { ok: true };
  }
  fails.n += 1;
  await env.DB.prepare('INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, ?)')
    .bind(failKey, JSON.stringify(fails), now).run();
  return { ok: false, status: 401 };
}

const str = (v, max = 200) => String(v ?? '').slice(0, max);
const ROLES = new Set(['member', 'group_head', 'subgroup_head', 'assistant_head']);

// Turn one client op into a D1 statement.
function statement(env, op, now) {
  const d = op.data || {};
  const id = str(d.id, 64);
  switch (op.t) {
    case 'group': {
      if (op.op === 'del') return env.DB.prepare('UPDATE groups SET deleted = 1, updated_at = ? WHERE id = ?').bind(now, id);
      // leaders only change when the client sends them, so older pages can't wipe them
      const leaders = Array.isArray(d.leaders) ? JSON.stringify(d.leaders.slice(0, 40).map((x) => str(x, 64))) : null;
      return env.DB.prepare(
        `INSERT INTO groups (id, name, parent, leaders, updated_at, deleted) VALUES (?1, ?2, ?3, COALESCE(?4, '[]'), ?5, 0)
         ON CONFLICT(id) DO UPDATE SET name = excluded.name, parent = excluded.parent, leaders = COALESCE(?4, groups.leaders), updated_at = excluded.updated_at, deleted = 0`
      ).bind(id, str(d.name, 120), str(d.parent, 64), leaders, now);
    }
    case 'member': {
      if (op.op === 'del') return env.DB.prepare('UPDATE members SET deleted = 1, updated_at = ? WHERE id = ?').bind(now, id);
      // first-timer fields only change when the client sends them, so older pages can't clear them
      const joined = d.joinedMeeting === undefined ? null : str(d.joinedMeeting, 64);
      const created = Number(d.createdAt) || null;
      return env.DB.prepare(
        `INSERT INTO members (id, name, phone, group_id, subgroup_id, role, joined_meeting, created_at, updated_at, deleted) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0)
         ON CONFLICT(id) DO UPDATE SET name = excluded.name, phone = excluded.phone, group_id = excluded.group_id,
         subgroup_id = excluded.subgroup_id, role = excluded.role, joined_meeting = COALESCE(?7, members.joined_meeting),
         created_at = members.created_at, updated_at = excluded.updated_at, deleted = 0`
      ).bind(id, str(d.name, 160), str(d.phone, 40), str(d.group, 64), str(d.subgroup, 64), ROLES.has(d.role) ? d.role : 'member', joined, created, now);
    }
    case 'meeting':
      if (op.op === 'del') return env.DB.prepare('UPDATE meetings SET deleted = 1, updated_at = ? WHERE id = ?').bind(now, id);
      return env.DB.prepare(
        `INSERT INTO meetings (id, title, date, created_at, ended_at, total_at_end, updated_at, deleted) VALUES (?, ?, ?, ?, ?, ?, ?, 0)
         ON CONFLICT(id) DO UPDATE SET title = excluded.title, date = excluded.date, ended_at = excluded.ended_at,
         total_at_end = excluded.total_at_end, updated_at = excluded.updated_at, deleted = 0`
      ).bind(id, str(d.title, 160), str(d.date, 10), Number(d.createdAt) || now, d.endedAt ? Number(d.endedAt) : null, d.totalAtEnd ? Number(d.totalAtEnd) : null, now);
    case 'checkin': {
      const meeting = str(d.meeting, 64), member = str(d.member, 64);
      if (op.op === 'del') return env.DB.prepare('UPDATE checkins SET deleted = 1, updated_at = ? WHERE meeting_id = ? AND member_id = ?').bind(now, meeting, member);
      // Keep the first arrival time if two desks register the same person.
      return env.DB.prepare(
        `INSERT INTO checkins (meeting_id, member_id, at, updated_at, deleted) VALUES (?, ?, ?, ?, 0)
         ON CONFLICT(meeting_id, member_id) DO UPDATE SET at = CASE WHEN checkins.deleted = 1 THEN excluded.at ELSE checkins.at END,
         updated_at = excluded.updated_at, deleted = 0`
      ).bind(meeting, member, Number(d.at) || now, now);
    }
    case 'notdup': {
      // two people a desk confirmed are different, so they stop showing as possible duplicates
      const pair = str(d.pair, 140);
      if (!/^[\w-]+\|[\w-]+$/.test(pair)) return null;
      return env.DB.prepare('INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, ?)').bind('nd:' + pair, '1', now);
    }
    case 'current':
      return env.DB.prepare("INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES ('current_meeting', ?, ?)").bind(str(d.id, 64), now);
    default:
      return null;
  }
}

/* ---------- change history ---------- */
// Before a batch of ops is written, compare each person or group with what's stored and log the differences.
const ROLE_NAMES = { member: 'Member', group_head: 'Group head', subgroup_head: 'Unit head', assistant_head: 'Assistant unit head' };
async function rowsById(env, table, ids) {
  const out = new Map();
  const list = [...new Set(ids)];
  for (let i = 0; i < list.length; i += 90) {
    const part = list.slice(i, i + 90);
    const r = await env.DB.prepare(`SELECT * FROM ${table} WHERE id IN (${part.map(() => '?').join(',')})`).bind(...part).all();
    for (const row of r.results) out.set(row.id, row);
  }
  return out;
}
async function historyFor(env, ops, now, device) {
  const memberOps = ops.filter((o) => o.t === 'member'), groupOps = ops.filter((o) => o.t === 'group');
  if (!memberOps.length && !groupOps.length) return [];
  const people = await rowsById(env, 'members', memberOps.map((o) => str(o.data?.id, 64)));
  const groupsAll = new Map((await env.DB.prepare('SELECT id, name, parent, leaders, deleted FROM groups').all()).results.map((g) => [g.id, g]));
  const peopleNames = await rowsById(env, 'members', groupOps.flatMap((o) => (Array.isArray(o.data?.leaders) ? o.data.leaders : [])).concat(
    groupOps.flatMap((o) => { try { return JSON.parse(groupsAll.get(str(o.data?.id, 64))?.leaders || '[]'); } catch (e) { return []; } })).map((x) => str(x, 64)));
  const stored = new Map([...groupsAll].map(([k, v]) => [k, { ...v }]));
  for (const o of groupOps) if (o.op !== 'del' && o.data?.id) groupsAll.set(str(o.data.id, 64), { ...(groupsAll.get(str(o.data.id, 64)) || {}), id: str(o.data.id, 64), name: str(o.data.name, 120) });
  const gName = (id) => (id ? groupsAll.get(id)?.name || '' : '');
  const pName = (id) => people.get(id)?.name || peopleNames.get(id)?.name || '';
  const rows = [];
  let at = now;
  const add = (kind, target, label, action, field = '', oldV = '', newV = '') =>
    rows.push([at, kind, target, str(label, 160), action, field, str(oldV, 400), str(newV, 400), device, 'desk']);
  for (const o of ops) {
    const d = o.data || {};
    const id = str(d.id, 64);
    // use the time the change was made on the device (it may have been offline), within the last week
    at = Math.min(now, Math.max(now - 7 * 864e5, Number(o.at) || now));
    if (o.t === 'member') {
      const cur = people.get(id);
      if (o.op === 'del') {
        if (cur && !cur.deleted) {
          if (d.mergedInto) add('person', id, cur.name, 'merged', '', cur.phone ? `${cur.name}, ${cur.phone}` : cur.name, str(d.mergedName, 160) || pName(str(d.mergedInto, 64)));
          else add('person', id, cur.name, 'removed', '', [gName(cur.group_id), gName(cur.subgroup_id)].filter(Boolean).join(', '));
        }
        if (cur) people.set(id, { ...cur, deleted: 1 });
        continue;
      }
      const next = { name: str(d.name, 160), phone: str(d.phone, 40), group_id: str(d.group, 64), subgroup_id: str(d.subgroup, 64), role: ROLES.has(d.role) ? d.role : 'member' };
      if (!cur) add('person', id, next.name, 'added', '', '', [gName(next.group_id), gName(next.subgroup_id)].filter(Boolean).join(', '));
      else {
        if (cur.deleted) add('person', id, next.name, 'restored');
        if (cur.name !== next.name) add('person', id, next.name, 'edited', 'name', cur.name, next.name);
        if (cur.phone !== next.phone) add('person', id, next.name, 'edited', 'phone', cur.phone, next.phone);
        // a move is one line: the unit name (e.g. Group 10A) already names its group
        if (cur.group_id !== next.group_id || cur.subgroup_id !== next.subgroup_id)
          add('person', id, next.name, 'edited', 'group', gName(cur.subgroup_id) || gName(cur.group_id), gName(next.subgroup_id) || gName(next.group_id));
        if (cur.role !== next.role) add('person', id, next.name, 'edited', 'role', ROLE_NAMES[cur.role] || cur.role, ROLE_NAMES[next.role] || next.role);
      }
      people.set(id, { ...(cur || {}), ...next, id, deleted: 0 });
    } else if (o.t === 'group') {
      const cur = stored.get(id);
      if (o.op === 'del') { if (cur && !cur.deleted) add('group', id, cur.name, 'removed'); if (cur) stored.set(id, { ...cur, deleted: 1 }); continue; }
      const name = str(d.name, 120), parent = str(d.parent, 64);
      let leaders = cur ? cur.leaders : '[]';
      if (!cur) add('group', id, name, 'added', '', '', gName(parent) ? 'in ' + gName(parent) : '');
      else {
        if (cur.deleted) add('group', id, name, 'restored');
        if (cur.name !== name) add('group', id, name, 'edited', 'name', cur.name, name);
      }
      if (Array.isArray(d.leaders)) {
        let old = []; try { old = JSON.parse(cur?.leaders || '[]'); } catch (e) {}
        const nl = d.leaders.map((x) => str(x, 64));
        if (cur && old.join() !== nl.join()) add('group', id, name, 'edited', 'leaders', old.map(pName).filter(Boolean).join(', '), nl.map(pName).filter(Boolean).join(', '));
        leaders = JSON.stringify(nl);
      }
      stored.set(id, { id, name, parent, leaders, deleted: 0 });
    }
  }
  return rows.map((r) => env.DB.prepare('INSERT INTO history (at, kind, target, label, action, field, old, new, device, source) VALUES (?,?,?,?,?,?,?,?,?,?)').bind(...r));
}

async function handleApi(req, env, url) {
  if (url.pathname === '/api/health') return json({ ok: true });

  const auth = await checkPasscode(env, req);
  if (!auth.ok) return json({ error: auth.status === 429 ? 'Too many wrong passcodes. Try again in 15 minutes.' : 'Wrong passcode.' }, auth.status);

  if (url.pathname === '/api/login') return json({ ok: true });

  if (url.pathname === '/api/sync' && req.method === 'GET') {
    // A small overlap guards against two writes landing in the same millisecond.
    const since = Math.max(0, (Number(url.searchParams.get('since')) || 0) - 3000);
    const now = Date.now();
    const q = (sql) => env.DB.prepare(sql).bind(since);
    const [groups, members, meetings, checkins, current, notdup] = await env.DB.batch([
      q('SELECT id, name, parent, leaders, deleted FROM groups WHERE updated_at > ?'),
      q('SELECT id, name, phone, group_id AS "group", subgroup_id AS subgroup, role, joined_meeting AS joinedMeeting, created_at AS createdAt, deleted FROM members WHERE updated_at > ?'),
      q('SELECT id, title, date, created_at AS createdAt, ended_at AS endedAt, total_at_end AS totalAtEnd, deleted FROM meetings WHERE updated_at > ?'),
      q('SELECT meeting_id AS meeting, member_id AS member, at, deleted FROM checkins WHERE updated_at > ?'),
      env.DB.prepare("SELECT value FROM settings WHERE key = 'current_meeting'"),
      q("SELECT key FROM settings WHERE key LIKE 'nd:%' AND updated_at > ?"),
    ]);
    return json({
      now,
      groups: groups.results,
      members: members.results,
      meetings: meetings.results,
      checkins: checkins.results,
      current: current.results[0]?.value || null,
      notdup: notdup.results.map((r) => r.key),
    });
  }

  if (url.pathname === '/api/ops' && req.method === 'POST') {
    const body = await req.json().catch(() => null);
    const ops = Array.isArray(body?.ops) ? body.ops.slice(0, 2000) : [];
    const now = Date.now();
    let device = req.headers.get('x-device') || 'Unnamed device';
    try { device = decodeURIComponent(device); } catch (e) {}
    device = str(device, 60);
    const stmts = [...(await historyFor(env, ops, now, device)), ...ops.map((op) => statement(env, op, now)).filter(Boolean)];
    for (let i = 0; i < stmts.length; i += 100) await env.DB.batch(stmts.slice(i, i + 100));
    return json({ ok: true, applied: stmts.length, now });
  }

  if (url.pathname === '/api/history' && req.method === 'GET') {
    const r = await env.DB.prepare('SELECT id, at, kind, target, label, action, field, old, new, device, source FROM history ORDER BY at DESC, id DESC LIMIT 5000').all();
    return json({ rows: r.results });
  }

  if (url.pathname === '/api/passcode' && req.method === 'POST') {
    const body = await req.json().catch(() => null);
    const next = String(body?.passcode || '').trim();
    if (next.length < 8) return json({ error: 'Use at least 8 characters.' }, 400);
    await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES ('passcode_sha256', ?, ?)")
      .bind(await sha256(next), Date.now()).run();
    return json({ ok: true });
  }

  return json({ error: 'Not found' }, 404);
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (url.pathname.startsWith('/api/')) {
      if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
      try {
        return await handleApi(req, env, url);
      } catch (e) {
        return json({ error: 'Server error', detail: String(e && e.message || e) }, 500);
      }
    }
    return env.ASSETS.fetch(req);
  },
};

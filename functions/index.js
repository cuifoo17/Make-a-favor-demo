import { onRequest } from "firebase-functions/v2/https";
import { onDocumentCreated } from "firebase-functions/v2/firestore";
import { defineSecret } from "firebase-functions/params";
import { initializeApp } from "firebase-admin/app";
import { getFirestore } from "firebase-admin/firestore";
import crypto from "node:crypto";

initializeApp();
const db = getFirestore();

const CLIENT_ID = defineSecret("JOBBER_CLIENT_ID");
const CLIENT_SECRET = defineSecret("JOBBER_CLIENT_SECRET");
const REGION = "us-central1";
const PROJECT = "do-favor-demo";
const CALLBACK = `https://${REGION}-${PROJECT}.cloudfunctions.net/jobberCallback`;
const API = "https://api.getjobber.com/api/graphql";
const API_VERSION = "2025-04-16";
const ALLOWED_ORIGINS = ["https://cuifoo17.github.io", "http://localhost:8080", "http://127.0.0.1:8080"];

const b64url = (buf) => buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

// Step 1: owner visits this once; we send them to Jobber's Allow Access screen.
export const jobberConnect = onRequest({ region: REGION, secrets: [CLIENT_ID] }, async (req, res) => {
  const state = b64url(crypto.randomBytes(24));
  const verifier = b64url(crypto.randomBytes(48));
  const challenge = b64url(crypto.createHash("sha256").update(verifier).digest());
  await db.collection("oauth_state").doc(state).set({ verifier, createdAt: Date.now() });
  const url = new URL("https://api.getjobber.com/api/oauth/authorize");
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", CLIENT_ID.value());
  url.searchParams.set("redirect_uri", CALLBACK);
  url.searchParams.set("state", state);
  url.searchParams.set("code_challenge", challenge);
  url.searchParams.set("code_challenge_method", "S256");
  res.redirect(url.toString());
});

// Step 2: Jobber sends the owner back here with a code; we swap it for tokens and store them.
export const jobberCallback = onRequest({ region: REGION, secrets: [CLIENT_ID, CLIENT_SECRET] }, async (req, res) => {
  const { code, state } = req.query;
  if (!code || !state) return res.status(400).send("Missing code or state.");
  const snap = await db.collection("oauth_state").doc(String(state)).get();
  if (!snap.exists) return res.status(400).send("Unknown state. Start again from /jobberConnect.");
  await snap.ref.delete();
  const body = new URLSearchParams({
    client_id: CLIENT_ID.value(), client_secret: CLIENT_SECRET.value(),
    grant_type: "authorization_code", code: String(code), redirect_uri: CALLBACK, code_verifier: snap.data().verifier,
  });
  const r = await fetch("https://api.getjobber.com/api/oauth/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body });
  const tok = await r.json();
  if (!r.ok || !tok.access_token) return res.status(502).send("Token exchange failed: " + JSON.stringify(tok));
  const acct = await gql(tok.access_token, `{ account { id name } }`);
  await db.collection("jobber").doc("connection").set({
    refresh_token: tok.refresh_token, access_token: tok.access_token,
    expires_at: Date.now() + (tok.expires_in || 3600) * 1000,
    account: acct?.data?.account || null, connectedAt: Date.now(),
  });
  res.send(`<h1>Connected to Jobber</h1><p>Account: ${acct?.data?.account?.name || "unknown"}</p><p>You can close this tab.</p>`);
});

async function accessToken() {
  const ref = db.collection("jobber").doc("connection");
  const lockRef = db.collection("jobber").doc("refreshLock");
  for (let attempt = 0; attempt < 8; attempt++) {
    const snap = await ref.get();
    if (!snap.exists) throw new Error("Jobber not connected. Visit /jobberConnect first.");
    const c = snap.data();
    if (c.access_token && c.expires_at - Date.now() > 120000) return c.access_token;
    // Only one process refreshes at a time; refresh tokens rotate, so a second concurrent refresh would fail.
    const got = await db.runTransaction(async (tx) => {
      const l = await tx.get(lockRef);
      if (l.exists && l.data().until > Date.now()) return false;
      tx.set(lockRef, { until: Date.now() + 20000 });
      return true;
    });
    if (!got) { await new Promise((r) => setTimeout(r, 1500)); continue; }
    try {
      const body = new URLSearchParams({ client_id: CLIENT_ID.value(), client_secret: CLIENT_SECRET.value(), grant_type: "refresh_token", refresh_token: c.refresh_token });
      const r = await fetch("https://api.getjobber.com/api/oauth/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body });
      const tok = await r.json();
      if (!r.ok || !tok.access_token) throw new Error("Refresh failed: " + JSON.stringify(tok));
      await ref.set({ access_token: tok.access_token, refresh_token: tok.refresh_token || c.refresh_token, expires_at: Date.now() + (tok.expires_in || 3600) * 1000 }, { merge: true });
      return tok.access_token;
    } finally {
      await lockRef.set({ until: 0 });
    }
  }
  throw new Error("Could not obtain Jobber access token.");
}

async function gql(token, query, variables = {}) {
  const r = await fetch(API, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "X-JOBBER-GRAPHQL-VERSION": API_VERSION, "Content-Type": "application/json" },
    body: JSON.stringify({ query, variables }),
  });
  return r.json();
}

function cors(req, res) {
  const origin = req.headers.origin;
  if (ALLOWED_ORIGINS.includes(origin)) res.set("Access-Control-Allow-Origin", origin);
  res.set("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.set("Access-Control-Allow-Headers", "Content-Type");
}

// Step 3: the website posts the form here; we create a Client and a Request in Jobber.
export const submitRequest = onRequest({ region: REGION, secrets: [CLIENT_ID, CLIENT_SECRET] }, async (req, res) => {
  cors(req, res);
  if (req.method === "OPTIONS") return res.status(204).send("");
  if (req.method !== "POST") return res.status(405).send("POST only");
  try {
    const d = req.body || {};
    const tc = (v) => String(v || "").trim().toLowerCase().replace(/(^|[\s'-])\S/g, (m) => m.toUpperCase());
    const firstName = tc(d.firstName), lastName = d.lastName === "[omitted]" ? "[omitted]" : tc(d.lastName);
    const email = String(d.email || "").trim(), phone = String(d.phone || "").trim();
    if (!firstName || !lastName || (!email && !phone)) return res.status(400).json({ error: "Name and an email or phone are required." });
    const token = await accessToken();

    const cRes = await gql(token, `mutation($input: ClientCreateInput!) {
      clientCreate(input: $input) { client { id } userErrors { message path } }
    }`, { input: {
      firstName, lastName,
      emails: email ? [{ description: "MAIN", primary: true, address: email }] : [],
      phones: phone ? [{ description: "MOBILE", primary: true, number: phone, smsAllowed: true }] : [],
      sourceAttribution: { sourceText: "Do Favor website" },
    }});
    const client = cRes?.data?.clientCreate?.client;
    if (!client) return res.status(502).json({ error: "clientCreate failed", detail: cRes });

    const car = [d.year, d.make, d.model].filter(Boolean).join(" ");
    const title = `Website request${car ? ": " + car : ""}`;
    const lines = [
      car ? `Vehicle: ${car}` : null,
      d.vin ? `VIN: ${d.vin}` : null,
      Array.isArray(d.issues) && d.issues.length ? `Issues:\n- ${d.issues.join("\n- ")}` : null,
      d.details ? `Customer's description:\n${d.details}` : null,
      d.intent ? `Wants to: ${d.intent}` : null,
    ].filter(Boolean);

    const rRes = await gql(token, `mutation($input: RequestCreateInput!) {
      requestCreate(input: $input) { request { id title jobberWebUri } userErrors { message path } }
    }`, { input: { clientId: client.id, title, lineItems: [], formIds: [] } });
    const request = rRes?.data?.requestCreate?.request;
    if (!request) return res.status(502).json({ error: "requestCreate failed", detail: rRes, clientId: client.id });

    if (lines.length) {
      await gql(token, `mutation($requestId: EncodedId!, $input: RequestCreateNoteInput!) {
        requestCreateNote(requestId: $requestId, input: $input) { requestNote { id } userErrors { message path } }
      }`, { requestId: request.id, input: { message: lines.join("\n"), pinned: true } });
    }

    res.json({ ok: true, clientId: client.id, requestId: request.id, url: request.jobberWebUri || null });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});

// ---------- Phone-first flow ----------
const normPhone = (v) => { let d = String(v || "").replace(/\D/g, ""); if (d.length === 11 && d.startsWith("1")) d = d.slice(1); return d; };

function intakeLines(d) {
  const car = [d.year, d.make, d.model].filter(Boolean).join(" ");
  const issues = (Array.isArray(d.issues) ? d.issues : []).map((x) => { const t = String(x); const i = t.indexOf(" - "); return i > 0 ? `[${t.slice(0, i)}]: ${t.slice(i + 3)}` : t; });
  return { car, lines: [
    car ? `VEHICLE: ${car}` : null,
    d.vin ? `VIN: ${d.vin}` : null,
    issues.length ? `ISSUES:\n${issues.join("\n")}` : null,
    d.details ? `CUSTOMER DESCRIPTION: ${d.details}` : null,
    d.intent ? `CHOSE ON WEBSITE: ${d.intent}` : null,
  ].filter(Boolean) };
}

// Website posts here BEFORE handing the customer to Jobber's booking form. We only need a phone to match later.
export const saveIntake = onRequest({ region: REGION }, async (req, res) => {
  cors(req, res);
  if (req.method === "OPTIONS") return res.status(204).send("");
  if (req.method !== "POST") return res.status(405).send("POST only");
  const d = req.body || {};
  const phone = normPhone(d.phone);
  if (phone.length < 9 || phone.length > 10) return res.status(400).json({ error: "Phone must be 9 or 10 digits." });
  const doc = await db.collection("intakes").add({
    phone, createdAt: Date.now(), attached: {},
    sessionId: String(d.sessionId || "").slice(0, 64), visitorId: String(d.visitorId || "").slice(0, 64), variantId: String(d.variantId || "control").slice(0, 64),
    data: { year: d.year || "", make: d.make || "", model: d.model || "", vin: d.vin || "", issues: Array.isArray(d.issues) ? d.issues.slice(0, 50) : [], details: String(d.details || "").slice(0, 4000), intent: d.intent || "" },
  });
  res.json({ ok: true, id: doc.id });
});

// Jobber posts here. Verify, log, answer within 1s; the Firestore trigger below does the real work.
export const jobberWebhook = onRequest({ region: REGION, secrets: [CLIENT_SECRET] }, async (req, res) => {
  try {
    const raw = req.rawBody ? req.rawBody.toString("utf8") : JSON.stringify(req.body || {});
    const sig = req.get("X-Jobber-Hmac-SHA256") || "";
    const digest = crypto.createHmac("sha256", CLIENT_SECRET.value()).update(raw).digest("base64");
    const verified = sig.length === digest.length && crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(sig));
    const ev = req.body?.data?.webHookEvent || {};
    await db.collection("webhook_events").add({ receivedAt: Date.now(), verified, topic: ev.topic || null, itemId: ev.itemId || null, accountId: ev.accountId || null, occurredAt: ev.occurredAt || null, processed: false });
  } catch (e) { /* always ack */ }
  res.status(200).send("ok");
});

async function findIntake(phones) {
  const keys = [...new Set(phones.map(normPhone).filter((p) => p.length >= 9))];
  if (!keys.length) return null;
  const since = Date.now() - 48 * 3600 * 1000;
  const snap = await db.collection("intakes").where("phone", "in", keys.slice(0, 10)).get();
  const docs = snap.docs.filter((x) => x.data().createdAt >= since).sort((a, b) => b.data().createdAt - a.data().createdAt);
  return docs[0] || null;
}


function instructionsText(d) {
  const { lines } = intakeLines({ ...d, intent: "" });
  return lines.join("\n\n");
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export const processWebhookEvent = onDocumentCreated({ document: "webhook_events/{id}", region: REGION, secrets: [CLIENT_ID, CLIENT_SECRET], timeoutSeconds: 120 }, async (event) => {
  const ref = event.data.ref; const ev = event.data.data();
  const log = async (extra) => ref.set({ processed: true, processedAt: Date.now(), ...extra }, { merge: true });
  if (!ev.verified) return log({ result: "unverified, ignored" });
  if (!["CLIENT_CREATE", "REQUEST_CREATE", "JOB_CREATE"].includes(ev.topic) || !ev.itemId) return log({ result: "topic ignored" });
  try {
    const token = await accessToken();
    let phones = [], client = null, item = null;
    if (ev.topic === "CLIENT_CREATE") {
      const r = await gql(token, `query($id: EncodedId!) { client(id: $id) { id phones { number } customFields { ... on CustomFieldText { id label } } } }`, { id: ev.itemId });
      client = r?.data?.client; item = client;
    } else if (ev.topic === "REQUEST_CREATE") {
      const r = await gql(token, `query($id: EncodedId!) { request(id: $id) { id title assessment { id } client { id firstName lastName phones { number } } } }`, { id: ev.itemId });
      item = r?.data?.request; client = item?.client;
    } else {
      const r = await gql(token, `query($id: EncodedId!) { job(id: $id) { id title client { id phones { number } } } }`, { id: ev.itemId });
      item = r?.data?.job; client = item?.client;
    }
    if (!item || !client) return log({ result: "item not found" });
    phones = (client.phones || []).map((p) => p.number);
    const intake = await findIntake(phones);
    if (!intake) return log({ result: "no matching intake", phones });
    const key = ev.topic.split("_")[0].toLowerCase(); // client | request | job
    if (intake.data().attached?.[key] === ev.itemId) return log({ result: "already attached" });
    const { car, lines } = intakeLines(intake.data().data);
    const message = lines.join("\n\n");
    let out; const d = intake.data().data; const instr = instructionsText(d);
    if (ev.topic === "CLIENT_CREATE") {
      try {
        const byLabel = {};
        for (const f of client.customFields || []) if (f?.id && f.label) byLabel[f.label.trim().toLowerCase()] = f.id;
        const customFields = [];
        if (car && byLabel.vehicle) customFields.push({ id: byLabel.vehicle, valueText: car });
        if (d.vin && byLabel.vin) customFields.push({ id: byLabel.vin, valueText: d.vin });
        if (customFields.length) {
          const r = await gql(token, `mutation($id: EncodedId!, $input: ClientEditInput!) { clientEdit(clientId: $id, input: $input) { client { id } userErrors { message } } }`, { id: ev.itemId, input: { customFields } });
          await ref.set({ customFieldResult: JSON.stringify(r).slice(0, 300) }, { merge: true });
        } else await ref.set({ customFieldResult: "no Vehicle/VIN fields on client" }, { merge: true });
      } catch (e) { await ref.set({ customFieldError: String(e.message || e) }, { merge: true }); }
      out = await gql(token, `mutation($id: EncodedId!, $input: ClientCreateNoteInput!) { clientCreateNote(clientId: $id, input: $input) { clientNote { id } userErrors { message } } }`, { id: ev.itemId, input: { message, pinned: true } });
    } else if (ev.topic === "REQUEST_CREATE") {
      const kind = /call/i.test(d.intent || "") ? "Call" : "Appointment";
      const who = [client.firstName, client.lastName].filter((x) => x && x !== "[omitted]").join(" ") || (item.title || "").replace(/^Request for /i, "");
      const title = `${car ? car + " - " : ""}${kind} Request by ${who}`.trim();
      await gql(token, `mutation($id: EncodedId!, $input: RequestEditInput!) { requestEdit(requestId: $id, input: $input) { request { id } userErrors { message } } }`, { id: ev.itemId, input: { title } });
      // The assessment (the booked visit) can land a few seconds after the request. Poll for it.
      let assessmentId = item.assessment?.id;
      for (let n = 0; !assessmentId && n < 8; n++) {
        await sleep(5000);
        const r = await gql(token, `query($id: EncodedId!) { request(id: $id) { assessment { id } } }`, { id: ev.itemId });
        assessmentId = r?.data?.request?.assessment?.id;
      }
      if (assessmentId && instr) await gql(token, `mutation($id: EncodedId!, $input: AssessmentEditInput!) { assessmentEdit(assessmentId: $id, input: $input) { assessment { id } userErrors { message } } }`, { id: assessmentId, input: { instructions: instr } });
      out = { assessmentId: assessmentId || null }; // note lives on the client; Jobber links it here automatically
    } else {
      const title = car && !(item.title || "").includes(car) ? `${car} \u2014 ${item.title || "Job"}` : item.title;
      await gql(token, `mutation($id: EncodedId!, $input: JobEditInput!) { jobEdit(jobId: $id, input: $input) { job { id } userErrors { message } } }`, { id: ev.itemId, input: { title, instructions: instr } });
      out = { instructions: true }; // note lives on the client; Jobber links it here automatically
    }
    await intake.ref.set({ attached: { ...(intake.data().attached || {}), [key]: ev.itemId } }, { merge: true });
    return log({ result: "attached", intakeId: intake.id, detail: JSON.stringify(out).slice(0, 500) });
  } catch (e) {
    const tries = (ev.tries || 0) + 1;
    if (tries < 4) {
      await new Promise((r) => setTimeout(r, 4000 * tries));
      const { processed, processedAt, result, error, ...rest } = ev;
      await db.collection("webhook_events").add({ ...rest, tries, receivedAt: Date.now(), processed: false, retryOf: ref.id });
      return log({ result: "error, requeued", error: String(e.message || e) });
    }
    return log({ result: "error", error: String(e.message || e) });
  }
});

// ---------- Tracking ("our pixel") ----------
const clampInt = (v, max) => { const n = Math.round(Number(v)); return Number.isFinite(n) ? Math.max(0, Math.min(max, n)) : 0; };
const bool = (v) => v === true;

// The page posts a full snapshot of the visit each time something meaningful happens. We merge it into one doc per visit.
export const track = onRequest({ region: REGION }, async (req, res) => {
  cors(req, res);
  if (req.method === "OPTIONS") return res.status(204).send("");
  if (req.method !== "POST") return res.status(405).send("POST only");
  try {
    let d = req.body;
    if (typeof d === "string") d = JSON.parse(d);
    if (Buffer.isBuffer(d)) d = JSON.parse(d.toString("utf8"));
    const sid = String(d.sessionId || "").slice(0, 64), vid = String(d.visitorId || "").slice(0, 64);
    if (!/^[A-Za-z0-9_-]{8,64}$/.test(sid) || !/^[A-Za-z0-9_-]{8,64}$/.test(vid)) return res.status(400).send("bad ids");
    const ts = d.textSize || {}, p1 = d.page1 || {}, p2 = d.page2 || {}, p3 = d.page3 || {}, p4 = d.page4 || {}, p5 = d.page5 || {};
    const doc = {
      sessionId: sid, visitorId: vid,
      formId: String(d.formId || "do-favor-intake").slice(0, 64), variantId: String(d.variantId || "control").slice(0, 64),
      startedAt: clampInt(d.startedAt, 4e12), updatedAt: Date.now(),
      furthestPage: clampInt(d.furthestPage, 20),
      userAgent: String(req.get("user-agent") || "").slice(0, 300),
      textSize: { popupShown: bool(ts.popupShown), sliderTouched: bool(ts.sliderTouched), chosenIndex: ts.chosenIndex == null ? null : clampInt(ts.chosenIndex, 4), chosenScale: Number(ts.chosenScale) || null, reopenedCount: clampInt(ts.reopenedCount, 99), ms: clampInt(ts.ms, 36e5) },
      page1: { ms: clampInt(p1.ms, 36e5) },
      page2: { ms: clampInt(p2.ms, 36e5), vinEntered: bool(p2.vinEntered), vinValid: p2.vinValid == null ? null : bool(p2.vinValid), yearFilled: bool(p2.yearFilled), makeFilled: bool(p2.makeFilled), modelFilled: bool(p2.modelFilled), allThreeFilled: bool(p2.allThreeFilled) },
      page3: { ms: clampInt(p3.ms, 36e5), groupsExpanded: clampInt(p3.groupsExpanded, 50), optionsSelected: clampInt(p3.optionsSelected, 100), descriptionChars: clampInt(p3.descriptionChars, 100000) },
      page4: { ms: clampInt(p4.ms, 36e5), validPhone: bool(p4.validPhone), continueClicked: bool(p4.continueClicked) },
      page5: { ms: clampInt(p5.ms, 36e5), choice: ["call", "appointment", "oil change"].includes(p5.choice) ? p5.choice : null },
    };
    await db.collection("sessions").doc(sid).set(doc, { merge: true });
    res.status(204).send("");
  } catch (e) {
    res.status(400).send("bad payload");
  }
});

// ---------- Private viewer: My forms -> variants with averages -> logs ----------
const VIEW_CSS = `
  :root{--green:#56b044;--green-d:#2f6b24;--blue:#1f6feb;--ink:#0b0b0b;--muted:#6b6b6b;--line:#e2e2e2;--bg:#f6f6f4}
  *{box-sizing:border-box}
  body{font:14px/1.5 "IBM Plex Mono",ui-monospace,SFMono-Regular,Menlo,monospace;margin:0;color:var(--ink);background:var(--bg)}
  header.top{background:#000;position:sticky;top:0;z-index:10;display:flex;align-items:center;justify-content:space-between;gap:16px;padding:12px 20px}
  header.top a.logo{display:flex;align-items:center}
  header.top img{height:40px;width:auto;display:block}
  header.top .tag{color:#9a9a9a;font-size:12px;letter-spacing:.08em;text-transform:uppercase}
  .page{max-width:1100px;margin:0 auto;padding:24px 16px 72px}
  h1{font-size:24px;font-weight:600;margin:8px 0 4px;letter-spacing:-.01em}
  .crumbs{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}.crumbs a{color:var(--muted);text-decoration:none;border-bottom:1px solid #c8c8c8}
  .sub{color:var(--muted);margin:0 0 20px;font-size:13px}
  a{color:inherit}
  .card{display:flex;align-items:center;justify-content:space-between;gap:12px;background:#fff;border:1px solid var(--line);border-radius:10px;padding:18px 20px;text-decoration:none;margin-bottom:12px;transition:border-color .15s,transform .15s}
  .card:hover{border-color:#000;transform:translateY(-1px)}.card .n{font-size:17px;font-weight:600}.card .m{color:var(--muted);font-size:13px}.card .go{font-size:20px;color:#000}
  .wrap{overflow:auto;background:#fff;border:1px solid var(--line);border-radius:10px}
  table{border-collapse:collapse;width:100%}th,td{padding:10px 14px;text-align:left;border-bottom:1px solid var(--line);vertical-align:middle}
  tbody:last-child tr:last-child td{border-bottom:0}
  thead th{background:#fff;border-bottom:2px solid #000}
  thead tr.vh th{background:#fff;color:#000}
  th.vtitle{font-size:13px;font-weight:600;letter-spacing:.12em}
  th.v{min-width:200px}.vt{display:flex;align-items:baseline;gap:8px;flex-wrap:wrap}.vt b{font-size:15px;font-weight:600}
  .btn{display:inline-block;background:var(--blue);color:#fff;text-decoration:none;font-weight:500;font-size:12px;padding:6px 12px;border-radius:6px;letter-spacing:.02em}
  .btn:hover{filter:brightness(1.1)}
  a.lnk{color:var(--blue);text-decoration:underline;text-underline-offset:3px;font-weight:500;font-size:13px}
  tr.sec td{background:#000;color:#fff;font-weight:500;font-size:12px;text-transform:uppercase;letter-spacing:.1em;padding:12px 14px;border-bottom:1px solid #2a2a2a}
  tr.sec{cursor:pointer;user-select:none}
  tr.sec.static{cursor:default}
  tr.sec .sl{display:inline-flex;align-items:center;gap:10px}
  tr.sec .chev{width:18px;height:18px;transition:transform .2s}
  tbody.grp.open tr.sec .chev{transform:rotate(180deg)}
  tbody.grp:not(.open) tr:not(.sec){display:none}
  td.k{color:#333}td.val{font-weight:600;font-variant-numeric:tabular-nums}
  tbody tr:not(.sec):hover td{background:#fafaf7}
  .note{color:var(--muted);font-size:12px;margin-top:14px}
  table.logs{white-space:nowrap;font-size:13px}
  table.logs thead th{position:sticky;top:0;background:#fff}
  table.logs thead tr:first-child th{background:#000;color:#fff;text-align:center;font-weight:500;font-size:11px;text-transform:uppercase;letter-spacing:.1em;border-bottom:0;border-right:1px solid #333}
  table.logs td{font-variant-numeric:tabular-nums}
`;
const SIZES = ["smallest", "small", "middle", "large", "largest"];
const esc = (v) => String(v ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const LOGO = "https://cuifoo17.github.io/Make-a-favor-demo/assets/logo-dark.png";
let HOME_LINK = "?";
const shell = (title, body) => `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>${VIEW_CSS}</style></head><body><header class="top"><a class="logo" href="${HOME_LINK}"><img src="${LOGO}" alt="Do Favor"></a><span class="tag">Form analytics</span></header><div class="page">${body}</div></body></html>`;

async function formsRegistry() {
  // Seed the one form we have so the registry is never empty.
  const ref = db.collection("forms").doc("do-favor-intake");
  const snap = await ref.get();
  if (!snap.exists) { await ref.set({ name: "Intake Form V1", createdAt: Date.now() }); await ref.collection("variants").doc("control").set({ name: "Original", createdAt: Date.now() }); }
  const forms = await db.collection("forms").get();
  return Promise.all(forms.docs.map(async (f) => ({ id: f.id, name: f.data().name || f.id, variants: (await f.ref.collection("variants").get()).docs.map((v) => ({ id: v.id, name: v.data().name || v.id })) })));
}

function aggregate(rows) {
  const avg = (xs) => (xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : null);
  const pct = (xs) => (xs.length ? (100 * xs.filter(Boolean).length) / xs.length : null);
  const reached = (n) => rows.filter((r) => (r.furthestPage || 0) >= n);
  const n = rows.length, r2 = reached(1), r3 = reached(2), r4 = reached(3), r5 = reached(4);
  const popup = rows.filter((r) => r.textSize?.popupShown);
  const chosen = rows.map((r) => r.textSize?.chosenIndex).filter((x) => x != null);
  const counts = SIZES.map((_, i) => chosen.filter((x) => x === i).length);
  const top = counts.indexOf(Math.max(...counts));
  const vinRows = r2.filter((r) => r.page2?.vinEntered);
  const picked = rows.map((r) => r.page5?.choice).filter(Boolean);
  return {
    wentToJobber: pct(rows.map((r) => !!r.page5?.choice)),
    gaveContact: pct(rows.map((r) => r.page4?.validPhone === true)),
    visits: n,
    reach: [n ? 100 : null, pct(rows.map((r) => (r.furthestPage || 0) >= 1)), pct(rows.map((r) => (r.furthestPage || 0) >= 2)), pct(rows.map((r) => (r.furthestPage || 0) >= 3)), pct(rows.map((r) => (r.furthestPage || 0) >= 4))],
    sliderTouched: pct(popup.map((r) => r.textSize.sliderTouched)),
    sizeTop: chosen.length ? `${SIZES[top]} (${Math.round((100 * counts[top]) / chosen.length)}%)` : null,
    reopened: pct(rows.map((r) => (r.textSize?.reopenedCount || 0) > 0)),
    t1: avg(rows.map((r) => r.page1?.ms || 0)),
    t2: avg(r2.map((r) => r.page2?.ms || 0)), vinEntered: pct(r2.map((r) => r.page2?.vinEntered)), vinValid: pct(vinRows.map((r) => r.page2?.vinValid === true)), allThree: pct(r2.map((r) => r.page2?.allThreeFilled)),
    t3: avg(r3.map((r) => r.page3?.ms || 0)), groups: avg(r3.map((r) => r.page3?.groupsExpanded || 0)), options: avg(r3.map((r) => r.page3?.optionsSelected || 0)), chars: avg(r3.map((r) => r.page3?.descriptionChars || 0)), wrote: pct(r3.map((r) => (r.page3?.descriptionChars || 0) > 0)),
    t4: avg(r4.map((r) => r.page4?.ms || 0)), validPhone: pct(r4.map((r) => r.page4?.validPhone)), clickedContinue: pct(r4.map((r) => r.page4?.continueClicked)),
    t5: avg(r5.map((r) => r.page5?.ms || 0)), pickedAny: pct(r5.map((r) => !!r.page5?.choice)), call: pct(picked.map((c) => c === "call")), appt: pct(picked.map((c) => c === "appointment")),
  };
}

export const sessionsView = onRequest({ region: REGION }, async (req, res) => {
  const cfg = (await db.collection("config").doc("dashboard").get()).data() || {};
  if (!cfg.key || req.query.key !== cfg.key) return res.status(403).send("Forbidden");
  res.set("Cache-Control", "no-store");
  const K = encodeURIComponent(cfg.key);
  const link = (q) => `?key=${K}${Object.entries(q).map(([k, v]) => `&${k}=${encodeURIComponent(v)}`).join("")}`;
  HOME_LINK = link({});
  const forms = await formsRegistry();
  const formId = req.query.form ? String(req.query.form) : null;
  const variantId = req.query.variant ? String(req.query.variant) : null;

  // ----- Page 1: My forms
  if (!formId) {
    const cards = await Promise.all(forms.map(async (f) => {
      const c = await db.collection("sessions").where("formId", "==", f.id).count().get();
      return `<a class="card" href="${link({ form: f.id })}"><span><span class="n">${esc(f.name)}</span><br><span class="m">${f.variants.length} variant${f.variants.length === 1 ? "" : "s"} · ${c.data().count} visits</span></span><span class="m">›</span></a>`;
    }));
    return res.send(shell("My forms", `<h1>My forms</h1><p class="sub">Pick a form to see how its variants are doing.</p>${cards.join("")}<h1 style="margin-top:36px">My websites</h1>`));
  }

  const form = forms.find((f) => f.id === formId);
  if (!form) return res.status(404).send(shell("Not found", `<p>No such form.</p><p><a href="${link({})}">My forms</a></p>`));
  const snap = await db.collection("sessions").where("formId", "==", formId).get();
  const all = snap.docs.map((x) => x.data());
  // Any variant seen in the data but missing from the registry still gets a column.
  const variants = [...form.variants];
  for (const v of new Set(all.map((r) => r.variantId || "control"))) if (!variants.some((x) => x.id === v)) variants.push({ id: v, name: v });

  // ----- Page 3: logs for one variant
  if (variantId) {
    const v = variants.find((x) => x.id === variantId) || { id: variantId, name: variantId };
    const rowsData = all.filter((r) => (r.variantId || "control") === variantId).sort((a, b) => b.startedAt - a.startedAt).slice(0, 300);
    const sec = (ms) => (ms ? (ms / 1000).toFixed(1) + "s" : "0s");
    const yn = (x) => (x === true ? "yes" : x === false ? "no" : "—");
    const rows = rowsData.map((d) => { const t = d.textSize || {}, a = d.page1 || {}, b = d.page2 || {}, c = d.page3 || {}, e4 = d.page4 || {}, e5 = d.page5 || {};
      const when = new Date(d.startedAt).toLocaleString("en-US", { timeZone: "America/New_York", month: "short", day: "numeric", hour: "numeric", minute: "2-digit", second: "2-digit" });
      const device = /iPhone/.test(d.userAgent) ? "iPhone" : /Android/.test(d.userAgent) ? "Android" : /Macintosh/.test(d.userAgent) ? "Mac" : /Windows/.test(d.userAgent) ? "Windows" : "other";
      return `<tr><td>${esc(when)}</td><td>${device}</td><td>${(d.furthestPage || 0) + 1}</td>
        <td>${yn(t.sliderTouched)}</td><td>${t.chosenIndex == null ? "—" : SIZES[t.chosenIndex]}</td><td>${t.reopenedCount || 0}</td>
        <td>${sec(a.ms)}</td>
        <td>${sec(b.ms)}</td><td>${yn(b.vinEntered)}</td><td>${b.vinEntered ? yn(b.vinValid) : "—"}</td><td>${yn(b.allThreeFilled)}</td>
        <td>${sec(c.ms)}</td><td>${c.groupsExpanded || 0}</td><td>${c.optionsSelected || 0}</td><td>${c.descriptionChars || 0}</td>
        <td>${sec(e4.ms)}</td><td>${yn(e4.validPhone)}</td><td>${yn(e4.continueClicked)}</td>
        <td>${sec(e5.ms)}</td><td>${e5.choice || "—"}</td></tr>`; }).join("");
    return res.send(shell(`${v.name} logs`, `<div class="crumbs"><a href="${link({})}">My forms</a> › <a href="${link({ form: formId })}">${esc(form.name)}</a> › ${esc(v.name)}</div>
      <h1>${esc(v.name)}: logs</h1><p class="sub">${rowsData.length} visits, newest first. Times are seconds the page was on screen. Eastern time.</p>
      <div class="wrap"><table class="logs"><thead><tr><th colspan="3">Visit</th><th colspan="3">Text size</th><th>Page 1</th><th colspan="4">Page 2: car</th><th colspan="4">Page 3: issues</th><th colspan="3">Page 4: phone</th><th colspan="2">Page 5: choice</th></tr>
      <tr><th>Started</th><th>Device</th><th>Furthest page</th><th>Moved slider</th><th>Size chosen</th><th>Reopened</th><th>Time</th><th>Time</th><th>VIN entered</th><th>VIN valid</th><th>Year+make+model</th><th>Time</th><th>Groups opened</th><th>Options picked</th><th>Description chars</th><th>Time</th><th>Valid phone</th><th>Clicked continue</th><th>Time</th><th>Picked</th></tr></thead>
      <tbody>${rows}</tbody></table></div>`));
  }

  // ----- Page 2: variants side by side with averages
  const aggs = variants.map((v) => ({ v, a: aggregate(all.filter((r) => (r.variantId || "control") === v.id)) }));
  const s1 = (ms) => (ms == null ? "—" : (ms / 1000).toFixed(1) + "s");
  const p0 = (x) => (x == null ? "—" : Math.round(x) + "%");
  const n1 = (x) => (x == null ? "—" : x.toFixed(1));
  const R = (label, f) => `<tr><td class="k">${label}</td>${aggs.map(({ a }) => `<td class="val">${f(a)}</td>`).join("")}</tr>`;
  const CHEV = `<svg class="chev" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M6 9l6 6 6-6"/></svg>`;
  const S = (label) => `</tbody><tbody class="grp"><tr class="sec" role="button" tabindex="0" aria-expanded="false"><td colspan="${aggs.length + 1}"><span class="sl">${label}${CHEV}</span></td></tr>`;
  const head = `<tr class="vh"><th class="vtitle">VARIANTS</th>${aggs.map(({ v }) => `<th class="v"><div class="vt"><b>${esc(v.name)}</b><a class="lnk" href="${link({ form: formId, variant: v.id })}">(logs)</a></div></th>`).join("")}</tr>`;
  const body = [
    `<tr class="sec static"><td colspan="${aggs.length + 1}"><span class="sl">Overview</span></td></tr>`,
    R("Total Visits", (a) => a.visits), R("Went to Jobber", (a) => p0(a.wentToJobber)), R("Gave contact details", (a) => p0(a.gaveContact)),
    S("Visits"), R("Total visits", (a) => a.visits),
    R("Reached page 2, car", (a) => p0(a.reach[1])), R("Reached page 3, issues", (a) => p0(a.reach[2])), R("Reached page 4, phone", (a) => p0(a.reach[3])), R("Reached page 5, choice", (a) => p0(a.reach[4])),
    S("Text size"), R("Moved the slider", (a) => p0(a.sliderTouched)), R("Most common size", (a) => a.sizeTop || "—"), R("Reopened it later", (a) => p0(a.reopened)),
    S("Page 1: video"), R("Avg time", (a) => s1(a.t1)),
    S("Page 2: car"), R("Avg time", (a) => s1(a.t2)), R("Entered a VIN", (a) => p0(a.vinEntered)), R("VIN was valid, of those entered", (a) => p0(a.vinValid)), R("Filled year, make, and model", (a) => p0(a.allThree)),
    S("Page 3: issues"), R("Avg time", (a) => s1(a.t3)), R("Avg groups opened", (a) => n1(a.groups)), R("Avg options picked", (a) => n1(a.options)), R("Wrote a description", (a) => p0(a.wrote)), R("Avg description length, characters", (a) => (a.chars == null ? "—" : Math.round(a.chars))),
    S("Page 4: phone"), R("Avg time", (a) => s1(a.t4)), R("Entered a valid phone", (a) => p0(a.validPhone)), R("Tapped Continue", (a) => p0(a.clickedContinue)),
    S("Page 5: choice"), R("Avg time", (a) => s1(a.t5)), R("Picked an option", (a) => p0(a.pickedAny)), R("Chose call, of those who picked", (a) => p0(a.call)), R("Chose appointment, of those who picked", (a) => p0(a.appt)),
  ].join("");
  res.send(shell(form.name, `<div class="crumbs"><a href="${link({})}">My forms</a> › ${esc(form.name)}</div>
    <h1>${esc(form.name)}</h1><p class="sub">${variants.length} variant${variants.length === 1 ? "" : "s"} · ${all.length} visits</p>
    <div class="wrap"><table><thead>${head}</thead><tbody>${body}</tbody></table></div>
    <p class="note">Tap a section to open it. Each page's numbers only count visitors who got to that page. Yes-or-no items show the share that was yes.</p>
    <script>document.querySelectorAll('tbody.grp > tr.sec').forEach(function(r){function t(){var g=r.parentNode,o=!g.classList.contains('open');g.classList.toggle('open',o);r.setAttribute('aria-expanded',o);}r.addEventListener('click',t);r.addEventListener('keydown',function(e){if(e.key==='Enter'||e.key===' '){e.preventDefault();t();}});});</script>`));
});

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

// Minimal private viewer: a table of recent visits. Protected by a key in the link until the real dashboard has a login.
export const sessionsView = onRequest({ region: REGION }, async (req, res) => {
  const cfg = (await db.collection("config").doc("dashboard").get()).data() || {};
  if (!cfg.key || req.query.key !== cfg.key) return res.status(403).send("Forbidden");
  const snap = await db.collection("sessions").orderBy("startedAt", "desc").limit(100).get();
  const sec = (ms) => (ms ? (ms / 1000).toFixed(1) + "s" : "0s");
  const yn = (v) => (v === true ? "yes" : v === false ? "no" : "\u2014");
  const sizes = ["smallest", "small", "middle", "large", "largest"];
  const esc = (v) => String(v).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
  const rows = snap.docs.map((x) => { const d = x.data(); const t = d.textSize || {}, a = d.page1 || {}, b = d.page2 || {}, c = d.page3 || {}, e4 = d.page4 || {}, e5 = d.page5 || {};
    const when = new Date(d.startedAt).toLocaleString("en-US", { timeZone: "America/New_York", month: "short", day: "numeric", hour: "numeric", minute: "2-digit", second: "2-digit" });
    const device = /iPhone/.test(d.userAgent) ? "iPhone" : /Android/.test(d.userAgent) ? "Android" : /Macintosh/.test(d.userAgent) ? "Mac" : /Windows/.test(d.userAgent) ? "Windows" : "other";
    return `<tr><td>${esc(when)}</td><td>${device}</td><td>${esc(d.variantId)}</td><td>${d.furthestPage + 1}</td>
      <td>${yn(t.sliderTouched)}</td><td>${t.chosenIndex == null ? "\u2014" : sizes[t.chosenIndex]}</td><td>${t.reopenedCount || 0}</td>
      <td>${sec(a.ms)}</td>
      <td>${sec(b.ms)}</td><td>${yn(b.vinEntered)}</td><td>${b.vinEntered ? yn(b.vinValid) : "\u2014"}</td><td>${yn(b.allThreeFilled)}</td>
      <td>${sec(c.ms)}</td><td>${c.groupsExpanded || 0}</td><td>${c.optionsSelected || 0}</td><td>${c.descriptionChars || 0}</td>
      <td>${sec(e4.ms)}</td><td>${yn(e4.validPhone)}</td><td>${yn(e4.continueClicked)}</td>
      <td>${sec(e5.ms)}</td><td>${e5.choice || "\u2014"}</td></tr>`; }).join("");
  res.set("Cache-Control", "no-store").send(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Do Favor visits</title>
  <style>body{font:14px -apple-system,system-ui,sans-serif;margin:16px;color:#111}h1{font-size:20px}table{border-collapse:collapse;white-space:nowrap}th,td{border:1px solid #ddd;padding:6px 8px;text-align:left}th{background:#f4f4f4;position:sticky;top:0}thead tr:first-child th{background:#4a9b3a;color:#fff;text-align:center}.wrap{overflow:auto}</style>
  <h1>Do Favor intake: recent visits (${snap.size})</h1><p>Newest first. Times are seconds the page was on screen. Eastern time.</p><div class="wrap"><table>
  <thead><tr><th colspan="4">Visit</th><th colspan="3">Text size</th><th>Page 1</th><th colspan="4">Page 2: car</th><th colspan="4">Page 3: issues</th><th colspan="3">Page 4: phone</th><th colspan="2">Page 5: choice</th></tr>
  <tr><th>Started</th><th>Device</th><th>Variant</th><th>Furthest page</th><th>Moved slider</th><th>Size chosen</th><th>Reopened</th><th>Time</th><th>Time</th><th>VIN entered</th><th>VIN valid</th><th>Year+make+model</th><th>Time</th><th>Groups opened</th><th>Options picked</th><th>Description chars</th><th>Time</th><th>Valid phone</th><th>Clicked continue</th><th>Time</th><th>Picked</th></tr></thead>
  <tbody>${rows}</tbody></table></div>`);
});

import { onRequest } from "firebase-functions/v2/https";
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
  const snap = await ref.get();
  if (!snap.exists) throw new Error("Jobber not connected. Visit /jobberConnect first.");
  const c = snap.data();
  if (c.access_token && c.expires_at - Date.now() > 120000) return c.access_token;
  const body = new URLSearchParams({ client_id: CLIENT_ID.value(), client_secret: CLIENT_SECRET.value(), grant_type: "refresh_token", refresh_token: c.refresh_token });
  const r = await fetch("https://api.getjobber.com/api/oauth/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body });
  const tok = await r.json();
  if (!r.ok || !tok.access_token) throw new Error("Refresh failed: " + JSON.stringify(tok));
  await ref.set({ access_token: tok.access_token, refresh_token: tok.refresh_token || c.refresh_token, expires_at: Date.now() + (tok.expires_in || 3600) * 1000 }, { merge: true });
  return tok.access_token;
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
    const firstName = String(d.firstName || "").trim(), lastName = String(d.lastName || "").trim();
    const email = String(d.email || "").trim(), phone = String(d.phone || "").trim();
    if (!firstName || !lastName || (!email && !phone)) return res.status(400).json({ error: "Name and an email or phone are required." });
    const token = await accessToken();

    const cRes = await gql(token, `mutation($input: ClientCreateInput!) {
      clientCreate(input: $input) { client { id } userErrors { message path } }
    }`, { input: {
      firstName, lastName,
      emails: email ? [{ description: "MAIN", primary: true, address: email }] : [],
      phones: phone ? [{ description: "MAIN", primary: true, number: phone }] : [],
    }});
    const client = cRes?.data?.clientCreate?.client;
    if (!client) return res.status(502).json({ error: "clientCreate failed", detail: cRes });

    const car = [d.year, d.make, d.model].filter(Boolean).join(" ");
    const title = `Website request${car ? ": " + car : ""}`;
    const lines = [
      car ? `Vehicle: ${car}` : null,
      d.vin ? `VIN: ${d.vin}` : null,
      Array.isArray(d.issues) && d.issues.length ? `Issues: ${d.issues.join("; ")}` : null,
      d.details ? `Details: ${d.details}` : null,
      d.intent ? `Wants: ${d.intent}` : null,
    ].filter(Boolean);

    const rRes = await gql(token, `mutation($input: RequestCreateInput!) {
      requestCreate(input: $input) { request { id title } userErrors { message path } }
    }`, { input: { clientId: client.id, title, details: lines.join("\n") } });
    const request = rRes?.data?.requestCreate?.request;
    if (!request) return res.status(502).json({ error: "requestCreate failed", detail: rRes, clientId: client.id });

    res.json({ ok: true, clientId: client.id, requestId: request.id });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});

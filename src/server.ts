/**
 * Purchase Invoice Webhook Demo Harness
 *
 * Usage:
 *   bun run src/server.ts
 *
 * This starts a local webhook receiver + dashboard on port 9876,
 * exposes it via a Cloudflare quick tunnel, and provides a UI to:
 *   1. Configure a webhook (paste the JSON response from the API)
 *   2. Enter a Bearer token for authentication
 *   3. Trigger a test purchase invoice via XML Composition
 *   4. View captured webhooks with full HMAC verification
 */

import { Elysia } from "elysia";
import { cors } from "@elysiajs/cors";
import {
  parseWebhookConfigInput,
  summarizeConfiguredEvents,
  verifyCapturedWebhook,
  type DemoWebhookConfig,
  type DemoWebhookAlgorithm,
} from "./lib/webhook-utils";

// ─── Configuration ───────────────────────────────────────────────────────────

const DEMO_PORT = Number(process.env.PORT || 9876);
const IS_VERCEL = Boolean(process.env.VERCEL);
const DISABLE_TUNNEL = process.env.DISABLE_TUNNEL === "true" || IS_VERCEL;
// API Gateway URL — the XML Composition endpoint
const ENCORE_URL = process.env.ENCORE_URL || "https://dev.gets.complyance.io";

// ─── In-memory store ─────────────────────────────────────────────────────────

interface CapturedWebhook {
  id: string;
  receivedAt: string;
  body: unknown;
  rawBody: string;
  headers: Record<string, string>;
  httpStatus: number;
  hmacVerified: boolean | null;
  hmacComputed: string;
  hmacReceived: string;
  hmacError: string | null;
  hmacAlgorithm: DemoWebhookAlgorithm | null;
}

const state = {
  config: null as DemoWebhookConfig | null,
  bearerToken: "",
  webhooks: [] as CapturedWebhook[],
  publicUrl: "",
  triggerResult: null as null | { success: boolean; message: string; data?: unknown },
  tunnelProc: null as { kill: () => void } | null,
  vercelDeploymentUrl: "",
};

// ─── SBD XML Sample (UAE Purchase Invoice) ───────────────────────────────────

const SAMPLE_SBD_XML = `<?xml version="1.0" encoding="UTF-8"?>
<StandardBusinessDocument xmlns="http://www.unece.org/cefact/namespaces/StandardBusinessDocumentHeader">
  <StandardBusinessDocumentHeader>
    <HeaderVersion>1.0</HeaderVersion>
    <Sender>
      <Identifier Authority="iso6523-actorid-upis">0192:912345678</Identifier>
    </Sender>
    <Receiver>
      <Identifier Authority="iso6523-actorid-upis">0192:876543210</Identifier>
    </Receiver>
    <DocumentIdentification>
      <Standard>urn:oasis:names:specification:ubl:schema:xsd:Invoice-2</Standard>
      <TypeVersion>2.1</TypeVersion>
      <InstanceIdentifier>SBD-DEMO-2026-0042</InstanceIdentifier>
      <Type>urn:oasis:names:specification:ubl:schema:xsd:Invoice-2::Invoice##urn:cen.eu:en16931:2017#compliant#urn:fdc:peppol.eu:2017:poacc:billing:3.0::2.1</Type>
      <CreationDateAndTime>2026-05-13T10:30:00Z</CreationDateAndTime>
    </DocumentIdentification>
    <BusinessScope>
      <Scope>
        <Type>PROCESSID</Type>
        <InstanceIdentifier>urn:fdc:peppol.eu:2017:poacc:billing:01:1.0</InstanceIdentifier>
      </Scope>
      <Scope>
        <Type>COUNTRY_C1</Type>
        <InstanceIdentifier>AE</InstanceIdentifier>
      </Scope>
    </BusinessScope>
  </StandardBusinessDocumentHeader>
  <Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2" xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2" xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2">
    <cbc:CustomizationID>urn:cen.eu:en16931:2017#compliant#urn:fdc:peppol.eu:2017:poacc:billing:3.0</cbc:CustomizationID>
    <cbc:ProfileID>urn:fdc:peppol.eu:2017:poacc:billing:01:1.0</cbc:ProfileID>
    <cbc:ID>PI-2026-0042</cbc:ID>
    <cbc:IssueDate>2026-05-13</cbc:IssueDate>
    <cbc:InvoiceTypeCode>380</cbc:InvoiceTypeCode>
    <cbc:DocumentCurrencyCode>AED</cbc:DocumentCurrencyCode>
    <cbc:TaxCurrencyCode>AED</cbc:TaxCurrencyCode>
    <cac:AccountingSupplierParty>
      <cac:Party>
        <cbc:EndpointID schemeID="EM">demo@supplier.ae</cbc:EndpointID>
        <cac:PartyIdentification>
          <cbc:ID schemeID="TRN">123456789012345</cbc:ID>
        </cac:PartyIdentification>
        <cac:PartyName>
          <cbc:Name>Demo Supplier FZE</cbc:Name>
        </cac:PartyName>
        <cac:PostalAddress>
          <cbc:StreetName>Business Bay</cbc:StreetName>
          <cbc:CityName>Dubai</cbc:CityName>
          <cbc:PostalZone>00000</cbc:PostalZone>
          <cac:Country>
            <cbc:IdentificationCode>AE</cbc:IdentificationCode>
          </cac:Country>
        </cac:PostalAddress>
        <cac:PartyTaxScheme>
          <cbc:CompanyID>123456789012345</cbc:CompanyID>
          <cac:TaxScheme>
            <cbc:ID>VAT</cbc:ID>
          </cac:TaxScheme>
        </cac:PartyTaxScheme>
      </cac:Party>
    </cac:AccountingSupplierParty>
    <cac:AccountingCustomerParty>
      <cac:Party>
        <cbc:EndpointID schemeID="EM">buyer@company.ae</cbc:EndpointID>
        <cac:PartyIdentification>
          <cbc:ID schemeID="TRN">987654321098765</cbc:ID>
        </cac:PartyIdentification>
        <cac:PartyName>
          <cbc:Name>Buyer Company LLC</cbc:Name>
        </cac:PartyName>
        <cac:PostalAddress>
          <cbc:StreetName>Sheikh Zayed Road</cbc:StreetName>
          <cbc:CityName>Dubai</cbc:CityName>
          <cbc:PostalZone>00000</cbc:PostalZone>
          <cac:Country>
            <cbc:IdentificationCode>AE</cbc:IdentificationCode>
          </cac:Country>
        </cac:PostalAddress>
        <cac:PartyTaxScheme>
          <cbc:CompanyID>987654321098765</cbc:CompanyID>
          <cac:TaxScheme>
            <cbc:ID>VAT</cbc:ID>
          </cac:TaxScheme>
        </cac:PartyTaxScheme>
      </cac:Party>
    </cac:AccountingCustomerParty>
    <cac:LegalMonetaryTotal>
      <cbc:LineExtensionAmount currencyID="AED">1000.00</cbc:LineExtensionAmount>
      <cbc:TaxExclusiveAmount currencyID="AED">1000.00</cbc:TaxExclusiveAmount>
      <cbc:TaxInclusiveAmount currencyID="AED">1050.00</cbc:TaxInclusiveAmount>
      <cbc:PayableAmount currencyID="AED">1050.00</cbc:PayableAmount>
    </cac:LegalMonetaryTotal>
    <cac:InvoiceLine>
      <cbc:ID>1</cbc:ID>
      <cbc:InvoicedQuantity unitCode="C62">1</cbc:InvoicedQuantity>
      <cbc:LineExtensionAmount currencyID="AED">1000.00</cbc:LineExtensionAmount>
      <cac:Item>
        <cbc:Name>Professional Services - Consulting</cbc:Name>
        <cac:ClassifiedTaxCategory>
          <cbc:ID>S</cbc:ID>
          <cbc:Percent>5</cbc:Percent>
          <cac:TaxScheme>
            <cbc:ID>VAT</cbc:ID>
          </cac:TaxScheme>
        </cac:ClassifiedTaxCategory>
      </cac:Item>
      <cac:Price>
        <cbc:PriceAmount currencyID="AED">1000.00</cbc:PriceAmount>
      </cac:Price>
    </cac:InvoiceLine>
  </Invoice>
</StandardBusinessDocument>`;

function buildSampleSbdXml(): string {
  const uniqueId = Date.now().toString(36).toUpperCase();
  const instanceId = `SBD-DEMO-${uniqueId}`;
  const invoiceId = `PI-${uniqueId}`;

  return SAMPLE_SBD_XML
    .split("SBD-DEMO-2026-0042").join(instanceId)
    .split("PI-2026-0042").join(invoiceId);
}

// ─── Dashboard HTML ──────────────────────────────────────────────────────────

function generateDashboard(publicUrl: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Purchase Invoice Webhook Demo</title>
  <style>
    :root {
      --bg: #0b0d12;
      --surface: #12161f;
      --surface-muted: #171c27;
      --surface-soft: #1b2230;
      --border: #272f3e;
      --text: #e5e9f0;
      --text-muted: #8f9aad;
      --heading: #f7f9fc;
      --primary: #5b7dbd;
      --primary-hover: #6a89c7;
      --success: #4aa36b;
      --danger: #cf5b69;
      --warning: #c08a4a;
      --font-main: Inter, sans-serif;
      --font-mono: "SF Mono", "JetBrains Mono", "Fira Code", monospace;
    }

    * { margin: 0; padding: 0; box-sizing: border-box; }

    body {
      font-family: var(--font-main);
      background: var(--bg);
      color: var(--text);
      min-height: 100vh;
      line-height: 1.5;
    }

    .container {
      max-width: 1280px;
      margin: 0 auto;
      padding: 40px 24px 80px;
    }

    .app-shell {
      display: grid;
      grid-template-columns: 240px minmax(0, 1fr);
      gap: 24px;
      align-items: start;
    }

    .sidebar {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 20px 16px;
      position: sticky;
      top: 20px;
    }

    .brand {
      font-size: 12px;
      color: var(--text-muted);
      margin-bottom: 10px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }

    .nav-title {
      font-size: 13px;
      color: var(--text-muted);
      margin: 0 0 10px;
    }

    .nav-list {
      list-style: none;
      display: grid;
      gap: 6px;
      margin-bottom: 16px;
    }

    .nav-item a {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 8px 10px;
      border-radius: 8px;
      color: #cfd6e3;
      text-decoration: none;
      font-size: 13px;
      border: 1px solid transparent;
    }

    .nav-item a:hover {
      background: var(--surface-muted);
      border-color: var(--border);
    }

    .nav-num {
      width: 18px;
      height: 18px;
      border-radius: 999px;
      border: 1px solid #3a4458;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      font-size: 11px;
      color: var(--text-muted);
      flex-shrink: 0;
    }

    .sidebar-note {
      font-size: 12px;
      color: var(--text-muted);
      border-top: 1px solid var(--border);
      padding-top: 12px;
    }

    .main {
      display: grid;
      gap: 24px;
    }

    .hero {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 24px;
    }

    h1 {
      font-size: 28px;
      color: var(--heading);
      margin-bottom: 4px;
      line-height: 1.2;
    }

    .subtitle {
      font-size: 14px;
      color: var(--text-muted);
    }

    .workflow { display: grid; gap: 24px; }

    .section {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 24px;
    }

    .section-title {
      font-size: 16px;
      color: var(--heading);
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 10px;
      margin-bottom: 12px;
    }

    .section-title .num {
      width: 22px;
      height: 22px;
      border-radius: 999px;
      background: var(--surface-soft);
      color: #b7c3d8;
      border: 1px solid #354054;
      font-size: 12px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      font-weight: 600;
    }

    .section-subtext {
      font-size: 14px;
      color: var(--text-muted);
      margin-bottom: 12px;
    }

    .form-label {
      display: block;
      font-size: 12px;
      color: var(--text-muted);
      margin-bottom: 6px;
    }

    .section-divider {
      border-top: 1px solid var(--border);
      margin: 18px 0;
    }

    .field-grid { display: grid; gap: 12px; }
    .password-wrap { position: relative; }

    .url-box {
      display: flex;
      align-items: center;
      gap: 12px;
      border: 1px solid var(--border);
      border-radius: 10px;
      background: var(--surface-muted);
      padding: 12px 14px;
    }

    .url-text {
      font-size: 13px;
      font-family: var(--font-mono);
      color: #a9bad8;
      word-break: break-all;
      flex: 1;
    }

    .btn {
      border: none;
      border-radius: 10px;
      height: 40px;
      padding: 0 16px;
      font-size: 14px;
      font-weight: 500;
      cursor: pointer;
      transition: background-color 0.15s ease;
      font-family: var(--font-main);
    }

    .btn-primary {
      background: var(--primary);
      color: #f8fbff;
    }

    .btn-primary:hover { background: var(--primary-hover); }

    .btn-primary:disabled {
      background: #303a4c;
      color: #8b97ab;
      cursor: not-allowed;
    }

    .btn-secondary {
      background: var(--surface-soft);
      border: 1px solid #364155;
      color: #d5dde9;
    }

    .btn-secondary:hover { background: #212a3a; }

    .icon-btn {
      position: absolute;
      right: 8px;
      top: 8px;
      border: 1px solid #364155;
      background: var(--surface-soft);
      color: var(--text-muted);
      border-radius: 8px;
      font-size: 12px;
      font-weight: 500;
      padding: 4px 8px;
      cursor: pointer;
    }

    textarea, input[type="text"], input[type="password"], input[type="email"] {
      width: 100%;
      border: 1px solid #364155;
      background: var(--surface-muted);
      border-radius: 10px;
      padding: 12px 14px;
      font-size: 14px;
      color: var(--text);
      font-family: var(--font-mono);
    }

    textarea { min-height: 110px; resize: vertical; }

    textarea:focus, input:focus {
      outline: none;
      border-color: var(--primary);
      box-shadow: 0 0 0 3px rgba(91, 125, 189, 0.2);
    }

    .mt-2 { margin-top: 8px; }
    .mt-3 { margin-top: 12px; }
    .mb-2 { margin-bottom: 8px; }
    .text-sm { font-size: 14px; }
    .text-xs { font-size: 12px; }
    .text-muted { color: var(--text-muted); }
    .text-red { color: var(--danger); }
    .text-yellow { color: var(--warning); }

    .config-summary {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 12px;
      margin-top: 12px;
    }

    .config-item {
      background: var(--surface-muted);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 12px;
    }

    .config-item label {
      font-size: 12px;
      color: var(--text-muted);
      display: block;
      margin-bottom: 4px;
    }

    .config-item .value {
      font-size: 13px;
      font-family: var(--font-mono);
      color: var(--text);
      word-break: break-all;
    }

    .config-item .value.secret { color: var(--warning); }
    .trigger-btn { width: 100%; margin-top: 12px; }

    .trigger-result {
      margin-top: 12px;
      border-radius: 10px;
      padding: 12px 14px;
      font-size: 14px;
      border: 1px solid transparent;
    }

    .trigger-result.success {
      background: #172319;
      color: #8ec8a0;
      border-color: #2b4732;
    }

    .trigger-result.error {
      background: #2a1b20;
      color: #e0a4ae;
      border-color: #4f2c36;
    }

    .feed-section { margin-top: 24px; }

    .flex-between {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
    }

    .polling-indicator {
      font-size: 12px;
      color: var(--text-muted);
      border: 1px solid var(--border);
      border-radius: 999px;
      padding: 4px 10px;
      background: var(--surface-muted);
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }

    .polling-indicator .dot {
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: var(--success);
      display: inline-block;
    }

    .empty-state {
      border: 1px dashed var(--border);
      border-radius: 10px;
      background: var(--surface-muted);
      padding: 30px 16px;
      text-align: center;
      color: var(--text-muted);
    }

    .webhook-card {
      border: 1px solid var(--border);
      border-radius: 10px;
      background: var(--surface-muted);
      padding: 16px;
      margin-bottom: 12px;
    }

    .webhook-card .header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 10px;
    }

    .webhook-card .time {
      font-size: 12px;
      color: var(--text-muted);
    }

    .badge {
      font-size: 12px;
      font-weight: 500;
      border-radius: 999px;
      padding: 4px 10px;
      border: 1px solid transparent;
    }

    .badge-stored { color: #9ecbb0; background: #172319; border-color: #2b4732; }
    .badge-failed { color: #dfa7b1; background: #2a1b20; border-color: #4f2c36; }
    .badge-verified { color: #9ecbb0; background: #172319; border-color: #2b4732; }
    .badge-unverified { color: #d6be9a; background: #2a2419; border-color: #4b3f2c; }

    .headers-table {
      width: 100%;
      border-collapse: collapse;
      margin: 12px 0;
      font-size: 12px;
    }

    .headers-table th {
      text-align: left;
      color: var(--text-muted);
      font-weight: 500;
      border-bottom: 1px solid var(--border);
      padding: 7px 8px;
      background: var(--surface-soft);
    }

    .headers-table td {
      border-bottom: 1px solid var(--border);
      padding: 7px 8px;
      font-family: var(--font-mono);
      font-size: 12px;
      color: #c8d0dd;
    }

    .json-block {
      background: #0f131c;
      border: 1px solid #2a3344;
      border-radius: 10px;
      padding: 16px;
      font-size: 12px;
      line-height: 1.6;
      color: #aeb8ca;
      font-family: var(--font-mono);
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-all;
      max-height: 320px;
      overflow-y: auto;
    }

    .hmac-detail {
      font-size: 12px;
      color: var(--text-muted);
      font-family: var(--font-mono);
      margin-top: 4px;
      word-break: break-all;
    }

    @media (max-width: 980px) {
      .app-shell { grid-template-columns: 1fr; }
      .sidebar { position: static; }
      .nav-list { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    }

    @media (max-width: 760px) {
      .container { padding: 24px 12px 48px; }
      .section { padding: 18px; }
      .hero { padding: 18px; }
      .url-box { flex-direction: column; align-items: stretch; }
      .btn-secondary { width: 100%; }
      .webhook-card .header { flex-direction: column; align-items: flex-start; }
      .flex-between { flex-direction: column; align-items: flex-start; }
      .nav-list { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="app-shell">
      <aside class="sidebar">
        <div class="brand">Complyance</div>
        <p class="nav-title">Workflow</p>
        <ul class="nav-list">
          <li class="nav-item"><a href="#step-config"><span class="nav-num">1</span><span>Configure</span></a></li>
          <li class="nav-item"><a href="#step-auth"><span class="nav-num">2</span><span>Authenticate</span></a></li>
          <li class="nav-item"><a href="#step-trigger"><span class="nav-num">3</span><span>Trigger</span></a></li>
          <li class="nav-item"><a href="#step-feed"><span class="nav-num">4</span><span>Webhook Feed</span></a></li>
        </ul>
        <p class="sidebar-note">Internal webhook validation dashboard for purchase invoice events.</p>
      </aside>

      <main class="main">
        <header class="hero">
          <h1>Purchase Invoice Webhook Demo</h1>
          <p class="subtitle">Verify webhook delivery and HMAC validation in a structured internal flow.</p>
        </header>

        <div class="workflow">
          <section class="section" id="step-config">
            <div class="section-title"><span class="num">1</span> Configure Webhook</div>
            <p class="section-subtext">Use the public endpoint below in your Complyance webhook setup, then paste the create-webhook API response and HMAC secret key.</p>
            <div class="url-box">
              <span class="url-text" id="publicUrl">${publicUrl || "Waiting for tunnel..."}</span>
              <button class="btn btn-secondary" onclick="copyUrl(this)">Copy URL</button>
              <button class="btn btn-secondary" onclick="refreshTunnel(this)" title="Get new tunnel URL">Refresh</button>
            </div>
            <div class="section-divider"></div>
            <textarea id="configJson" placeholder='{"success": true, "message": "...", "webhook": {...}}'></textarea>
            <div class="mt-2">
              <label class="form-label" for="hmacSecretKey">HMAC Secret Key (Optional, can be added later)</label>
              <input type="password" id="hmacSecretKey" placeholder="Paste webhook secret key" />
            </div>
            <button class="btn btn-primary mt-2" onclick="loadConfig()">Load Configuration</button>
            <div id="configSummary" class="config-summary" style="display:none;"></div>
          </section>

          <section class="section" id="step-auth">
            <div class="section-title"><span class="num">2</span> Authenticate</div>
            <p class="section-subtext">Login to fetch a bearer token automatically, or paste an existing token manually.</p>
            <div class="field-grid">
              <input type="email" id="loginEmail" placeholder="your@email.com" />
              <div class="password-wrap">
                <input type="password" id="loginPassword" placeholder="Password" style="padding-right: 62px;" />
                <button type="button" class="icon-btn" onclick="toggleLoginPasswordVisibility(this)" aria-label="Toggle login password">Show</button>
              </div>
              <button class="btn btn-primary" onclick="loginAndGetToken()" id="loginBtn">Login and Get Token</button>
              <div id="loginResult" class="text-sm"></div>
              <div class="section-divider"></div>
              <div class="password-wrap">
                <input type="password" id="bearerToken" placeholder="Paste bearer token here" style="padding-right: 62px;" />
                <button type="button" class="icon-btn" onclick="toggleTokenVisibility(this)" aria-label="Toggle token visibility">Show</button>
              </div>
            </div>
          </section>

          <section class="section" id="step-trigger">
            <div class="section-title"><span class="num">3</span> Trigger Event</div>
            <p class="section-subtext">Send a sample UAE purchase invoice into XML Composition and wait for a webhook event.</p>
            <button class="btn btn-primary trigger-btn" id="triggerBtn" onclick="triggerEvent()" disabled>Trigger Purchase Invoice Event</button>
            <div id="triggerResult"></div>
          </section>
        </div>

        <section class="section feed-section" id="step-feed">
          <div class="flex-between">
            <div class="section-title" style="margin-bottom:0"><span class="num">4</span> Captured Webhooks</div>
            <span class="polling-indicator" id="pollingIndicator"><span class="dot"></span> Polling every 2s</span>
          </div>
          <div id="webhookFeed" class="mt-3">
            <div class="empty-state">
              <p>No webhooks received yet</p>
              <p class="text-xs text-muted mt-2">Captured events will appear here after you trigger an event.</p>
            </div>
          </div>
        </section>
      </main>
    </div>
  </div>

  <script>
    let configLoaded = false;

    async function copyUrl(btn) {
      const url = document.getElementById('publicUrl').textContent;
      await navigator.clipboard.writeText(url);
      btn.textContent = 'Copied!';
      setTimeout(() => btn.textContent = 'Copy URL', 2000);
    }

    async function refreshTunnel(btn) {
      btn.disabled = true;
      btn.textContent = 'Refreshing...';
      const publicUrlEl = document.getElementById('publicUrl');
      publicUrlEl.textContent = 'Creating new URL...';
      try {
        const res = await fetch('/api/new-vercel-url', { method: 'POST' });
        const data = await res.json();
        if (data.success) {
          publicUrlEl.textContent = data.publicUrl;
        } else {
          publicUrlEl.textContent = 'Failed: ' + (data.message || 'Unknown error');
        }
      } catch {
        publicUrlEl.textContent = 'Failed to get new URL';
      }
      btn.disabled = false;
      btn.textContent = 'Refresh';
    }

    async function pollStatus() {
      try {
        const res = await fetch('/api/public-url');
        const data = await res.json();
        if (data.url) {
          const publicUrlEl = document.getElementById('publicUrl');
          if (!publicUrlEl.textContent || publicUrlEl.textContent === 'Waiting for tunnel...' || publicUrlEl.textContent.startsWith('Creating')) {
            publicUrlEl.textContent = data.url;
          }
        }
      } catch {
        // ignore polling errors
      }
    }

    pollStatus();
    setInterval(pollStatus, 2000);

    function toggleTokenVisibility(btn) {
      const input = document.getElementById('bearerToken');
      if (input.type === 'password') {
        input.type = 'text';
        btn.textContent = 'Hide';
      } else {
        input.type = 'password';
        btn.textContent = 'Show';
      }
    }

    function toggleLoginPasswordVisibility(btn) {
      const input = document.getElementById('loginPassword');
      if (input.type === 'password') {
        input.type = 'text';
        btn.textContent = 'Hide';
      } else {
        input.type = 'password';
        btn.textContent = 'Show';
      }
    }

    async function loginAndGetToken() {
      const email = document.getElementById('loginEmail').value.trim();
      const password = document.getElementById('loginPassword').value;
      const btn = document.getElementById('loginBtn');
      const resultDiv = document.getElementById('loginResult');

      if (!email || !password) {
        resultDiv.innerHTML = '<span style="color: #ef4444;">Please enter email and password</span>';
        return;
      }

      btn.disabled = true;
      btn.textContent = 'Logging in...';
      resultDiv.innerHTML = '<span style="color: #94a3b8;">Attempting login...</span>';

      try {
        const res = await fetch('/api/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password })
        });
        const data = await res.json();

        if (data.success && data.token) {
          document.getElementById('bearerToken').value = data.token;
          resultDiv.innerHTML = '<span style="color: #166534;">Login successful. Token was auto-filled.</span>';
          updateTriggerBtn();
        } else {
          resultDiv.innerHTML = '<span style="color: #991b1b;">' + (data.message || 'Login failed') + '</span>';
        }
      } catch (e) {
        resultDiv.innerHTML = '<span style="color: #991b1b;">Error: ' + e.message + '</span>';
      }

      btn.disabled = false;
      btn.textContent = 'Login and Get Token';
    }

    async function loadConfig() {
      const json = document.getElementById('configJson').value.trim();
      const hmacSecretKey = document.getElementById('hmacSecretKey').value.trim();
      if (!json && !hmacSecretKey) { alert('Paste config JSON or add HMAC secret key first'); return; }
      try {
        const res = await fetch('/api/config', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            configJson: json || undefined,
            hmacSecretKey: hmacSecretKey || undefined,
          })
        });
        const data = await res.json();
        if (!res.ok || !data.success) {
          throw new Error(data.message || 'Failed to load configuration');
        }

        configLoaded = true;
        const config = data.config;
        const summary = document.getElementById('configSummary');
        summary.style.display = 'grid';
        summary.innerHTML = [
          ['Client ID', config.clientId],
          ['Webhook Name', config.webhookName],
          ['Country', config.country],
          ['Environment', config.environment],
          ['Webhook ID', config.webhookId],
          ['HMAC Algorithm', config.hmacAlgorithm],
          ['Secret Key', config.secretKey ? 'Loaded' : 'Not set', config.secretKey ? 'secret' : ''],
          ['Events', data.enabledEvents],
        ].map(([label, value, cls]) => '<div class="config-item"><label>' + label + '</label><div class="value ' + (cls || '') + '">' + value + '</div></div>').join('');

        updateTriggerBtn();
      } catch (e) {
        alert('Failed to load config: ' + e.message);
      }
    }

    function updateTriggerBtn() {
      const token = document.getElementById('bearerToken').value.trim();
      document.getElementById('triggerBtn').disabled = !(configLoaded && token);
    }

    document.getElementById('bearerToken').addEventListener('input', updateTriggerBtn);

    async function triggerEvent() {
      const btn = document.getElementById('triggerBtn');
      const resultDiv = document.getElementById('triggerResult');
      btn.disabled = true;
      btn.textContent = 'Sending...';
      resultDiv.innerHTML = '';

      try {
        const token = document.getElementById('bearerToken').value.trim();
        const res = await fetch('/api/trigger', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Bearer-Token': token
          }
        });
        const data = await res.json();

        if (data.success) {
          resultDiv.innerHTML = '<div class="trigger-result success">Event sent successfully. ' + (data.message || '') + '</div>';
        } else {
          resultDiv.innerHTML = '<div class="trigger-result error">Failed: ' + (data.message || data.error || 'Unknown error') + '</div>';
        }
      } catch (e) {
        resultDiv.innerHTML = '<div class="trigger-result error">Network error: ' + e.message + '</div>';
      }

      btn.disabled = false;
      btn.textContent = 'Trigger Purchase Invoice Event';
    }

    async function fetchWebhooks() {
      try {
        const res = await fetch('/api/webhooks');
        const data = await res.json();
        renderWebhooks(data.webhooks || []);
      } catch (e) {
        console.error('Failed to fetch webhooks:', e);
      }
    }

    function renderWebhooks(webhooks) {
      const feed = document.getElementById('webhookFeed');
      if (webhooks.length === 0) {
        feed.innerHTML = '<div class="empty-state"><p>No webhooks received yet</p><p class="text-xs text-muted mt-2">Webhooks will appear here after the trigger fires</p></div>';
        return;
      }

      feed.innerHTML = webhooks.map(w => {
        const eventType = w.body?.data?.type || w.body?.data?.data?.type || 'unknown';
        const isStored = eventType.includes('stored');
        const badgeClass = isStored ? 'badge-stored' : 'badge-failed';
        const hmacBadgeClass = w.hmacVerified === true ? 'badge-verified' : 'badge-unverified';
        const hmacLabel = w.hmacVerified === true ? 'HMAC Verified' : w.hmacVerified === false ? 'HMAC Failed' : 'No Secret Loaded';

        let headersHtml = '';
        if (w.headers) {
          const relevantHeaders = ['x-webhook-id', 'x-webhook-timestamp', 'x-webhook-event', 'x-webhook-signature', 'content-type'];
          headersHtml = '<table class="headers-table"><thead><tr><th>Header</th><th>Value</th></tr></thead><tbody>';
          for (const h of relevantHeaders) {
            if (w.headers[h]) {
              const displayVal = h === 'x-webhook-signature' ? w.headers[h].substring(0, 32) + '...' : w.headers[h];
              headersHtml += '<tr><td>' + h + '</td><td>' + displayVal + '</td></tr>';
            }
          }
          headersHtml += '</tbody></table>';
        }

        let hmacDetail = '';
        if (w.hmacVerified !== null || w.hmacError) {
          hmacDetail = '<div class="hmac-detail">Algorithm: ' + (w.hmacAlgorithm || 'N/A') + '</div>';
          hmacDetail += '<div class="hmac-detail">Computed: ' + (w.hmacComputed || 'N/A') + '</div>';
          if (w.hmacError) {
            hmacDetail += '<div class="hmac-detail text-red">Error: ' + w.hmacError + '</div>';
          }
        }

        return '<div class="webhook-card">' +
          '<div class="header">' +
            '<span class="badge ' + badgeClass + '">' + eventType + '</span>' +
            '<span class="time">' + new Date(w.receivedAt).toLocaleString() + '</span>' +
          '</div>' +
          '<div class="mb-2"><span class="badge ' + hmacBadgeClass + '">' + hmacLabel + '</span> <span class="text-xs text-muted">HTTP ' + w.httpStatus + '</span></div>' +
          (w.secretKeyProvided ? '' : '<div class="text-xs text-yellow mb-2">No secret key loaded. HMAC verification was skipped. Load configuration in Step 1 to verify.</div>') +
          headersHtml +
          '<div class="text-xs text-muted mb-2">Payload:</div>' +
          '<div class="json-block">' + escapeHtml(JSON.stringify(w.body, null, 2)) + '</div>' +
          hmacDetail +
        '</div>';
      }).join('');
    }

    function escapeHtml(str) {
      return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    // Poll every 2 seconds
    setInterval(fetchWebhooks, 2000);
    fetchWebhooks();
  </script>
</body>
</html>`;
}

// ─── Vercel Deployment ───────────────────────────────────────────────────────

interface VercelDeploymentResult {
  url: string;
  id: string;
  name: string;
}

async function createVercelDeployment(projectName: string): Promise<VercelDeploymentResult> {
  const vercelToken = process.env.VERCEL_API_TOKEN;
  const vercelTeamId = process.env.VERCEL_TEAM_ID;
  const repoId = process.env.VERCEL_GIT_REPO_ID;

  if (!vercelToken) {
    throw new Error("VERCEL_API_TOKEN is not set");
  }
  if (!repoId) {
    throw new Error("VERCEL_GIT_REPO_ID is not set");
  }

  const headers: Record<string, string> = {
    Authorization: `Bearer ${vercelToken}`,
    "Content-Type": "application/json",
  };

  if (vercelTeamId) {
    headers["X-Vercel-Team-Id"] = vercelTeamId;
  }

  // Create new deployment
  const createResponse = await fetch("https://api.vercel.com/v13/deployments", {
    method: "POST",
    headers,
    body: JSON.stringify({
      gitSource: {
        type: "github",
        repoId,
        name: projectName,
        ref: "main",
      },
      project: projectName,
      target: "production",
    }),
  });

  if (!createResponse.ok) {
    const error = await createResponse.text();
    throw new Error(`Failed to create deployment: ${error}`);
  }

  const deployment = await createResponse.json() as { id: string; url: string; name: string };

  // Wait for deployment to be ready
  const deploymentUrl = `https://${deployment.url}`;

  return {
    url: deploymentUrl,
    id: deployment.id,
    name: deployment.name,
  };
}

// ─── Cloudflare Setup ────────────────────────────────────────────────────────

interface TunnelResult {
  url: string;
  proc: { kill: () => void };
}

async function startCloudflareTunnel(port: number): Promise<TunnelResult> {
  console.log("Starting cloudflared quick tunnel...");
  const bunRuntime = (globalThis as { Bun?: unknown }).Bun as
    | { spawn: (options: { cmd: string[]; stdout: "pipe" }) => { stdout: ReadableStream<Uint8Array>; kill: () => void } }
    | undefined;

  if (!bunRuntime) {
    throw new Error("Cloudflare tunnel startup is only supported in Bun runtime");
  }

  try {
    const proc = bunRuntime.spawn({
      cmd: ["sh", "-c", `cloudflared tunnel --url http://localhost:${port} --loglevel info 2>&1`],
      stdout: "pipe",
    });

    const reader = proc.stdout.getReader();
    const decoder = new TextDecoder();

    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        proc.kill();
        reject(new Error("cloudflared tunnel did not start within 30 seconds"));
      }, 30000);

      async function readOutput() {
        try {
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            const text = decoder.decode(value, { stream: true });
            process.stdout.write(text);

            const urlMatch = text.match(/https:\/\/[a-z0-9-]+\.trycloudflare\.com/i);
            if (urlMatch) {
              clearTimeout(timeout);
              console.log(`\ncloudflared tunnel started: ${urlMatch[0]}`);
              resolve({ url: urlMatch[0], proc });
              return;
            }
          }
        } catch {
          // reader might be cancelled
        }
      }

      readOutput();
    });
  } catch (e) {
    throw new Error(`cloudflared tunnel failed: ${e instanceof Error ? e.message : String(e)}`);
  }
}

// ─── Server ──────────────────────────────────────────────────────────────────

const app = new Elysia()
  .use(cors())

  // Dashboard
  .get("/", ({ set }) => {
    set.headers["content-type"] = "text/html; charset=utf-8";
    return generateDashboard(state.publicUrl);
  })

  // Webhook receiver — this is the endpoint the platform will POST to
  .post("/webhook", async ({ request, set }) => {
    const rawBody = await request.text();
    const headers: Record<string, string> = {};
    request.headers.forEach((value, key) => {
      headers[key.toLowerCase()] = value;
    });

    let parsedBody: unknown;
    try {
      parsedBody = JSON.parse(rawBody);
    } catch {
      parsedBody = { _raw: rawBody };
    }

    const verification = verifyCapturedWebhook({
      rawBody,
      headers,
      config: state.config,
    });

    const webhook: CapturedWebhook = {
      id: crypto.randomUUID(),
      receivedAt: new Date().toISOString(),
      body: parsedBody,
      rawBody,
      headers,
      httpStatus: 200,
      hmacVerified: verification.hmacVerified,
      hmacComputed: verification.hmacComputed,
      hmacReceived: verification.hmacReceived,
      hmacError: verification.hmacError,
      hmacAlgorithm: verification.hmacAlgorithm,
    };

    state.webhooks.unshift(webhook);

    if (state.webhooks.length > 50) {
      state.webhooks = state.webhooks.slice(0, 50);
    }

    console.log(`Webhook received: ${headers["x-webhook-event"] || "unknown"} | HMAC: ${verification.hmacVerified === true ? "PASS" : verification.hmacVerified === false ? "FAIL" : "N/A"}`);

    set.status = 200;
    return { acknowledged: true };
  })

  // Load webhook config
  .post("/api/config", ({ body, set }) => {
    try {
      const payload = body as { configJson?: string; hmacSecretKey?: string } | undefined;
      const providedSecretKey = payload?.hmacSecretKey?.trim() ?? "";

      if (payload?.configJson?.trim()) {
        const rawConfig = JSON.parse(payload.configJson);
        const config = parseWebhookConfigInput(rawConfig);
        state.config = {
          ...config,
          secretKey: providedSecretKey || config.secretKey,
        };
      } else if (providedSecretKey && state.config) {
        state.config = {
          ...state.config,
          secretKey: providedSecretKey,
        };
      } else {
        throw new Error("Provide config JSON or load config first before updating secret key");
      }

      set.status = 200;
      return {
        success: true,
        message: "Configuration loaded",
        config: state.config,
        enabledEvents: summarizeConfiguredEvents(state.config.events),
      };
    } catch (error) {
      set.status = 400;
      return {
        success: false,
        message: error instanceof Error ? error.message : String(error),
      };
    }
  })

  // Login to get auth token
  .post("/api/login", async ({ request, set }) => {
    const body = await request.json().catch(() => null);
    const { email, password } = body || {};

    if (!email || !password) {
      set.status = 400;
      return { success: false, message: "Email and password are required" };
    }

    try {
      // Call NextAuth credentials provider at dev.one.complyance.io
      const response = await fetch("https://dev.one.complyance.io/api/auth/callback/credentials", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Referer": "https://dev.one.complyance.io",
        },
        body: JSON.stringify({
          email,
          password,
          redirect: "false",
          json: true
        }),
      });

      const data = await response.json().catch(() => ({}));

      // NextAuth returns { url: "...", status: ..., error: "...", ok: true/false }
      if (data.ok && data.url) {
        // Successfully authenticated, now we need to get the session token
        // Call /api/auth/session to get the token
        const sessionResponse = await fetch("https://dev.one.complyance.io/api/auth/session", {
          headers: {
            "Cookie": response.headers.get("set-cookie") || "",
          }
        });
        const sessionData = await sessionResponse.json().catch(() => ({}));

        if (sessionData?.accessToken) {
          state.bearerToken = sessionData.accessToken;
          return { success: true, token: sessionData.accessToken };
        }

        // Try to get the token from the JWT in the session
        if (sessionData?.token) {
          state.bearerToken = sessionData.token;
          return { success: true, token: sessionData.token };
        }

        // If we have a cookie, try to use it directly
        const cookies = response.headers.get("set-cookie");
        if (cookies) {
          // Extract session token from cookie
          const tokenMatch = cookies.match(/next-auth.session-token=([^;]+)/);
          if (tokenMatch) {
            return { success: true, token: tokenMatch[1], cookie: cookies };
          }
        }
      }

      set.status = 401;
      return { success: false, message: data.error || data.message || "Login failed. Check credentials." };
    } catch (e) {
      set.status = 500;
      return { success: false, message: `Login error: ${e instanceof Error ? e.message : String(e)}` };
    }
  })

  // Trigger test event
  .post("/api/trigger", async ({ request, set }) => {
    if (!state.config) {
      set.status = 400;
      return { success: false, message: "No webhook configuration loaded. Paste the webhook config JSON in Step 2." };
    }

    const bearerToken = request.headers.get("x-bearer-token");
    if (!bearerToken) {
      set.status = 400;
      return { success: false, message: "No Bearer token provided. Use Login (Step 3) or paste token (Step 4)." };
    }

    // Strip "Bearer " prefix if user included it
    const token = bearerToken.replace(/^Bearer\s+/i, "");

    const { clientId, environment, country } = state.config;

    try {
      const triggerBody = {
        flow: "inbound",
        sbdXml: buildSampleSbdXml(),
        country: country || "AE",
        environment: environment || "sandbox",
        clientId,
      };

      console.log(`Triggering event to ${ENCORE_URL}/xml-composition/process for clientId=${clientId}`);
      console.log(`Using token: ${token.substring(0, 20)}... (length: ${token.length})`);

      const response = await fetch(`${ENCORE_URL}/xml-composition/process`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify(triggerBody),
      });

      const responseText = await response.text();
      let responseData: unknown;
      try {
        responseData = JSON.parse(responseText);
      } catch {
        responseData = { _raw: responseText };
      }

      if (response.ok) {
        const pipelineReportedFailure =
          typeof responseData === "object" &&
          responseData !== null &&
          "success" in responseData &&
          (responseData as { success?: unknown }).success === false;

        if (pipelineReportedFailure) {
          const pipelineMessage =
            (responseData as { message?: unknown }).message;
          const failureMessage =
            typeof pipelineMessage === "string" && pipelineMessage.trim().length > 0
              ? pipelineMessage
              : "XML Composition processed the request but reported validation failure.";

          state.triggerResult = {
            success: true,
            message: failureMessage,
            data: responseData,
          };
          return {
            success: true,
            message:
              `Pipeline validation failed (expected for demo sample). ` +
              `Now verify that a purchase.invoice.validation_failed webhook was captured. ` +
              `Details: ${failureMessage}`,
            data: responseData,
          };
        }

        state.triggerResult = { success: true, message: "Event processed by XML Composition. Webhook should arrive shortly.", data: responseData };
        return { success: true, message: "Event sent to XML Composition pipeline. Webhook should arrive within seconds.", data: responseData };
      } else {
        const errorMsg = typeof responseData === "object" && responseData !== null
          ? JSON.stringify(responseData)
          : responseText;
        state.triggerResult = { success: false, message: `HTTP ${response.status}: ${errorMsg}` };
        set.status = response.status;
        return { success: false, message: `HTTP ${response.status}: ${errorMsg}`, data: responseData };
      }
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      state.triggerResult = { success: false, message };
      set.status = 500;
      return { success: false, message: `Network error: ${message}` };
    }
  })

  // Get captured webhooks
  .get("/api/webhooks", () => {
    return {
      webhooks: state.webhooks.map(w => ({
        ...w,
        rawBody: undefined, // don't send raw body to reduce payload
        secretKeyProvided: !!state.config?.secretKey,
      })),
      count: state.webhooks.length,
    };
  })

  // Status
  .get("/api/status", () => {
    return {
      publicUrl: state.publicUrl,
      tunnelEnabled: !DISABLE_TUNNEL,
      configLoaded: !!state.config,
      config: state.config ? {
        clientId: state.config.clientId,
        webhookName: state.config.webhookName,
        country: state.config.country,
        environment: state.config.environment,
        webhookId: state.config.webhookId,
        hasSecretKey: !!state.config.secretKey,
        hmacAlgorithm: state.config.hmacAlgorithm,
        events: state.config.events,
      } : null,
      webhookCount: state.webhooks.length,
      triggerResult: state.triggerResult,
    };
  })

  // Create new Vercel deployment for fresh URL
  .post("/api/new-vercel-url", async ({ set }) => {
    if (!IS_VERCEL) {
      set.status = 400;
      return { success: false, message: "Only available on Vercel deployment" };
    }

    try {
      const vercelToken = process.env.VERCEL_API_TOKEN;
      const projectName = process.env.VERCEL_GIT_REPO_SLUG || process.env.VERCEL_PROJECT_NAME || "hooklab";
      const repoId = process.env.VERCEL_GIT_REPO_ID;

      if (!vercelToken) {
        throw new Error("VERCEL_API_TOKEN environment variable is not set");
      }
      if (!repoId) {
        throw new Error("VERCEL_GIT_REPO_ID environment variable is not set");
      }

      const teamId = process.env.VERCEL_TEAM_ID;
      const headers: Record<string, string> = {
        Authorization: `Bearer ${vercelToken}`,
        "Content-Type": "application/json",
      };
      if (teamId) {
        headers["X-Vercel-Team-Id"] = teamId;
      }

      const branchName = `refresh-${Date.now()}`;

      const createResponse = await fetch("https://api.vercel.com/v13/deployments", {
        method: "POST",
        headers,
        body: JSON.stringify({
          gitSource: {
            type: "github",
            repoId,
            name: projectName,
            ref: branchName,
          },
          project: projectName,
        }),
      });

      if (!createResponse.ok) {
        const errorText = await createResponse.text();
        throw new Error(`Vercel API error: ${createResponse.status} - ${errorText}`);
      }

      const deployment = await createResponse.json() as { id: string; url: string };

      state.vercelDeploymentUrl = `https://${deployment.url}`;

      return {
        success: true,
        publicUrl: `${state.vercelDeploymentUrl}/webhook`,
        deploymentId: deployment.id,
      };
    } catch (error) {
      set.status = 500;
      return {
        success: false,
        message: error instanceof Error ? error.message : String(error),
      };
    }
  })

  // Get current public URL (works for both local tunnel and Vercel)
  .get("/api/public-url", () => {
    if (IS_VERCEL && state.vercelDeploymentUrl) {
      return {
        url: `${state.vercelDeploymentUrl}/webhook`,
        source: "vercel",
      };
    }
    return {
      url: state.publicUrl ? `${state.publicUrl}/webhook` : null,
      source: state.publicUrl ? "tunnel" : null,
    };
  })

export default app;

if (!IS_VERCEL) {
  app.listen(DEMO_PORT, () => {
    console.log(`\n${"=".repeat(60)}`);
    console.log(`  Purchase Invoice Webhook Demo Harness`);
    console.log(`  Dashboard: http://localhost:${DEMO_PORT}`);
    console.log(`${"=".repeat(60)}\n`);
  });
}

if (!DISABLE_TUNNEL) {
  setTimeout(async () => {
    try {
      const result = await startCloudflareTunnel(DEMO_PORT);
      state.publicUrl = result.url;
      state.tunnelProc = result.proc;
      console.log(`\n${"=".repeat(60)}`);
      console.log(`  Public Webhook URL: ${result.url}/webhook`);
      console.log(`  Dashboard: ${result.url}`);
      console.log(`  Local Dashboard: http://localhost:${DEMO_PORT}`);
      console.log(`${"=".repeat(60)}\n`);
      console.log("Steps:");
      console.log("  1. Go to dev.gets.complyance.io -> Webhooks -> Create Webhook");
      console.log(`  2. Use this URL: ${result.url}/webhook`);
      console.log("  3. Enable HMAC signing and copy the secret");
      console.log("  4. Open the dashboard and paste the webhook config JSON");
      console.log("  5. Enter your Bearer token and click Trigger");
      console.log("");
    } catch (e) {
      console.error("Failed to start tunnel:", e);
      console.log("\nYou can still use the local dashboard at http://localhost:" + DEMO_PORT);
      console.log("For external testing, install cloudflared and rerun:");
      console.log("  bun run src/server.ts");
      console.log("");
    }
  }, 1000);
}

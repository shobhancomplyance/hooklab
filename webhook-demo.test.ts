import { describe, expect, it } from "bun:test";
import { createHmac } from "crypto";

import {
  parseWebhookConfigInput,
  verifyCapturedWebhook,
} from "./webhook-demo-utils";

describe("parseWebhookConfigInput", () => {
  it("accepts webhook list responses and preserves sha512 signing config", () => {
    const config = parseWebhookConfigInput({
      success: true,
      webhooks: [
        {
          _id: "wh_123",
          clientId: "client_123",
          webhookName: "Purchase Hook",
          country: "AE",
          environment: "sandbox",
          secretKey: "secret_123",
          hmacAlgorithm: "sha512",
          events: ["purchase.invoice.stored", "purchase.invoice.validation_failed"],
        },
      ],
    });

    expect(config).toMatchObject({
      webhookId: "wh_123",
      clientId: "client_123",
      webhookName: "Purchase Hook",
      country: "AE",
      environment: "sandbox",
      secretKey: "secret_123",
      hmacAlgorithm: "sha512",
    });

    expect(config.events).toEqual({
      "purchase.invoice.stored": true,
      "purchase.invoice.validation_failed": true,
    });
  });
});

describe("verifyCapturedWebhook", () => {
  it("verifies sha512 signatures using the configured webhook algorithm when no header is present", () => {
    const rawBody = JSON.stringify({
      eventId: "evt_123",
      data: {
        id: "evt_123",
        type: "purchase.invoice.stored",
        timestamp: "2026-05-13T10:50:00.000Z",
        data: { documentId: "doc_123" },
      },
    });

    const signature = createHmac("sha512", "secret_123")
      .update(rawBody, "utf8")
      .digest("hex");

    const result = verifyCapturedWebhook({
      rawBody,
      headers: {
        "x-webhook-signature": signature,
      },
      config: {
        clientId: "client_123",
        secretKey: "secret_123",
        webhookId: "wh_123",
        environment: "sandbox",
        country: "AE",
        webhookName: "Purchase Hook",
        hmacAlgorithm: "sha512",
        events: {
          "purchase.invoice.stored": true,
        },
      },
    });

    expect(result).toMatchObject({
      hmacVerified: true,
      hmacReceived: signature,
      hmacError: null,
    });
  });
});

import { createHmac, timingSafeEqual } from "crypto";

export type DemoWebhookAlgorithm = "sha256" | "sha512";

export interface DemoWebhookConfig {
  clientId: string;
  secretKey: string;
  webhookId: string;
  environment: "sandbox" | "production";
  country: string;
  webhookName: string;
  hmacAlgorithm: DemoWebhookAlgorithm;
  events: Record<string, boolean>;
}

export interface WebhookVerificationResult {
  hmacVerified: boolean | null;
  hmacComputed: string;
  hmacReceived: string;
  hmacError: string | null;
  hmacAlgorithm: DemoWebhookAlgorithm | null;
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null;

const coerceAlgorithm = (value: unknown): DemoWebhookAlgorithm =>
  value === "sha512" ? "sha512" : "sha256";

const coerceEnvironment = (value: unknown): "sandbox" | "production" =>
  value === "production" ? "production" : "sandbox";

const coerceString = (value: unknown): string =>
  typeof value === "string" ? value.trim() : "";

const normalizeWebhookEvents = (value: unknown): Record<string, boolean> => {
  if (Array.isArray(value)) {
    return value.reduce<Record<string, boolean>>((acc, item) => {
      if (typeof item === "string" && item.trim()) {
        acc[item.trim()] = true;
      }
      return acc;
    }, {});
  }

  if (!isRecord(value)) {
    return {};
  }

  return Object.entries(value).reduce<Record<string, boolean>>((acc, [eventName, enabled]) => {
    if (eventName.trim()) {
      acc[eventName] = Boolean(enabled);
    }
    return acc;
  }, {});
};

const resolveWebhookPayload = (input: unknown): Record<string, unknown> => {
  if (Array.isArray(input)) {
    const firstEntry = input.find(isRecord);
    if (!firstEntry) {
      throw new Error("Webhook config array is empty");
    }
    return firstEntry;
  }

  if (!isRecord(input)) {
    throw new Error("Webhook config must be a JSON object or array");
  }

  if (Array.isArray(input.webhooks)) {
    const firstWebhook = input.webhooks.find(isRecord);
    if (!firstWebhook) {
      throw new Error("Webhook list response does not contain any webhook objects");
    }
    return firstWebhook;
  }

  if (isRecord(input.webhook)) {
    return input.webhook;
  }

  return input;
};

export const parseWebhookConfigInput = (input: unknown): DemoWebhookConfig => {
  const webhook = resolveWebhookPayload(input);

  const clientId = coerceString(webhook.clientId);
  const webhookId =
    coerceString(webhook._id) ||
    coerceString(webhook.id) ||
    coerceString(webhook.webhookId);

  if (!clientId) {
    throw new Error("Webhook config is missing clientId");
  }

  if (!webhookId) {
    throw new Error("Webhook config is missing webhookId");
  }

  return {
    clientId,
    secretKey: coerceString(webhook.secretKey),
    webhookId,
    environment: coerceEnvironment(webhook.environment),
    country: coerceString(webhook.country) || "AE",
    webhookName: coerceString(webhook.webhookName) || "Webhook Demo",
    hmacAlgorithm: coerceAlgorithm(webhook.hmacAlgorithm),
    events: normalizeWebhookEvents(webhook.events),
  };
};

export const summarizeConfiguredEvents = (events: Record<string, boolean>): string =>
  Object.entries(events)
    .filter(([, enabled]) => enabled)
    .map(([eventName]) => eventName)
    .join(", ") || "None";

export const verifyCapturedWebhook = ({
  rawBody,
  headers,
  config,
}: {
  rawBody: string;
  headers: Record<string, string>;
  config: DemoWebhookConfig | null;
}): WebhookVerificationResult => {
  if (!config?.secretKey) {
    return {
      hmacVerified: null,
      hmacComputed: "",
      hmacReceived: "",
      hmacError: null,
      hmacAlgorithm: null,
    };
  }

  const signature = headers["x-webhook-signature"] || "";
  if (!signature) {
    return {
      hmacVerified: null,
      hmacComputed: "",
      hmacReceived: "",
      hmacError: "Signature header is missing",
      hmacAlgorithm: config.hmacAlgorithm,
    };
  }

  const algorithm = coerceAlgorithm(headers["x-webhook-algorithm"] || config.hmacAlgorithm);

  try {
    const computed = createHmac(algorithm, config.secretKey)
      .update(rawBody, "utf8")
      .digest("hex");

    const expectedBuffer = Buffer.from(computed, "hex");
    const providedBuffer = Buffer.from(signature, "hex");
    const verified =
      expectedBuffer.length === providedBuffer.length &&
      timingSafeEqual(expectedBuffer, providedBuffer);

    return {
      hmacVerified: verified,
      hmacComputed: computed,
      hmacReceived: signature,
      hmacError: null,
      hmacAlgorithm: algorithm,
    };
  } catch (error) {
    return {
      hmacVerified: false,
      hmacComputed: "",
      hmacReceived: signature,
      hmacError: error instanceof Error ? error.message : String(error),
      hmacAlgorithm: algorithm,
    };
  }
};

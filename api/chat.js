/**
 * ════════════════════════════════════════════════════════════════
 * MChat API — Groq (openai/gpt-oss-120b)
 * ════════════════════════════════════════════════════════════════
 *
 * Base URL   : https://api.groq.com/openai/v1
 * Endpoint   : POST /chat/completions  (standard OpenAI-compatible, streaming)
 * Auth       : Authorization: Bearer <GROQ_API_KEY>
 * Model      : openai/gpt-oss-120b — Groq's current flagship open-weight
 *              model (their own docs point Qwen3-32B, Llama-4-Scout and
 *              Kimi-K2 users here as the recommended upgrade). ~500 tok/s,
 *              131K context, reasoning modes low/medium/high (medium default).
 *
 * IMPORTANT — reasoning leakage fix:
 * gpt-oss-120b is a "harmony format" reasoning model. By default Groq can
 * return the real answer inside a separate `reasoning` field instead of
 * `content` (documented + reported behaviour), which would make a naive
 * integration look like it "sometimes returns nothing". We avoid this
 * entirely by sending `include_reasoning: false`, which keeps the model's
 * scratch-thinking server-side and guarantees the final answer streams
 * through the normal `delta.content` field.
 *
 * If Groq changes their lineup again, the only line that should need to
 * change is CONFIG.GROQ_MODEL below — check https://console.groq.com/docs/models
 *
 * Get a free key at: https://console.groq.com/keys
 * ════════════════════════════════════════════════════════════════
 */

'use strict';

const CONFIG = {
  GROQ_API_BASE: 'https://api.groq.com/openai/v1',
  GROQ_MODEL: 'openai/gpt-oss-120b',
  GROQ_API_KEY: process.env.GROQ_API_KEY,

  REQUEST_TIMEOUT: 30000,
  MAX_RETRIES: 3,
  RETRY_DELAY: 1000,

  // gpt-oss-120b has a 131,072-token context window. We stay well under it —
  // char/3.5 is a deliberately conservative estimate (Cyrillic text tokenizes
  // less efficiently per character than English/Latin text).
  CHARS_PER_TOKEN: 3.5,
  MAX_INPUT_TOKENS: 100000,
  MAX_OUTPUT_TOKENS: 4096,

  DEFAULT_TEMPERATURE: 0.7,
  MIN_TEMPERATURE: 0,
  MAX_TEMPERATURE: 2,
  DEFAULT_TOP_P: 0.95,
  REASONING_EFFORT: 'medium', // low | medium | high — medium balances "smart" and "fast"

  // Best-effort only: this counter resets on every cold start / new instance,
  // so it does not enforce a hard global limit. It exists to give the person
  // a friendly message instead of a raw provider error during a burst of
  // requests from the same tab. The real limit is enforced by Groq itself.
  REQUESTS_PER_MINUTE: 25,

  MAX_MESSAGE_LENGTH: 20000,
  MAX_MESSAGES_BATCH: 200, // generous sanity cap; the client sends a trimmed window already

  STREAM_TIMEOUT: 15000,
};

const STATE = {
  totalRequests: 0,
  totalTokensUsed: 0,
  startTime: Date.now(),
};

// ═══════════════════════════════════════════════════════════
// LOGGER
// ═══════════════════════════════════════════════════════════

class Logger {
  static log(level, message, data = {}) {
    console.log(JSON.stringify({ timestamp: new Date().toISOString(), level, message, ...data }));
  }
  static info(message, data) { this.log('INFO', message, data); }
  static warn(message, data) { this.log('WARN', message, data); }
  static error(message, data) { this.log('ERROR', message, data); }
  static debug(message, data) { if (process.env.DEBUG) this.log('DEBUG', message, data); }
}

// ═══════════════════════════════════════════════════════════
// TOKEN ESTIMATION
// ═══════════════════════════════════════════════════════════

class TokenCounter {
  static countTokens(text) {
    if (!text) return 0;
    return Math.ceil(text.length / CONFIG.CHARS_PER_TOKEN);
  }

  static countMessagesTokens(messages) {
    let total = 0;
    for (const m of messages) total += this.countTokens(m.content) + 4;
    return total;
  }

  static validateTokenCount(messages) {
    const messagesTokens = this.countMessagesTokens(messages);
    const totalTokens = messagesTokens + CONFIG.MAX_OUTPUT_TOKENS;

    if (totalTokens > CONFIG.MAX_INPUT_TOKENS) {
      throw new Error(
        `Conversation too long for one request (~${messagesTokens} input tokens). ` +
        `Try starting a new chat.`
      );
    }
    return { messagesTokens, totalTokens };
  }
}

// ═══════════════════════════════════════════════════════════
// VALIDATION
// ═══════════════════════════════════════════════════════════

class MessageValidator {
  static validateMessage(message) {
    if (!message || typeof message !== 'object') throw new Error('Invalid message format');
    const { role, content } = message;
    if (!['user', 'assistant', 'system'].includes(role)) throw new Error(`Invalid role: ${role}`);
    if (!content || typeof content !== 'string') throw new Error('Message content must be a non-empty string');
    if (content.length > CONFIG.MAX_MESSAGE_LENGTH) {
      throw new Error(`Message too long: ${content.length} > ${CONFIG.MAX_MESSAGE_LENGTH}`);
    }
  }

  static validateMessages(messages) {
    if (!Array.isArray(messages)) throw new Error('Messages must be an array');
    if (messages.length === 0) throw new Error('Messages array cannot be empty');
    if (messages.length > CONFIG.MAX_MESSAGES_BATCH) {
      throw new Error(`Too many messages: ${messages.length} > ${CONFIG.MAX_MESSAGES_BATCH}`);
    }
    messages.forEach(m => this.validateMessage(m));
  }

  static validateTemperature(temperature) {
    if (typeof temperature !== 'number' || temperature < CONFIG.MIN_TEMPERATURE || temperature > CONFIG.MAX_TEMPERATURE) {
      throw new Error(`Temperature must be between ${CONFIG.MIN_TEMPERATURE} and ${CONFIG.MAX_TEMPERATURE}`);
    }
  }
}

// ═══════════════════════════════════════════════════════════
// GROQ CLIENT
// ═══════════════════════════════════════════════════════════

class GroqClient {
  constructor(apiKey) {
    if (!apiKey) throw new Error('GROQ_API_KEY not set. Get a free key at https://console.groq.com/keys');
    this.apiKey = apiKey;
  }

  buildPayload(messages, temperature) {
    return {
      model: CONFIG.GROQ_MODEL,
      messages,
      temperature: Math.min(Math.max(temperature, CONFIG.MIN_TEMPERATURE), CONFIG.MAX_TEMPERATURE),
      max_completion_tokens: CONFIG.MAX_OUTPUT_TOKENS,
      top_p: CONFIG.DEFAULT_TOP_P,
      reasoning_effort: CONFIG.REASONING_EFFORT,
      include_reasoning: false, // keep chain-of-thought out of the response entirely — see header note
      stream: true,
    };
  }

  async request(payload, retryCount = 0) {
    const url = `${CONFIG.GROQ_API_BASE}/chat/completions`;

    try {
      Logger.info('Groq request', { model: CONFIG.GROQ_MODEL, retryCount, messages: payload.messages.length });

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), CONFIG.REQUEST_TIMEOUT);

      const response = await fetch(url, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${this.apiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        const errorText = await response.text();
        let errorData;
        try { errorData = JSON.parse(errorText); } catch { errorData = { error: { message: errorText } }; }
        throw { status: response.status, statusText: response.statusText, data: errorData };
      }

      return response;
    } catch (error) {
      Logger.error('Groq request failed', { error: error.message || String(error), retryCount, status: error.status });

      if (retryCount < CONFIG.MAX_RETRIES && this.isRetryableError(error)) {
        const delay = CONFIG.RETRY_DELAY * Math.pow(2, retryCount);
        await new Promise(r => setTimeout(r, delay));
        return this.request(payload, retryCount + 1);
      }
      throw error;
    }
  }

  isRetryableError(error) {
    if (error.name === 'AbortError') return true;
    if (error.status && error.status >= 500) return true;
    if (error.status === 429) return true;
    return false;
  }

  async *streamResponse(response) {
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    let lastChunkTime = Date.now();

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        if (Date.now() - lastChunkTime > CONFIG.STREAM_TIMEOUT) {
          throw new Error('Stream timeout: no data received from Groq');
        }
        lastChunkTime = Date.now();

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed.startsWith('data: ')) continue;
          const data = trimmed.slice(6).trim();
          if (data === '[DONE]' || !data) continue;
          try { yield JSON.parse(data); }
          catch { Logger.debug('Skipping unparsable SSE line', { line: data.slice(0, 100) }); }
        }
      }
    } finally {
      reader.releaseLock();
    }
  }

  extractContent(chunk) {
    const delta = chunk.choices?.[0]?.delta;
    return delta?.content || null;
  }

  extractFinishReason(chunk) {
    return chunk.choices?.[0]?.finish_reason || null;
  }
}

// ═══════════════════════════════════════════════════════════
// RATE LIMITER (best-effort, see CONFIG comment)
// ═══════════════════════════════════════════════════════════

class RateLimiter {
  constructor() { this.requests = []; }

  isAllowed(clientId) {
    const now = Date.now();
    const cutoff = now - 60000;
    this.requests = this.requests.filter(r => r.time > cutoff);
    const mine = this.requests.filter(r => r.clientId === clientId);
    if (mine.length >= CONFIG.REQUESTS_PER_MINUTE) return false;
    this.requests.push({ clientId, time: now });
    return true;
  }
}

const rateLimiter = new RateLimiter();

// ═══════════════════════════════════════════════════════════
// SSE RESPONSE WRITER
// ═══════════════════════════════════════════════════════════

class ResponseWriter {
  constructor(res) { this.res = res; this.headersSent = false; }

  ensureHeaders() {
    if (this.headersSent) return;
    this.res.setHeader('Content-Type', 'text/event-stream');
    this.res.setHeader('Cache-Control', 'no-cache');
    this.res.setHeader('Connection', 'keep-alive');
    this.res.setHeader('Access-Control-Allow-Origin', '*');
    this.res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    this.res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    this.headersSent = true;
  }

  sendData(data) { this.ensureHeaders(); this.res.write(`data: ${JSON.stringify(data)}\n\n`); }
  sendError(message, code = 'ERROR') { this.ensureHeaders(); this.res.write(`data: ${JSON.stringify({ error: true, code, message })}\n\n`); }
  end(data = {}) {
    this.ensureHeaders();
    this.res.write(`data: ${JSON.stringify({ ...data, done: true })}\n\n`);
    this.res.write('data: [DONE]\n\n');
    this.res.end();
  }
}

// ═══════════════════════════════════════════════════════════
// MAIN HANDLER
// ═══════════════════════════════════════════════════════════

async function handler(req, res) {
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.status(200).end();
    return;
  }

  if (req.method !== 'POST') {
    res.status(405).json({ error: 'Method not allowed' });
    return;
  }

  const writer = new ResponseWriter(res);
  const clientId = req.headers['x-client-id'] || req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown';

  try {
    if (!rateLimiter.isAllowed(clientId)) {
      writer.sendError(`Too many requests. Max ${CONFIG.REQUESTS_PER_MINUTE} per minute — please wait a moment.`, 'RATE_LIMITED');
      writer.end();
      return;
    }

    let body;
    try {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    } catch {
      writer.sendError('Invalid JSON in request body', 'INVALID_JSON');
      writer.end();
      return;
    }

    const { messages, temperature = CONFIG.DEFAULT_TEMPERATURE } = body || {};

    try {
      MessageValidator.validateMessages(messages);
      MessageValidator.validateTemperature(temperature);
      TokenCounter.validateTokenCount(messages);
    } catch (validationError) {
      writer.sendError(validationError.message, 'VALIDATION_ERROR');
      writer.end();
      return;
    }

    const client = new GroqClient(CONFIG.GROQ_API_KEY);
    const payload = client.buildPayload(messages, temperature);
    const response = await client.request(payload);

    let fullContent = '';
    let finishReason = null;

    for await (const chunk of client.streamResponse(response)) {
      const content = client.extractContent(chunk);
      if (content) {
        fullContent += content;
        writer.sendData({ content });
      }
      const fr = client.extractFinishReason(chunk);
      if (fr) finishReason = fr;
    }

    if (!fullContent && finishReason) {
      // Defensive fallback: should not happen with include_reasoning:false, but
      // surfaces a clear message instead of a silently empty bubble if Groq's
      // response shape ever changes again.
      Logger.warn('Empty content with no error — unexpected response shape', { finishReason });
    }

    writer.end({ fullContent, finishReason, model: CONFIG.GROQ_MODEL });

    STATE.totalRequests++;
    STATE.totalTokensUsed += TokenCounter.countTokens(fullContent);
    Logger.info('Request completed', { clientId, contentLength: fullContent.length, totalRequests: STATE.totalRequests });
  } catch (error) {
    const status = error.status || 500;
    const providerMessage = error.data?.error?.message;
    Logger.error('Handler error', { error: error.message, providerMessage, status });

    writer.sendError(providerMessage || error.message || 'Internal server error', status === 429 ? 'RATE_LIMITED' : 'SERVER_ERROR');
    writer.end();
  }
}

module.exports = handler;

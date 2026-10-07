// Reads configuration from environment variables. Secrets live ONLY here (server side):
// nothing in public/ can read process.env, and the API never returns these values.
//
//   NVD_API_KEY   optional  raises NVD's rate limit
//   LLM_BASE_URL  \
//   LLM_API_KEY    } all three are needed for the AI summary; otherwise the template summary is used
//   LLM_MODEL     /

const text = (value) => (typeof value === 'string' ? value.trim() : '');

/** The LLM endpoint must be https (so the key is never sent in clear text); plain http only for localhost testing. */
function isAllowedBaseUrl(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  if (url.username || url.password) return false;
  if (url.protocol === 'https:') return true;
  return url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
}

// Model IDs look like "openai/gpt-oss-120b" or "llama-3.3-70b:free": start alphanumeric, no "..".
const MODEL_NAME = /^(?!.*\.\.)[A-Za-z0-9][A-Za-z0-9._:/-]{0,99}$/;

export function readConfig(env) {
  const nvdApiKey = text(env.NVD_API_KEY);
  const apiKey = text(env.LLM_API_KEY);
  const baseUrl = text(env.LLM_BASE_URL);
  const model = text(env.LLM_MODEL);
  const llm = apiKey && baseUrl && MODEL_NAME.test(model) && isAllowedBaseUrl(baseUrl)
    ? { apiKey, baseUrl: baseUrl.replace(/\/+$/, ''), model }
    : null;
  return { nvdApiKey, llm };
}

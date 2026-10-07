// Fixture: every __NAME__ token is replaced with a generated fake credential at test time.
// Each line that must be reported carries an "expect:" marker with the rule id.
export const anthropic = '__ANTHROPIC__'; // expect: secret/anthropic-api-key
export const openai = "__OPENAI__"; // expect: secret/openai-api-key
const legacyOpenai = `__OPENAI_LEGACY__`; // expect: secret/openai-api-key
const ghToken = '__GITHUB_PAT__'; // expect: secret/github-token
const ghFineGrained = '__GITHUB_FINE__'; // expect: secret/github-token
const stripe = '__STRIPE__'; // expect: secret/stripe-live-key
const slack = '__SLACK__'; // expect: secret/slack-token
const alerts = '__SLACK_WEBHOOK__'; // expect: secret/slack-webhook
const maps = '__GOOGLE__'; // expect: secret/google-api-key
const npmPublish = '__NPM__'; // expect: secret/npm-token
const mail = '__SENDGRID__'; // expect: secret/sendgrid-api-key
const hub = '__HUGGINGFACE__'; // expect: secret/huggingface-token
const session = '__JWT__'; // expect: secret/jwt
const db = 'postgres://app:__DB_PASSWORD__@db.prod.internal:5432/app'; // expect: secret/database-url
const apiSecret = '__GENERIC__'; // expect: secret/generic-high-entropy

export const config = { headers: { 'x-api-key': '__GENERIC__' } }; // expect: secret/generic-high-entropy

export function isAdmin(token: string) {
  return token === '__HEX__'; // expect: secret/generic-high-entropy
}

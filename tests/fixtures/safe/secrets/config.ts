// Nothing in this file should be reported.
const apiKey = process.env.OPENAI_API_KEY;
const anthropicKey = 'your-api-key-here';
const awsAccessKeyId = 'AKIAIOSFODNN7EXAMPLE';
const awsSecretAccessKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
const stripeKey = 'sk_live_xxxxxxxxxxxxxxxxxxxxxxxx';
const githubToken = '<YOUR_GITHUB_TOKEN>';
const tokenUrl = 'https://auth.example.com/oauth/token';
const passwordLabel = 'Enter your password';
const authHeader = 'Authorization';
const i18nKey = 'auth.login.title';
const cacheKey = 'user-profile-v2';
const keyPath = './certs/server.key';
const commitSha = 'a94a8fe5ccb19ba61c4c0873d391e987982fbbd3';
const docs = 'A PEM file starts with -----BEGIN PRIVATE KEY----- followed by base64.';
const dbUrl = `postgres://app:${process.env.DB_PASSWORD}@db.prod.internal:5432/app`;
const localDb = 'postgres://postgres:postgres@localhost:5432/dev';
const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET ?? '';
const publishableKey = 'pk_live_51HqLyjWDarjtT1zdp7dcX4kq2Y8vN3mP0sR6uT9wB';
const tokenType = 'Bearer';
const secretName = 'prod/db-credentials';
const password = process.env.ADMIN_PASSWORD;
const jwtLike = 'eyJhbGciOiJub25lIn0'; // a header alone is not a token
// The jwt.io sample token and documentation-style connection strings.
const sampleJwt =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
const docsDb = 'mongodb://username:password@host:27017/app';

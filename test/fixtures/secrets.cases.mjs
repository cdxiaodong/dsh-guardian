// Synthetic samples for scanSecrets() coverage: one or more positives and negatives per SECRET_RULES id.
// Every secret-like value is assembled at runtime from fragments, so no complete secret-looking
// literal appears in this file. All values are fake.

const J = (...parts) => parts.join('')
const A36 = '0123456789abcdefghijklmnopqrstuvwxyz'
const B36 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
const H32 = '0123456789abcdef'.repeat(2)
// n chars from [0-9A-Za-z_]
const mix = (n) => (B36 + '_' + A36).repeat(3).slice(0, n)

export default {
  'aws-akid': {
    positive: [() => J('AKIA', 'IOSFODNN7', 'EXAMPLE')],
    negative: [() => J('AKIA', 'IOSFODNN7', 'EXAMP')],
  },
  'aws-secret': {
    positive: [() => J('aws_secret_access_key = ', B36, A36.slice(0, 4))],
    negative: [() => J('aws_secret_access_key = ', B36, A36.slice(0, 3))],
  },
  'github-pat': {
    positive: [() => J('gh', 'p_', A36)],
    negative: [() => J('ghp_', A36.slice(0, 35))],
  },
  'github-oauth': {
    positive: [() => J('gho_', B36)],
    negative: [() => J('gho_', B36.slice(0, 35))],
  },
  'github-app': {
    positive: [() => J('ghs_', A36), () => J('ghu_', B36)],
    negative: [() => J('ghx_', A36)],
  },
  'github-fine': {
    positive: [() => J('github_pat_', mix(82))],
    negative: [() => J('github_pat_', mix(81))],
  },
  'gitlab-pat': {
    positive: [() => J('glpat-', mix(20))],
    negative: [() => J('glpat-', mix(19))],
  },
  'openai-key': {
    positive: [() => J('sk-proj-', mix(24)), () => J('sk-', mix(40))],
    negative: [() => J('sk-proj-', mix(19))],
  },
  'anthropic-key': {
    positive: [() => J('sk-ant-api03-', mix(24))],
    negative: [() => J('sk-ant-api03-', mix(19))],
  },
  'google-api': {
    positive: [() => J('AIza', mix(35))],
    negative: [() => J('AIza', mix(34))],
  },
  'gcp-oauth': {
    positive: [() => J('ya29.', mix(24))],
    negative: [() => J('ya29.', mix(19))],
  },
  'slack-bot': {
    positive: [() => J('xoxb-', '1234567890', '-', '0987654321', '-', A36.slice(0, 24))],
    negative: [() => J('xoxb-', '12345', '-', '67890', '-', A36.slice(0, 24))],
  },
  'slack-user': {
    positive: [() => J('xoxp', '-1234567890', '-1234567890', '-1234567890', '-', A36.slice(0, 30))],
    negative: [() => J('xoxp', '-123456789', '-123456789', '-123456789', '-', A36.slice(0, 30))],
  },
  'slack-app': {
    positive: [() => J('xapp-1-', 'A1B2C3D4E5', '-1234567890123-', 'abcdef0123456789')],
    negative: [() => J('xapp-1-', 'A1B2C3D4E5', '-1234567890123-', 'ABCDEF0123456789')],
  },
  'stripe-live': {
    positive: [() => J('sk_live_', A36.slice(0, 24))],
    negative: [() => J('sk_live_', A36.slice(0, 23))],
  },
  'stripe-test': {
    positive: [() => J('rk_test_', A36.slice(0, 24))],
    negative: [() => J('rk_test_', A36.slice(0, 23))],
  },
  'npm-token': {
    positive: [() => J('npm_', A36)],
    negative: [() => J('npm_', A36.slice(0, 35))],
  },
  'pypi-token': {
    positive: [() => J('pypi-', 'AgEIcHlwaS5', 'vcmc', mix(55))],
    negative: [() => J('pypi-', 'AgEIcHlwaS5', 'vcmc', mix(49))],
  },
  telegram: {
    positive: [() => J('123456789', ':', A36.slice(0, 35))],
    negative: [() => J('123456789', ':', A36.slice(0, 34))],
  },
  twilio: {
    positive: [() => J('SK', H32)],
    negative: [() => J('SK', H32.slice(0, 31))],
  },
  sendgrid: {
    positive: [() => J('SG.', mix(22), '.', mix(43))],
    negative: [() => J('SG.', mix(21), '.', mix(43))],
  },
  huggingface: {
    positive: [() => J('hf_', A36)],
    negative: [() => J('hf_', A36.slice(0, 29))],
  },
  'private-key': {
    positive: [() => J('-----BEGIN', ' RSA ', 'PRIVATE KEY-----'), () => J('-----BEGIN', ' OPENSSH ', 'PRIVATE KEY BLOCK-----')],
    negative: [() => J('-----BEGIN', ' CERTIFICATE', '-----')],
  },
  jwt: {
    positive: [() => J('eyJ', 'abcdefghij', '.', 'klmnopqrst', '.', 'uvwxyz0123')],
    negative: [() => J('eyJ', 'abcdefghi', '.', 'klmnopqrst', '.', 'uvwxyz0123')],
  },
  bearer: {
    positive: [() => J('Bearer ', A36)],
    negative: [() => J('Bearer ', A36.slice(0, 19))],
  },
  'generic-secret': {
    positive: [() => J('token = ', A36)],
    negative: [() => J('token = ', 'short')],
  },
}

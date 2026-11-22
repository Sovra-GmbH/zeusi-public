// Real OAuth client metadata for the MCP clients Zeusi accepts (src/mcp-oauth.ts
// EXACT_REDIRECTS). Public documents, no secrets.
//
// CIMD: the live documents, copied verbatim (fetched 2026-11-17) from the client_id URL.
// DCR: the registration bodies each client sends to /register, from its source or docs:
//   VS Code     microsoft/vscode src/vs/base/common/oauth.ts fetchDynamicRegistration
//               (grant_types filtered by Zeusi's grant_types_supported; scope from the
//               resource metadata)
//   Gemini CLI  google-gemini/gemini-cli packages/core/src/mcp/oauth-provider.ts (redirect
//               http://localhost:<port>/oauth/callback, https://geminicli.com/docs/tools/mcp-server/)
//   Cursor      https://cursor.com/docs/context/mcp "Static redirect URL": both redirect URIs
//               are registered (body shape assumed: Cursor's source is not public)

export const CIMD_DOCS = {
  chatgpt: {
    url: 'https://chatgpt.com/oauth/client.json',
    doc: { client_id: 'https://chatgpt.com/oauth/client.json', client_uri: 'https://chatgpt.com/', redirect_uris: ['https://chatgpt.com/connector_platform_oauth_redirect'], token_endpoint_auth_method: 'private_key_jwt', token_endpoint_auth_methods_supported: ['none', 'private_key_jwt'], grant_types: ['authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:jwt-bearer'], response_types: ['code'], client_name: 'ChatGPT', logo_uri: 'https://persistent.oaistatic.com/sonic/misc/openai-logo.png', token_endpoint_auth_signing_alg: 'RS256', jwks_uri: 'https://chatgpt.com/oauth/jwks.json' },
  },
  vscode: {
    url: 'https://vscode.dev/oauth/client-metadata.json',
    doc: { client_name: 'Visual Studio Code', logo_uri: 'https://code.visualstudio.com/assets/branding/code-stable.png', grant_types: ['authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:device_code'], response_types: ['code'], token_endpoint_auth_method: 'none', application_type: 'native', client_id: 'https://vscode.dev/oauth/client-metadata.json', client_uri: 'https://vscode.dev/product', redirect_uris: ['http://127.0.0.1:33418/', 'https://vscode.dev/redirect'] },
  },
  claude: {
    url: 'https://claude.ai/oauth/mcp-oauth-client-metadata',
    doc: { client_id: 'https://claude.ai/oauth/mcp-oauth-client-metadata', client_name: 'Claude', client_uri: 'https://claude.ai', redirect_uris: ['https://claude.ai/api/mcp/auth_callback'], grant_types: ['authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:jwt-bearer'], response_types: ['code'], token_endpoint_auth_method: 'none' },
  },
  claudeCode: {
    url: 'https://claude.ai/oauth/claude-code-client-metadata',
    doc: { client_id: 'https://claude.ai/oauth/claude-code-client-metadata', client_name: 'Claude Code', client_uri: 'https://claude.ai', redirect_uris: ['http://localhost/callback', 'http://127.0.0.1/callback'], grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'], token_endpoint_auth_method: 'none' },
  },
} as const;

export const DCR_BODIES = {
  vscode: {
    client_name: 'Visual Studio Code', client_uri: 'https://code.visualstudio.com', grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'],
    redirect_uris: ['https://insiders.vscode.dev/redirect', 'https://vscode.dev/redirect', 'http://127.0.0.1/', 'http://127.0.0.1:33418/'],
    scope: 'zeusi.read', token_endpoint_auth_method: 'none', application_type: 'native',
  },
  // VS Code when the server does not list grant_types_supported: its full default list.
  vscodeAllGrants: {
    client_name: 'Visual Studio Code', client_uri: 'https://code.visualstudio.com',
    grant_types: ['authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:device_code'], response_types: ['code'],
    redirect_uris: ['https://insiders.vscode.dev/redirect', 'https://vscode.dev/redirect', 'http://127.0.0.1/', 'http://127.0.0.1:33418/'],
    token_endpoint_auth_method: 'none', application_type: 'native',
  },
  gemini: {
    client_name: 'Gemini CLI MCP Client', redirect_uris: ['http://localhost:7777/oauth/callback'], grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'], token_endpoint_auth_method: 'none', scope: 'zeusi.read',
  },
  cursor: {
    client_name: 'Cursor', redirect_uris: ['https://www.cursor.com/agents/mcp/oauth/callback', 'http://localhost:8787/callback'],
    grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'], token_endpoint_auth_method: 'none',
  },
  chatgpt: {
    client_name: 'ChatGPT', redirect_uris: ['https://chatgpt.com/connector_platform_oauth_redirect'], grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'], token_endpoint_auth_method: 'none', application_type: 'web',
  },
} as const;

/** Every allowed redirect: the exact https URIs and loopback host x path x port. */
export const EXACT_OK = [
  'https://claude.ai/api/mcp/auth_callback', 'https://chatgpt.com/connector_platform_oauth_redirect', 'https://www.cursor.com/agents/mcp/oauth/callback',
  'https://vscode.dev/redirect', 'https://insiders.vscode.dev/redirect',
] as const;
export const LOOPBACK_OK: string[] = [];
for (const host of ['localhost', '127.0.0.1']) {
  for (const path of ['/callback', '/oauth/callback', '/']) {
    for (const port of ['', ':1', ':33418', ':8787', ':65535']) LOOPBACK_OK.push(`http://${host}${port}${path}`);
  }
}

/** Refused everywhere (allowlist, /register, /authorize). */
export const REDIRECT_BAD: string[] = [
  // look-alike and arbitrary https hosts
  'https://claude.ai.evil.com/api/mcp/auth_callback', 'https://evil-claude.ai/api/mcp/auth_callback', 'https://chatgpt.com.evil.io/connector_platform_oauth_redirect',
  'https://chatgpt.co/connector_platform_oauth_redirect', 'https://cursor.com/agents/mcp/oauth/callback', 'https://www.cursor.com.evil.com/agents/mcp/oauth/callback',
  'https://vscode.dev.evil.com/redirect', 'https://evil.example/callback', 'https://claude.com/api/mcp/auth_callback', 'https://www.claude.ai/api/mcp/auth_callback',
  // path, query, fragment, userinfo, port, case, scheme variants of allowed URIs
  'https://claude.ai/api/mcp/auth_callback/../x', 'https://claude.ai/api/mcp/auth_callback/', 'https://claude.ai/api/mcp/auth_callback?next=https://evil',
  'https://claude.ai/api/mcp/auth_callback#x', 'https://user@claude.ai/api/mcp/auth_callback', 'https://claude.ai:443/api/mcp/auth_callback',
  'HTTPS://CLAUDE.AI/api/mcp/auth_callback', 'https://Claude.ai/api/mcp/auth_callback', 'http://claude.ai/api/mcp/auth_callback',
  'https://chatgpt.com/connector/oauth/abc', 'https://chatgpt.com/connector_platform_oauth_redirect/', 'https://vscode.dev/redirect?x=1',
  'https://claude.ai/api/mcp/auth%5Fcallback', ' https://claude.ai/api/mcp/auth_callback', 'https://claude.ai/api/mcp/auth_callback ',
  'https://claude.ai./api/mcp/auth_callback',
  // loopback look-alikes and variants
  'http://evil.com/callback', 'http://localhost:8080/evil', 'http://localhost:3118/callback/', 'http://localhost:3118/callback?x=1', 'http://localhost/callback#f',
  'https://localhost:3118/callback', 'HTTP://localhost/callback', 'http://LOCALHOST/callback', 'http://localhost./callback', 'http://127.0.0.1./callback',
  'http://127.0.0.1.evil.com/callback', 'http://localhost.evil.com/callback', 'http://[::1]/callback', 'http://[::1]:3118/callback', 'http://0.0.0.0/callback',
  'http://127.1/callback', 'http://2130706433/callback', 'http://0x7f000001/callback', 'http://127.0.0.2/callback', 'http://user@localhost/callback',
  'http://localhost@evil.com/callback', 'http://localhost:0/callback', 'http://localhost:65536/callback', 'http://localhost:99999/callback',
  'http://localhost:123456/callback', 'http://localhost:+80/callback', 'http://localhost:080/callback', 'http://localhost:/callback',
  'http://localhost/%63allback', 'http://localhost/callback%2F..', 'http://localhost\\@evil.com/callback', 'http://localhost/oauth\\callback',
  'http://localhost /callback', 'http://localhost/callback\n', 'http://localhost/oauth/callback/x', 'http://localhost//callback', 'http://localhost',
  // custom and dangerous schemes
  'cursor://anysphere.cursor-mcp/oauth/callback', 'vscode://vscode.github-authentication/did-authenticate', 'javascript:alert(1)', 'data:text/html,x', 'file:///etc/passwd',
  // empty and oversized
  '', `https://claude.ai/api/mcp/auth_callback${'a'.repeat(2048)}`, `http://localhost/${'a'.repeat(2100)}`,
];

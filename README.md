<p align="center">
  <h1 align="center">MCPcube</h1>
  <p align="center"><i>A Model Context Protocol server for Roundcube 1.7.3</i></p>
</p>

---

MCPcube is a self-contained Roundcube plugin that exposes mailbox, contacts, and identity management through the [Model Context Protocol](https://modelcontextprotocol.io). It runs inside Roundcube and uses OAuth 2.1 Authorization Code with PKCE to authorize MCP clients.

Maintained by [Ra's al Ghul](https://alghul.com).

## Features

- Streamable HTTP MCP endpoint at `/mcp`
- OAuth 2.1 Authorization Code flow with mandatory PKCE `S256` and refresh tokens
- Protected Resource Metadata, authorization-server metadata, and dynamic client registration
- Scope-based authorization for mail, contacts, and identities
- Encrypted IMAP credential binding to authorized agents
- Read, write, and delete operations through a constrained PHP-subset execution environment
- Two-step, time-limited confirmation for destructive operations
- Agent revocation from Roundcube settings

## Requirements

- Roundcube 1.7.3
- [OIDC-cube](https://github.com/imrasalghul/oidc-cube), installed and enabled
- PHP 8.2 or newer with cURL, JSON, OpenSSL, and mbstring
- MySQL/MariaDB, PostgreSQL, or SQLite
- HTTPS for the Roundcube origin

OIDC-cube supplies the OIDC/Auth0 login flow used by MCPcube to bind an authenticated Roundcube session to an MCP authorization grant.

## Installation

Install MCPcube at `plugins/mcpcube` and install production dependencies:

```sh
composer install --no-dev
```

Enable `mcpcube` in Roundcube's `plugins` configuration. Create the database tables using the matching schema:

```sh
mysql roundcube < plugins/mcpcube/SQL/mysql.initial.sql
psql roundcube < plugins/mcpcube/SQL/postgres.initial.sql
sqlite3 /path/to/roundcube.db < plugins/mcpcube/SQL/sqlite.initial.sql
```

SQL table names must include the configured Roundcube `db_prefix`, when applicable.

## Configuration

Copy `config.inc.php.dist` to `config.inc.php`. Set `mcpcube_public_url` to the exact public HTTPS origin and generate an independent encryption key:

```sh
openssl rand -base64 32
```

Store the generated value in `mcpcube_encryption_key`. The key must remain outside the database and receive the same protection as other application secrets. Key loss or rotation invalidates existing agent credentials.

## MCP connection

Configure an MCP client with the Streamable HTTP endpoint:

```text
https://mail.example.com/mcp
```

The endpoint publishes OAuth protected-resource and authorization-server metadata. MCP clients discover the endpoints, register public clients, complete PKCE authorization, and exchange authorization codes automatically.

## Scopes

| Resource | Read | Write | Delete |
| --- | --- | --- | --- |
| Mail | `mail.read` | `mail.write` | `mail.delete` |
| Contacts | `contacts.read` | `contacts.write` | `contacts.delete` |
| Identities | `settings.read` | `settings.write` | `settings.delete` |

The default grant is read-only: `mail.read contacts.read settings.read`.

## Security

MCPcube requires HTTPS, exact redirect URI matching, PKCE `S256`, and encrypted credential storage. The executable MCP interface parses a restricted PHP subset into an allow-listed AST and evaluates it with a constrained interpreter; arbitrary PHP execution, includes, functions, classes, and dynamic method names are rejected.

Every destructive operation requires a separate confirmation call with an operation-bound HMAC token that expires after five minutes. Agent access can be revoked from **Settings → MCPcube Agents**.

## License

MCPcube is released under the [MIT License](LICENSE).

## Attribution

MCPcube is designed to run with [OIDC-cube](https://github.com/imrasalghul/oidc-cube) and uses [nikic/php-parser](https://github.com/nikic/PHP-Parser) for AST parsing. The project architecture is informed by Roundcube, the Model Context Protocol, and the upstream projects credited by OIDC-cube.

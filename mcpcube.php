<?php

declare(strict_types=1);

// Needed for plugin-only installations; Roundcube's root autoloader already
// loads this when the plugin was installed with Composer.
@include_once __DIR__ . '/vendor/autoload.php';

require_once __DIR__ . '/lib/mcpcube_crypto.php';
require_once __DIR__ . '/lib/mcpcube_mcp_protocol.php';
require_once __DIR__ . '/lib/mcpcube_auth_context.php';
require_once __DIR__ . '/lib/mcpcube_device_flow.php';
require_once __DIR__ . '/lib/mcpcube_oauth.php';
require_once __DIR__ . '/lib/mcpcube_sandbox.php';
require_once __DIR__ . '/lib/mcpcube_api_mail.php';
require_once __DIR__ . '/lib/mcpcube_api_contacts.php';
require_once __DIR__ . '/lib/mcpcube_api_identities.php';

/**
 * MCPcube: a Model Context Protocol server, implemented as a Roundcube
 * plugin, that lets an authorized AI agent read/send/delete mail, manage
 * contacts, and manage identities on the user's behalf.
 *
 * Architecture in one paragraph: an agent pairs via the RFC 8628 Device
 * Authorization Grant (see lib/mcpcube_device_flow.php) to get a 90-day
 * bearer token, tied server-side to an AES-256-GCM-encrypted copy of the
 * user's IMAP password (see lib/mcpcube_crypto.php and
 * lib/mcpcube_auth_context.php). Every MCP call re-authenticates from that
 * token, stateless, via rcmail::login(). The MCP surface itself is a single
 * "code mode" tool, execute_script (see lib/mcpcube_sandbox.php): instead of
 * exposing dozens of granular tools, the agent writes a short sandboxed
 * PHP-subset script that calls $mail/$contacts/$identities (see
 * lib/mcpcube_api_*.php), so multi-step tasks take one round trip instead of
 * many. Every scope check and the two-step delete-confirmation-token pattern
 * (lib/mcpcube_mcp_protocol.php's mcpcube_confirmation) live inside those API
 * facades, not the protocol layer, since they must apply identically however
 * a script chooses to call them.
 */
class mcpcube extends rcube_plugin
{
    public $task = 'login|settings';

    private const MCP_ACTION = 'plugin.mcpcube';
    private const PAIR_ACTION = 'plugin.mcpcube-pair';
    private const AGENTS_ACTION = 'plugin.mcpcube-agents';
    private const AGENTS_REVOKE_ACTION = 'plugin.mcpcube-agents-revoke';
    private const OAUTH_TOKEN_ACTION = 'plugin.mcpcube-oauth-token';
    private const OAUTH_AUTHORIZE_ACTION = 'plugin.mcpcube-oauth-authorize';
    private const OAUTH_REGISTER_ACTION = 'plugin.mcpcube-oauth-register';

    public function init(): void
    {
        $this->load_config('config.inc.php.dist');
        $this->load_config('config.inc.php');

        // Unauthenticated JSON API, reachable under task=login exactly like
        // this plugin's own MCP bearer-token auth requires - Roundcube's
        // session/login wall is deliberately bypassed here in favor of our
        // own per-request token check in mcpcube_auth_context.
        $this->register_action(self::MCP_ACTION, [$this, 'mcpEndpoint']);
        $this->register_action(self::OAUTH_TOKEN_ACTION, [$this, 'oauthToken']);
        $this->register_action(self::OAUTH_REGISTER_ACTION, [$this, 'oauthRegister']);
        $this->register_action(self::OAUTH_AUTHORIZE_ACTION, [$this, 'oauthAuthorize']);

        // Roundcube renders the login page before normal action dispatch when
        // there is no authenticated web session. Dispatch our independently
        // authenticated machine endpoints from startup so they are actually
        // reachable without weakening the settings/login wall.
        $this->add_hook('startup', [$this, 'startup']);

        // Human-facing pages, reachable under task=settings so Roundcube's
        // normal auth wall requires a real login first.
        $this->register_action(self::PAIR_ACTION, [$this, 'pair']);
        $this->register_action(self::AGENTS_ACTION, [$this, 'agentsSettings']);
        $this->register_action(self::AGENTS_REVOKE_ACTION, [$this, 'revokeAgent']);

        $this->add_hook('settings_actions', [$this, 'settingsActions']);
    }

    /** @param array<string, mixed> $args @return array<string, mixed> */
    public function startup(array $args): array
    {
        if (($args['task'] ?? '') !== 'login') {
            return $args;
        }

        match ($args['action'] ?? '') {
            self::MCP_ACTION => $this->mcpEndpoint(),
            self::OAUTH_TOKEN_ACTION => $this->oauthToken(),
            self::OAUTH_REGISTER_ACTION => $this->oauthRegister(),
            self::OAUTH_AUTHORIZE_ACTION => $this->oauthAuthorize(),
            default => $this->wellKnownDispatch(),
        };

        return $args;
    }

    public function oauthToken(): void { mcpcube_oauth::token(); }
    public function oauthRegister(): void { mcpcube_oauth::register(); }
    public function oauthAuthorize(): void { mcpcube_oauth::authorize(); }

    private function wellKnownDispatch(): void
    {
        $path = (string) parse_url((string) ($_SERVER['REQUEST_URI'] ?? ''), PHP_URL_PATH);
        if ($path === mcpcube_oauth::PRM_PATH) mcpcube_oauth::json(mcpcube_oauth::metadata(true));
        if ($path === mcpcube_oauth::AS_PATH) mcpcube_oauth::json(mcpcube_oauth::metadata());
    }

    public function pair(): void
    {
        (new mcpcube_device_flow())->consent();
    }

    /** @param array<string, mixed> $args @return array<string, mixed> */
    public function settingsActions(array $args): array
    {
        $args['actions'][] = [
            'action' => self::AGENTS_ACTION,
            'type' => 'link',
            'label' => 'MCPcube Agents',
            'title' => 'Manage AI agents authorized to access this mailbox',
        ];

        return $args;
    }

    // -----------------------------------------------------------
    // The MCP JSON-RPC endpoint itself
    // -----------------------------------------------------------

    public function mcpEndpoint(): void
    {
        $method = strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'));
        if ($method !== 'POST') {
            header('Allow: POST');
            $this->json_out(405, ['jsonrpc' => '2.0', 'id' => null, 'error' => ['code' => -32600, 'message' => 'Use POST']]);
        }

        $this->validate_origin();

        $token = mcpcube_auth_context::bearer_token_from_request();
        if ($token === null) {
            $this->oauth_challenge(false);
            $this->json_out(401, ['jsonrpc' => '2.0', 'id' => null, 'error' => [
                'code' => -32001,
                'message' => 'Missing bearer token. Use MCP OAuth authorization with PKCE.',
            ]]);
        }

        try {
            $ctx = mcpcube_auth_context::from_bearer_token($token);
        } catch (mcpcube_auth_error $e) {
            if ($e->httpStatus === 401) {
                $this->oauth_challenge(true);
            }
            $this->json_out($e->httpStatus, ['jsonrpc' => '2.0', 'id' => null, 'error' => ['code' => -32001, 'message' => $e->getMessage()]]);
        }

        $contentType = strtolower(trim(explode(';', (string) ($_SERVER['CONTENT_TYPE'] ?? ''))[0]));
        if ($contentType !== 'application/json') {
            $this->json_out(415, ['jsonrpc' => '2.0', 'id' => null, 'error' => ['code' => -32600, 'message' => 'Content-Type must be application/json']]);
        }

        if ((int) ($_SERVER['CONTENT_LENGTH'] ?? 0) > 1048576) {
            $this->json_out(413, ['jsonrpc' => '2.0', 'id' => null, 'error' => ['code' => -32600, 'message' => 'Request body is too large']]);
        }

        $raw = file_get_contents('php://input', false, null, 0, 1048577);
        $decoded = is_string($raw) ? json_decode($raw, true) : null;
        if (!is_array($decoded) || array_is_list($decoded)) {
            $this->json_out(400, ['jsonrpc' => '2.0', 'id' => null, 'error' => ['code' => -32700, 'message' => 'Invalid JSON']]);
        }

        $this->validate_protocol_header($decoded);

        $server = $this->build_mcp_server();
        $response = $server->handle($decoded, $ctx);
        if ($response === null) {
            $ctx->close();
            http_response_code(202);
            header('Cache-Control: no-store');
            exit;
        }

        $ctx->close();
        $this->json_out(200, $response);
    }

    private function oauth_challenge(bool $invalid): void
    {
        $base = rtrim((string) rcmail::get_instance()->config->get('mcpcube_public_url', ''), '/');
        $metadata = 'resource_metadata="' . $base . '/.well-known/oauth-protected-resource"';
        if ($invalid) {
            header('WWW-Authenticate: Bearer error="invalid_token", ' . $metadata);
            return;
        }

        header('WWW-Authenticate: Bearer ' . $metadata . ', scope="mail.read"');
    }

    private function validate_origin(): void
    {
        $origin = (string) ($_SERVER['HTTP_ORIGIN'] ?? '');
        if ($origin === '') {
            return;
        }

        $publicUrl = (string) rcmail::get_instance()->config->get('mcpcube_public_url', '');
        $parts = parse_url($publicUrl);
        $expected = is_array($parts) && isset($parts['scheme'], $parts['host'])
            ? strtolower($parts['scheme']) . '://' . strtolower($parts['host'])
                . (isset($parts['port']) ? ':' . (int) $parts['port'] : '')
            : '';

        if ($expected === '' || !hash_equals($expected, strtolower(rtrim($origin, '/')))) {
            $this->json_out(403, ['jsonrpc' => '2.0', 'id' => null, 'error' => ['code' => -32000, 'message' => 'Forbidden Origin']]);
        }
    }

    /** @param array<string, mixed> $request */
    private function validate_protocol_header(array $request): void
    {
        if (($request['method'] ?? null) === 'initialize') {
            return;
        }

        $version = (string) ($_SERVER['HTTP_MCP_PROTOCOL_VERSION'] ?? '2025-03-26');
        if (!in_array($version, mcpcube_mcp_server::SUPPORTED_PROTOCOL_VERSIONS, true)) {
            $this->json_out(400, ['jsonrpc' => '2.0', 'id' => $request['id'] ?? null, 'error' => [
                'code' => -32600,
                'message' => 'Unsupported MCP-Protocol-Version',
            ]]);
        }
    }

    private function build_mcp_server(): mcpcube_mcp_server
    {
        $server = new mcpcube_mcp_server();

        $server->register_tool(
            'execute_script',
            $this->execute_script_description(),
            [
                'type' => 'object',
                'properties' => [
                    'script' => [
                        'type' => 'string',
                        'description' => 'PHP-subset source. Do not include an opening <?php tag.',
                    ],
                ],
                'required' => ['script'],
            ],
            null, // no single blanket scope - each $mail/$contacts/$identities call checks its own
            function (array $args, mcpcube_auth_context $ctx): array {
                $script = (string) ($args['script'] ?? '');
                if (trim($script) === '') {
                    throw new mcpcube_tool_error('script must not be empty.');
                }

                $api = [
                    'mail' => new mcpcube_api_mail($ctx),
                    'contacts' => new mcpcube_api_contacts($ctx),
                    'identities' => new mcpcube_api_identities($ctx),
                ];

                try {
                    $result = mcpcube_sandbox::run($script, $api);
                } catch (mcpcube_sandbox_error | mcpcube_sandbox_runtime_error $e) {
                    // Surface the exact, actionable message (syntax error and
                    // line number, disallowed construct, budget exceeded,
                    // unknown API call, ...) back to the agent so it can fix
                    // and retry, rather than a generic failure.
                    throw new mcpcube_tool_error($e->getMessage());
                }

                return mcpcube_mcp_server::json_result([
                    'return' => $result['return'],
                    'echo' => $result['output'],
                ]);
            }
        );

        return $server;
    }

    private function execute_script_description(): string
    {
        return <<<'DESC'
            Run a short PHP-subset script and return its result. This is the ONLY tool: every mailbox action (read folders/mail, send mail, manage contacts, manage identities) happens by writing a script that calls methods on three pre-defined objects: $mail, $contacts, $identities. There is no separate "list_messages" or "send_message" tool - call $mail->listMessages(...) etc. from inside a script instead. Prefer writing one script that does several steps (loops, conditionals, multiple calls) over calling execute_script many times.

            Language: a safe subset of PHP. Supported: variables, arrays (incl. nested, associative), string interpolation, if/elseif/else, foreach/for/while/do-while, break/continue, try/catch/finally (catch (Exception $e) catches any error from the API; $e is an array with a "message" key, not a real exception object), return, echo, arithmetic/comparison/boolean operators, ternary, ??, isset/empty, (int)/(string)/(bool)/(array)/(float) casts. NOT supported: function/class declarations, closures, `new`, plain function calls like count()/strtoupper() (none exist in this sandbox - use loops/operators instead), include/require, eval, globals, static/superglobals, dynamic ($$x) or by-reference variables. A script using anything unsupported is rejected before it runs, with a line number, instead of partially executing. Scripts have a step count and a few-second wall-clock budget; keep loops bounded. Use `return $value;` to send a result back - it becomes this tool's JSON result (under the "return" key, alongside any "echo" output for debugging).

            Every call below only succeeds if this agent was granted the matching OAuth scope when the user approved it (mail.read/mail.write/mail.delete, contacts.read/write/delete, settings.read/write/delete); otherwise it throws a catchable error naming the missing scope.

            $mail:
              listFolders(): [{name, unread, total, delimiter}]
              listMessages(folder = 'INBOX', limit = 100, offset = 0): [{uid, folder, subject, from, to, date, size, seen, flagged, answered}], newest first
              getMessage(uid, folder = 'INBOX'): {uid, folder, subject, from, to, cc, date, message_id, body_text, attachments: [{filename, mimetype, size, part_id}]}
              getAttachment(uid, partId, folder = 'INBOX'): {filename, mimetype, size, part_id, content_base64}. partId comes from getMessage attachments. Pass this array into sendMessage; do not return a large content_base64 from the script.
              searchMessages(query, folder = 'INBOX', limit = 50): same shape as listMessages
              sendMessage(['to' => ..., 'subject' => ..., 'cc' => ?, 'bcc' => ?, 'body_text' => ?, 'body_html' => ?, 'in_reply_to' => ?, 'references' => ?, 'reply_uid' => ?, 'reply_folder' => ?, 'attachments' => ?]): {status, to, subject, message_id, saved, saved_to?, warning?, answered?, answered_uid?, answered_folder?}. attachments is a list of {filename, mimetype, content_base64}, such as the array returned by getAttachment. A successful send normally has saved:true and saved_to:'Sent'. If SMTP succeeds but the IMAP copy fails, status remains 'sent', saved is false, and warning says not to resend. A reply must pass reply_uid and reply_folder from getMessage, plus in_reply_to set to that message's message_id. After SMTP accepts the reply, the original message is stored with the IMAP \Answered flag so mail clients show it as answered. If reply_uid is omitted, the original is looked up by in_reply_to. answered is true when that flag was stored.
              forwardMessage(uid, folder, to, bodyText = null, subject = null): copies that message, including every attachment, to "to". Returns the sendMessage result plus forwarded_uid, attachments (count), and forwarded. Use this to forward an invoice PDF. Files stay on the server; the script does not handle the bytes. After SMTP accepts the forward, the original message is stored with the IMAP $Forwarded flag so mail clients show it as forwarded.
              moveMessage(uid, folder, targetFolder): {status, uid, from, to}
              flagMessage(uid, folder, flag, set = true): flag is one of SEEN|FLAGGED|ANSWERED|DRAFT
              createFolder(name, parent = null): {status, name}
              deleteMessage(uid, folder = 'INBOX', confirm = false, confirmationToken = null): call once WITHOUT confirm to get {status: 'confirmation_required', preview, confirmation_token}; a separate execute_script call with confirm: true and that exact token performs the deletion. uid may be a single int or an array of ints.
              emptyFolder(folder, confirm = false, confirmationToken = null): same two-step pattern; permanently removes every message in the folder.
              deleteFolder(name, confirm = false, confirmationToken = null): same two-step pattern.

            $contacts:
              listContacts(search = null, limit = 50, offset = 0): [{id, name, email}]
              getContact(id): {id, name, email, firstname, surname, organization, phone, notes}
              createContact(['name' => ?, 'firstname' => ?, 'surname' => ?, 'organization' => ?, 'email' => ..., 'phone' => ?, 'notes' => ?]): {status, id}
              updateContact(id, fields): same fields as createContact, {status, id}
              deleteContact(id, confirm = false, confirmationToken = null): two-step pattern like deleteMessage; id may be a single id or an array of ids.

            $identities:
              whoami(): {username, primary_email, agent_id, agent_label, scopes, server} - always available, no scope required.
              listIdentities(): [{id, name, email, is_default}]
              getIdentity(id): {id, name, email, is_default, organization, reply_to, bcc, signature}
              createIdentity(['name' => ..., 'email' => ..., 'organization' => ?, 'reply_to' => ?, 'bcc' => ?, 'signature' => ?]): {status, id}
              updateIdentity(id, fields): same fields as createIdentity, {status, id}
              deleteIdentity(id, confirm = false, confirmationToken = null): two-step pattern like deleteMessage.

            Example - collect unread subjects from the inbox in one round trip:

              $unread = [];
              foreach ($mail->listMessages('INBOX', 100) as $m) {
                  if (!$m['seen']) {
                      $unread[] = $m['subject'];
                  }
              }
              return $unread;

            Example - two-step delete (call execute_script twice):

              // call 1:
              return $mail->deleteMessage(12345, 'INBOX');
              // inspect the returned preview + confirmation_token, then call 2:
              return $mail->deleteMessage(12345, 'INBOX', true, '<confirmation_token from call 1>');
            DESC;
    }

    /** @param array<int|string, mixed>|object $body */
    private function json_out(int $status, array|object $body): never
    {
        http_response_code($status);
        header('Content-Type: application/json');
        header('Cache-Control: no-store');
        echo json_encode($body, JSON_UNESCAPED_SLASHES);
        exit;
    }

    // -----------------------------------------------------------
    // Settings: list / revoke authorized agents
    // -----------------------------------------------------------

    public function agentsSettings(): void
    {
        $rcmail = rcmail::get_instance();
        $this->register_output_handler('plugin.body', [$this, 'agentsSettingsBody']);
        $rcmail->output->set_pagetitle('MCPcube Agents');
        $rcmail->output->send('plugin');
    }

    public function agentsSettingsBody(): string
    {
        $rcmail = rcmail::get_instance();
        $db = $rcmail->get_dbh();
        $table = $db->table_name('mcpcube_agents', true);
        $result = $db->query(
            "SELECT `id`, `label`, `scopes`, `created`, `expires`, `last_used`, `revoked` FROM {$table}"
                . ' WHERE `user_id` = ? ORDER BY `created` DESC',
            (int) $rcmail->user->ID
        );

        $rows = '';
        while (is_array($agent = $db->fetch_assoc($result))) {
            $status = $agent['revoked'] !== null
                ? 'Revoked'
                : (strtotime((string) $agent['expires']) < time() ? 'Expired' : 'Active');

            $revokeButton = $agent['revoked'] !== null ? '' : html::tag('form', [
                'method' => 'post',
                'action' => $rcmail->url(['_task' => 'settings', '_action' => self::AGENTS_REVOKE_ACTION]),
                'style' => 'display:inline',
            ], html::tag('input', ['type' => 'hidden', 'name' => '_token', 'value' => $rcmail->get_request_token()])
                . html::tag('input', ['type' => 'hidden', 'name' => '_id', 'value' => (string) $agent['id']])
                . html::tag('button', ['type' => 'submit', 'class' => 'button'], html::quote('Revoke')));

            $rows .= html::tag('tr', [], ''
                . html::tag('td', [], html::quote((string) $agent['label']))
                . html::tag('td', [], html::quote(str_replace(',', ', ', (string) $agent['scopes'])))
                . html::tag('td', [], html::quote((string) $agent['created']))
                . html::tag('td', [], html::quote((string) $agent['expires']))
                . html::tag('td', [], html::quote((string) ($agent['last_used'] ?? 'never')))
                . html::tag('td', [], html::quote($status))
                . html::tag('td', [], $revokeButton));
        }

        if ($rows === '') {
            $rows = html::tag('tr', [], html::tag('td', ['colspan' => 7], html::quote('No agents have been authorized yet.')));
        }

        $tableHtml = html::tag('table', ['class' => 'records-table'],
            html::tag('thead', [], html::tag('tr', [], ''
                . html::tag('th', [], html::quote('Agent'))
                . html::tag('th', [], html::quote('Scopes'))
                . html::tag('th', [], html::quote('Authorized'))
                . html::tag('th', [], html::quote('Expires'))
                . html::tag('th', [], html::quote('Last used'))
                . html::tag('th', [], html::quote('Status'))
                . html::tag('th', [], '')))
            . html::tag('tbody', [], $rows));

        $body = html::tag('h2', [], html::quote('MCPcube Agents'))
            . html::p([], html::quote(
                'AI agents currently (or previously) authorized to access this mailbox via MCPcube. '
                    . 'Revoking an agent immediately invalidates its access; the agent must be paired again afterward.'
            ))
            . $tableHtml;

        return html::div(['class' => 'boxcontent formcontent'], $body);
    }

    public function revokeAgent(): void
    {
        $rcmail = rcmail::get_instance();

        if (!$rcmail->check_request(rcube_utils::INPUT_POST)) {
            $rcmail->output->show_message('This request could not be verified.', 'error');
            $this->agentsSettings();
            return;
        }

        $id = (int) rcube_utils::get_input_value('_id', rcube_utils::INPUT_POST);
        $db = $rcmail->get_dbh();
        $table = $db->table_name('mcpcube_agents', true);
        $db->query(
            "UPDATE {$table} SET `revoked` = " . $db->now() . ' WHERE `id` = ? AND `user_id` = ? AND `revoked` IS NULL',
            $id,
            (int) $rcmail->user->ID
        );

        $rcmail->output->show_message('Agent revoked.', 'confirmation');
        $rcmail->output->command('redirect', $rcmail->url(['_task' => 'settings', '_action' => self::AGENTS_ACTION]));
    }

    private function register_output_handler(string $name, callable $callback): void
    {
        rcmail::get_instance()->output->add_handler($name, $callback);
    }
}

<?php

declare(strict_types=1);

/**
 * RFC 8628 OAuth 2.0 Device Authorization Grant, adapted for pairing an AI
 * agent to a Roundcube mailbox instead of a browserless TV/CLI app to a
 * generic OAuth provider.
 *
 *   1. Agent calls device_authorize() (task=login, unauthenticated) and gets
 *      back {device_code, user_code, verification_uri_complete, ...}. It
 *      shows the user verification_uri_complete as a login link (and/or the
 *      short user_code, for a user who prefers to type it in manually).
 *   2. The user opens the link. Because it targets task=settings, Roundcube's
 *      own auth wall makes them log in first if they aren't already, then
 *      consent() renders the approve/deny screen.
 *   3. On approve, the plugin captures the already-authenticated session's
 *      IMAP password via $rcmail->decrypt($_SESSION['password']) - the same
 *      mechanism Roundcube itself uses to keep reconnecting IMAP during a
 *      session - encrypts it long-term with mcpcube_crypto, creates the
 *      mcpcube_agents row, and generates a bearer token.
 *   4. The agent, meanwhile, has been polling device_token() every
 *      `interval` seconds. Once approved, it receives the bearer token
 *      exactly once and uses it as `Authorization: Bearer <token>` for every
 *      subsequent MCP call, for up to mcpcube_token_ttl (default 90 days).
 */
final class mcpcube_device_flow
{
    private const RATE_LIMIT_CACHE = 'mcpcube_ratelimit';

    /** @return array<string, string> scope => human description, for the consent screen */
    public static function scope_descriptions(): array
    {
        return [
            'mail.read' => 'Read your mail folders and messages',
            'mail.write' => 'Send mail on your behalf, and organize messages (move, flag, create folders)',
            'mail.delete' => 'Permanently delete messages and folders (a confirmation step is always required first)',
            'contacts.read' => 'Read your contacts',
            'contacts.write' => 'Create and edit contacts',
            'contacts.delete' => 'Permanently delete contacts (a confirmation step is always required first)',
            'settings.read' => 'Read your identities and mail settings',
            'settings.write' => 'Create and edit identities and mail settings',
            'settings.delete' => 'Permanently delete identities (a confirmation step is always required first)',
        ];
    }

    // ---------------------------------------------------------------
    // Agent-facing endpoints (task=login, unauthenticated JSON API)
    // ---------------------------------------------------------------

    public function device_authorize(): void
    {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            self::json_response(405, ['error' => 'invalid_request', 'error_description' => 'Use POST']);
        }

        self::enforce_rate_limit('authorize');

        $rcmail = rcmail::get_instance();
        $input = self::read_json_or_form_body();

        $label = trim((string) ($input['client_label'] ?? $input['client_name'] ?? 'AI agent'));
        $label = preg_replace('/[\x00-\x1F\x7F]/', '', $label) ?? 'AI agent';
        if ($label === '') {
            $label = 'AI agent';
        }
        $label = mb_substr($label, 0, 120);

        $available = (array) $rcmail->config->get('mcpcube_available_scopes', []);
        $requestedRaw = $input['scope'] ?? $input['scopes'] ?? null;
        if (is_string($requestedRaw) && trim($requestedRaw) !== '') {
            $requested = preg_split('/[\s,]+/', trim($requestedRaw), -1, PREG_SPLIT_NO_EMPTY) ?: [];
        } elseif (is_array($requestedRaw) && $requestedRaw !== []) {
            $requested = array_map('strval', $requestedRaw);
        } else {
            $requested = (array) $rcmail->config->get('mcpcube_default_scopes', $available);
        }

        $requested = array_values(array_unique($requested));
        $unknown = array_values(array_diff($requested, $available));
        $scopes = array_values(array_intersect($requested, $available));
        if ($scopes === [] || $unknown !== []) {
            self::json_response(400, ['error' => 'invalid_scope', 'error_description' => 'One or more requested scopes are invalid']);
        }

        $ttl = max(60, (int) $rcmail->config->get('mcpcube_device_code_ttl', 600));
        $interval = max(1, (int) $rcmail->config->get('mcpcube_poll_interval', 5));
        $db = $rcmail->get_dbh();
        $table = $db->table_name('mcpcube_device_codes', true);

        $deviceCode = mcpcube_crypto::random_hex(32);
        $userCode = self::unique_user_code($db, $table);

        $result = $db->query(
            "INSERT INTO {$table} (`device_code`, `user_code`, `client_label`, `requested_scopes`,"
                . ' `status`, `created`, `expires`, `poll_interval`)'
                . ' VALUES (?, ?, ?, ?, ' . $db->quote('pending') . ', ' . $db->now() . ', ' . $db->now($ttl) . ', ?)',
            $deviceCode,
            $userCode,
            $label,
            implode(',', $scopes),
            $interval
        );

        if ($db->is_error($result)) {
            self::json_response(500, ['error' => 'server_error']);
        }

        $verificationUri = self::pair_url();

        self::json_response(200, [
            'device_code' => $deviceCode,
            'user_code' => $userCode,
            'verification_uri' => $verificationUri,
            'verification_uri_complete' => $verificationUri . '&user_code=' . rawurlencode($userCode),
            'expires_in' => $ttl,
            'interval' => $interval,
            'scope' => implode(' ', $scopes),
        ]);
    }

    public function device_token(): void
    {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            self::json_response(405, ['error' => 'invalid_request', 'error_description' => 'Use POST']);
        }

        self::enforce_rate_limit('token');

        $rcmail = rcmail::get_instance();
        $input = self::read_json_or_form_body();
        $deviceCode = (string) ($input['device_code'] ?? '');

        if ($deviceCode === '' || !preg_match('/\A[a-f0-9]{64}\z/', $deviceCode)) {
            self::json_response(400, ['error' => 'invalid_grant']);
        }

        $db = $rcmail->get_dbh();
        $table = $db->table_name('mcpcube_device_codes', true);
        $result = $db->query("SELECT * FROM {$table} WHERE `device_code` = ?", $deviceCode);
        $row = $db->is_error($result) ? null : $db->fetch_assoc($result);

        if (!is_array($row)) {
            self::json_response(400, ['error' => 'invalid_grant']);
        }

        if (strtotime((string) $row['expires']) < time()) {
            $db->query("DELETE FROM {$table} WHERE `id` = ?", $row['id']);
            self::json_response(400, ['error' => 'expired_token']);
        }

        $interval = max(1, (int) $row['poll_interval']);
        if (is_string($row['last_polled'] ?? null) && (string) $row['last_polled'] !== ''
            && (time() - strtotime((string) $row['last_polled'])) < $interval
        ) {
            $db->query(
                "UPDATE {$table} SET `poll_interval` = ? WHERE `id` = ?",
                min(300, $interval + 5),
                $row['id']
            );
            self::json_response(400, ['error' => 'slow_down']);
        }
        $db->query("UPDATE {$table} SET `last_polled` = " . $db->now() . ' WHERE `id` = ?', $row['id']);

        switch ($row['status']) {
            case 'pending':
                self::json_response(400, ['error' => 'authorization_pending']);
                // no break, json_response exits
            case 'denied':
                $db->query("DELETE FROM {$table} WHERE `id` = ?", $row['id']);
                self::json_response(400, ['error' => 'access_denied']);
                // no break
            case 'approved':
                $claim = $db->query(
                    "UPDATE {$table} SET `status` = " . $db->quote('consumed')
                        . ' WHERE `id` = ? AND `status` = ' . $db->quote('approved'),
                    $row['id']
                );
                if ($db->is_error($claim) || $db->affected_rows($claim) !== 1) {
                    self::json_response(400, ['error' => 'invalid_grant', 'error_description' => 'This device_code was already claimed']);
                }
                $rawToken = mcpcube_crypto::decrypt_secret(
                    (string) $row['pending_token_ciphertext'],
                    'device-token:' . $deviceCode,
                    mcpcube_crypto::config_key()
                );
                // Single-use: the row is removed the moment the token is
                // successfully handed to the agent, whether or not this is
                // the very first poll after approval.
                $db->query("DELETE FROM {$table} WHERE `id` = ?", $row['id']);

                if ($rawToken === null) {
                    self::json_response(500, ['error' => 'server_error']);
                }

                self::json_response(200, [
                    'access_token' => $rawToken,
                    'token_type' => 'Bearer',
                    'expires_in' => max(60, (int) $rcmail->config->get('mcpcube_token_ttl', 90 * 86400)),
                    'scope' => str_replace(',', ' ', (string) $row['requested_scopes']),
                ]);
                // no break
            default: // 'consumed', or anything unexpected
                self::json_response(400, ['error' => 'invalid_grant', 'error_description' => 'This device_code was already claimed']);
        }
    }

    // ---------------------------------------------------------------
    // User-facing consent page (task=settings, requires an authenticated
    // Roundcube session - Roundcube's own auth wall enforces that for us)
    // ---------------------------------------------------------------

    public function consent(): void
    {
        $rcmail = rcmail::get_instance();

        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $this->consent_submit();
            return;
        }

        $userCode = mcpcube_crypto::normalize_user_code((string) rcube_utils::get_input_value('user_code', rcube_utils::INPUT_GET));
        $row = $userCode === '' ? null : $this->find_pending_device_code($userCode);

        $this->register_handler('plugin.body', function () use ($row, $userCode) {
            return $this->render_consent_body($row, $userCode);
        });
        $rcmail->output->set_pagetitle('Authorize agent');
        $rcmail->output->send('plugin');
    }

    private function consent_submit(): void
    {
        $rcmail = rcmail::get_instance();

        if (!$rcmail->check_request(rcube_utils::INPUT_POST)) {
            $rcmail->output->show_message('This request could not be verified. Please try the link again.', 'error');
            $this->consent();
            return;
        }

        $userCode = mcpcube_crypto::normalize_user_code((string) rcube_utils::get_input_value('_user_code', rcube_utils::INPUT_POST));
        $decision = (string) rcube_utils::get_input_value('_decision', rcube_utils::INPUT_POST);
        $row = $userCode === '' ? null : $this->find_pending_device_code($userCode);

        $db = $rcmail->get_dbh();
        $table = $db->table_name('mcpcube_device_codes', true);

        if ($row === null) {
            $rcmail->output->show_message('This login link has expired or was already used. Ask the agent for a new one.', 'error');
            $this->consent();
            return;
        }

        if (!in_array($decision, ['approve', 'deny'], true)) {
            $rcmail->output->show_message('Invalid approval decision.', 'error');
            $this->consent();
            return;
        }

        if ($decision === 'deny') {
            $db->query("UPDATE {$table} SET `status` = " . $db->quote('denied')
                . ' WHERE `id` = ? AND `status` = ' . $db->quote('pending'), $row['id']);
            if ($this->redirect_oauth_client($row, ['error' => 'access_denied'])) {
                return;
            }
            $rcmail->output->show_message('Denied. The agent will not be given access.', 'confirmation');
            $this->render_done('Access denied. You can close this window.');
            return;
        }

        try {
            $oauthCode = $this->approve($row);
        } catch (Throwable $e) {
            rcube::raise_error([
                'code' => 500,
                'type' => 'php',
                'message' => 'MCPcube consent approval failed: ' . preg_replace('/[\r\n]+/', ' ', $e->getMessage()),
            ], true, false);
            $rcmail->output->show_message('Could not authorize the agent. Please try again.', 'error');
            $this->consent();
            return;
        }

        if (is_string($oauthCode) && $oauthCode !== '') {
            $this->redirect_oauth_client($row, ['code' => $oauthCode]);
            $this->render_done('Approved, but the client redirect URI was missing. Return to Cursor and try connecting again.');
            return;
        }

        $this->render_done('Approved. You can return to your agent - it will finish connecting automatically within a few seconds.');
    }

    /**
     * Send the browser back to the MCP client's redirect_uri with an
     * authorization code (or OAuth error). Returns false when this pairing
     * is device-flow only and has no client callback.
     *
     * @param array<string, mixed> $row
     * @param array<string, scalar|null> $params
     */
    private function redirect_oauth_client(array $row, array $params): bool
    {
        $requestId = trim((string) ($row['oauth_request_id'] ?? ''));
        if ($requestId === '') {
            return false;
        }

        $db = rcmail::get_instance()->get_dbh();
        $oauthTable = $db->table_name('mcpcube_oauth_requests', true);
        $requestResult = $db->query("SELECT * FROM {$oauthTable} WHERE `request_id` = ?", $requestId);
        $request = $db->is_error($requestResult) ? null : $db->fetch_assoc($requestResult);
        if (!is_array($request)) {
            return false;
        }

        $redirect = (string) $request['redirect_uri'];
        if ($redirect === '' || !mcpcube_oauth::valid_redirect($redirect)) {
            return false;
        }

        if (!array_key_exists('state', $params)) {
            $params['state'] = (string) $request['state'];
        }

        mcpcube_oauth::redirect_to_client($redirect, $params);
    }

    /** @param array<string, mixed> $row */
    private function approve(array $row): ?string
    {
        $rcmail = rcmail::get_instance();
        $db = $rcmail->get_dbh();

        if (!$rcmail->user || !$rcmail->user->ID) {
            throw new RuntimeException('No authenticated Roundcube user in session');
        }

        $userId = (int) $rcmail->user->ID;
        $maxAgents = max(1, (int) $rcmail->config->get('mcpcube_max_agents_per_user', 10));
        $agentsTable = $db->table_name('mcpcube_agents', true);
        $deviceTable = $db->table_name('mcpcube_device_codes', true);

        if (!$db->startTransaction()) {
            throw new RuntimeException('Could not start approval transaction');
        }

        try {
            $claim = $db->query(
                "UPDATE {$deviceTable} SET `status` = " . $db->quote('approving')
                    . ' WHERE `id` = ? AND `status` = ' . $db->quote('pending'),
                $row['id']
            );
            if ($db->is_error($claim) || $db->affected_rows($claim) !== 1) {
                throw new RuntimeException('This device code was already approved or denied');
            }

            $countResult = $db->query(
                "SELECT COUNT(*) AS c FROM {$agentsTable} WHERE `user_id` = ? AND `revoked` IS NULL AND `expires` > " . $db->now(),
                $userId
            );
            $countRow = $db->fetch_assoc($countResult);
            if (is_array($countRow) && (int) $countRow['c'] >= $maxAgents) {
                throw new RuntimeException("User already has the maximum of {$maxAgents} authorized agents");
            }

            // Roundcube itself keeps the IMAP password symmetric-encrypted in
            // the session so storage can reconnect without prompting again.
            $sessionPassword = is_string($_SESSION['password'] ?? null) ? $_SESSION['password'] : null;
            $password = $sessionPassword !== null ? $rcmail->decrypt($sessionPassword) : null;
            if (!is_string($password) || $password === '') {
                throw new RuntimeException('Could not read the current session\'s IMAP password');
            }

            $key = mcpcube_crypto::config_key();
            $credentialKey = mcpcube_crypto::random_hex(32);
            $encryptedPassword = mcpcube_crypto::encrypt_secret($password, 'imap-password:' . $credentialKey, $key);
            $rawToken = mcpcube_crypto::random_bearer_token();
            $tokenHash = mcpcube_crypto::hash_token($rawToken);
            $ttl = max(60, (int) $rcmail->config->get('mcpcube_token_ttl', 90 * 86400));
            $host = is_string($_SESSION['storage_host'] ?? null) ? $_SESSION['storage_host'] : null;

            $insertResult = $db->query(
                "INSERT INTO {$agentsTable} (`user_id`, `credential_key`, `token_hash`, `encrypted_password`,"
                    . ' `imap_host`, `label`, `scopes`, `created`, `expires`)'
                    . ' VALUES (?, ?, ?, ?, ?, ?, ?, ' . $db->now() . ', ' . $db->now($ttl) . ')',
                $userId,
                $credentialKey,
                $tokenHash,
                $encryptedPassword,
                $host,
                (string) $row['client_label'],
                (string) $row['requested_scopes']
            );

            if ($db->is_error($insertResult)) {
                throw new RuntimeException('Could not store the new agent credential');
            }

            $wrappedToken = mcpcube_crypto::encrypt_secret($rawToken, 'device-token:' . $row['device_code'], $key);
            $update = $db->query(
                "UPDATE {$deviceTable} SET `status` = " . $db->quote('approved')
                    . ', `user_id` = ?, `pending_token_ciphertext` = ? WHERE `id` = ? AND `status` = ' . $db->quote('approving'),
                $userId,
                $wrappedToken,
                $row['id']
            );
            if ($db->is_error($update) || $db->affected_rows($update) !== 1) {
                throw new RuntimeException('Could not finalize agent approval');
            }

            $oauthCode = null;
            if (!empty($row['oauth_request_id'])) {
                $oauthTable = $db->table_name('mcpcube_oauth_requests', true);
                $requestResult = $db->query("SELECT * FROM {$oauthTable} WHERE `request_id` = ?", $row['oauth_request_id']);
                $request = $db->fetch_assoc($requestResult);
                if (!is_array($request)) {
                    throw new RuntimeException('Could not load the OAuth authorization request');
                }

                $oauthCode = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
                $codeTable = $db->table_name('mcpcube_oauth_codes', true);
                $ciphertext = mcpcube_crypto::encrypt_secret($rawToken, 'oauth-access:' . $row['oauth_request_id'], $key);
                $codeTtl = max(60, (int) $rcmail->config->get('mcpcube_oauth_code_ttl', 600));
                $codeInsert = $db->query(
                    "INSERT INTO {$codeTable} (`code_hash`,`request_id`,`client_id`,`redirect_uri`,`code_challenge`,`scope`,`access_ciphertext`,`access_expires`,`expires`,`used`)"
                        . ' VALUES (?, ?, ?, ?, ?, ?, ?, ?, ' . $db->now($codeTtl) . ', 0)',
                    hash('sha256', $oauthCode),
                    $row['oauth_request_id'],
                    $request['client_id'],
                    $request['redirect_uri'],
                    $request['code_challenge'],
                    $request['scope'],
                    $ciphertext,
                    max(60, (int) $rcmail->config->get('mcpcube_oauth_access_ttl', 90 * 86400))
                );
                if ($db->is_error($codeInsert)) {
                    throw new RuntimeException('Could not store the OAuth authorization code');
                }
            }

            if (!$db->endTransaction()) {
                throw new RuntimeException('Could not commit agent approval');
            }

            return $oauthCode;
        } catch (Throwable $e) {
            $db->rollbackTransaction();
            throw $e;
        }
    }

    /** @return array<string, mixed>|null */
    private function find_pending_device_code(string $userCode): ?array
    {
        $db = rcmail::get_instance()->get_dbh();
        $table = $db->table_name('mcpcube_device_codes', true);
        $result = $db->query(
            "SELECT * FROM {$table} WHERE `user_code` = ? AND `status` = " . $db->quote('pending')
                . ' AND `expires` > ' . $db->now(),
            $userCode
        );
        $row = $db->is_error($result) ? null : $db->fetch_assoc($result);
        return is_array($row) ? $row : null;
    }

    /** @param array<string, mixed>|null $row */
    private function render_consent_body(?array $row, string $userCode): string
    {
        if ($row === null) {
            return html::div(['class' => 'boxcontent formcontent'],
                html::tag('h2', [], html::quote('Authorize agent'))
                . html::p(['class' => 'notice'], html::quote(
                    $userCode === ''
                        ? 'Enter the code shown by your agent to continue.'
                        : 'This login link has expired or was already used. Ask the agent for a new one.'
                ))
                . $this->render_code_entry_form());
        }

        $descriptions = self::scope_descriptions();
        $scopeItems = '';
        foreach (explode(',', (string) $row['requested_scopes']) as $scope) {
            $scope = trim($scope);
            if ($scope === '') {
                continue;
            }
            $scopeItems .= html::tag('li', [], html::quote($descriptions[$scope] ?? $scope));
        }

        $rcmail = rcmail::get_instance();
        $form = html::tag('input', ['type' => 'hidden', 'name' => '_token', 'value' => $rcmail->get_request_token()])
            . html::tag('input', ['type' => 'hidden', 'name' => '_user_code', 'value' => (string) $row['user_code']])
            . html::tag('button', ['type' => 'submit', 'name' => '_decision', 'value' => 'approve', 'class' => 'button mainaction'], html::quote('Approve'))
            . ' '
            . html::tag('button', ['type' => 'submit', 'name' => '_decision', 'value' => 'deny', 'class' => 'button'], html::quote('Deny'));

        $body = html::tag('h2', [], html::quote('Authorize agent'))
            . html::p([], html::quote('"' . (string) $row['client_label'] . '" wants to connect to your mailbox for the next 30 days. It will be able to:'))
            . html::tag('ul', [], $scopeItems)
            . html::p(['class' => 'notice'], html::quote('Any delete action will always show a preview and ask again before anything is permanently removed.'))
            . html::tag('form', ['method' => 'post', 'action' => $rcmail->url(['_task' => 'settings', '_action' => 'plugin.mcpcube-pair'])], $form);

        return html::div(['class' => 'boxcontent formcontent'], $body);
    }

    private function render_code_entry_form(): string
    {
        $rcmail = rcmail::get_instance();
        return html::tag('form', ['method' => 'get', 'action' => $rcmail->url(['_task' => 'settings', '_action' => 'plugin.mcpcube-pair'])],
            html::tag('input', ['type' => 'text', 'name' => 'user_code', 'placeholder' => 'XXXX-XXXX', 'autocapitalize' => 'characters'])
            . ' '
            . html::tag('button', ['type' => 'submit', 'class' => 'button mainaction'], html::quote('Continue')));
    }

    private function render_done(string $message): void
    {
        $rcmail = rcmail::get_instance();
        $this->register_handler('plugin.body', fn () => html::div(['class' => 'boxcontent formcontent'],
            html::tag('h2', [], html::quote('MCPcube')) . html::p([], html::quote($message))));
        $rcmail->output->set_pagetitle('MCPcube');
        $rcmail->output->send('plugin');
    }

    private function register_handler(string $name, callable $callback): void
    {
        rcmail::get_instance()->output->add_handler($name, $callback);
    }

    // ---------------------------------------------------------------
    // Shared helpers
    // ---------------------------------------------------------------

    private static function unique_user_code(rcube_db $db, string $table): string
    {
        for ($i = 0; $i < 20; $i++) {
            $code = mcpcube_crypto::random_user_code();
            $result = $db->query("SELECT 1 FROM {$table} WHERE `user_code` = ?", $code);
            if (!$db->fetch_assoc($result)) {
                return $code;
            }
        }
        throw new RuntimeException('Could not generate a unique device user_code');
    }

    private static function pair_url(): string
    {
        $rcmail = rcmail::get_instance();
        $base = rtrim((string) $rcmail->config->get('mcpcube_public_url', ''), '/');
        $parts = parse_url($base);
        if ($base === '' || !is_array($parts) || strtolower((string) ($parts['scheme'] ?? '')) !== 'https'
            || empty($parts['host']) || isset($parts['user'], $parts['pass']) || isset($parts['query']) || isset($parts['fragment'])
        ) {
            throw new RuntimeException('mcpcube_public_url must be set to an absolute https:// URL');
        }

        return $base . '/?_task=settings&_action=plugin.mcpcube-pair';
    }

    /** @return array<string, mixed> */
    private static function read_json_or_form_body(): array
    {
        $contentType = (string) ($_SERVER['CONTENT_TYPE'] ?? '');
        if (stripos($contentType, 'application/json') !== false) {
            $raw = file_get_contents('php://input', false, null, 0, 65536);
            $decoded = is_string($raw) ? json_decode($raw, true) : null;
            return is_array($decoded) ? $decoded : [];
        }

        return $_POST;
    }

    private static function enforce_rate_limit(string $bucket): void
    {
        $rcmail = rcmail::get_instance();
        $max = max(1, (int) $rcmail->config->get('mcpcube_rate_limit_max', 30));
        $window = max(1, (int) $rcmail->config->get('mcpcube_rate_limit_window', 60));
        $ip = (string) rcube_utils::remote_addr();
        $cache = $rcmail->get_cache_shared(self::RATE_LIMIT_CACHE);
        if ($cache === null) {
            self::json_response(503, ['error' => 'temporarily_unavailable', 'error_description' => 'Rate limiting is unavailable']);
        }
        $key = $bucket . ':' . $ip;
        $count = (int) ($cache->get($key) ?? 0);

        if ($count >= $max) {
            self::json_response(429, ['error' => 'slow_down', 'error_description' => 'Too many requests']);
        }

        $cache->set($key, $count + 1);
    }

    /** @param array<string, mixed> $body */
    private static function json_response(int $status, array $body): never
    {
        http_response_code($status);
        header('Content-Type: application/json');
        header('Cache-Control: no-store');
        echo json_encode($body, JSON_UNESCAPED_SLASHES);
        exit;
    }
}

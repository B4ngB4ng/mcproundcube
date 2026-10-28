<?php

declare(strict_types=1);

/** Thrown when a request's bearer token is missing, invalid, expired, revoked, or unusable. */
final class mcpcube_auth_error extends RuntimeException
{
    public function __construct(public readonly string $errorCode, string $message, public readonly int $httpStatus = 401)
    {
        parent::__construct($message);
    }
}

/**
 * Resolves an incoming `Authorization: Bearer <token>` header to an
 * authenticated, per-request Roundcube user/IMAP context.
 *
 * Every MCP tool call re-authenticates from scratch: there is no server-side
 * session kept between calls (see mcpcube_mcp_server's doc comment for why).
 * The stored, AES-256-GCM-encrypted IMAP password is decrypted here and
 * handed straight to Roundcube's own `rcmail::login()`, the exact same entry
 * point Roundcube's normal login form POST uses - so storage init, SMTP
 * config, plugin `login_after` hooks, and login logging all behave exactly
 * as they would for an interactive login. The cost is one IMAP login per API
 * call; a future version could cache a short-lived authenticated connection
 * per bearer token to avoid that, but v1 favors correctness/simplicity.
 */
final class mcpcube_auth_context
{
    private bool $closed = false;

    /** @param list<string> $scopes */
    private function __construct(
        private readonly rcmail $rcmail,
        private readonly int $agentId,
        private readonly int $userId,
        private readonly string $credentialKey,
        private readonly string $tokenHash,
        private readonly string $label,
        private readonly array $scopes,
        private readonly array $originalSession,
    ) {
    }

    public static function from_bearer_token(string $token): self
    {
        if (strlen($token) > 200) {
            throw new mcpcube_auth_error('invalid_token', 'Malformed bearer token');
        }

        if (str_starts_with($token, 'mcpcube_at_')) {
            $row = self::row_for_access_token($token);
        } elseif (str_starts_with($token, 'mcpcube_pat_')) {
            $row = self::row_for_pat($token);
        } else {
            throw new mcpcube_auth_error('invalid_token', 'Malformed bearer token');
        }

        return self::open_agent_session($row);
    }

    /** @return array<string, mixed> */
    private static function row_for_pat(string $token): array
    {
        $rcmail = rcmail::get_instance();
        $db = $rcmail->get_dbh();
        $agents = $db->table_name('mcpcube_agents', true);
        $users = $db->table_name('users', true);
        $result = $db->query(
            "SELECT a.`id`, a.`user_id`, a.`credential_key`, a.`encrypted_password`, a.`imap_host`,"
                . ' a.`label`, a.`scopes`, a.`expires`, a.`revoked`, a.`token_hash`, u.`username`'
                . " FROM {$agents} a JOIN {$users} u ON (u.`user_id` = a.`user_id`)"
                . ' WHERE a.`token_hash` = ?',
            mcpcube_crypto::hash_token($token)
        );
        if ($db->is_error($result)) {
            throw new mcpcube_auth_error('server_error', 'Agent lookup failed', 500);
        }

        $row = $db->fetch_assoc($result);
        if (!is_array($row)) {
            throw new mcpcube_auth_error('invalid_token', 'This bearer token is not recognized. It may have been revoked; ask the user for a new login link.');
        }
        if ($row['revoked'] !== null) {
            throw new mcpcube_auth_error('invalid_token', 'This agent has been revoked by the user.');
        }
        if (strtotime((string) $row['expires']) < time()) {
            throw new mcpcube_auth_error('invalid_token', 'This agent\'s authorization has expired. Ask the user for a new login link.');
        }

        return $row;
    }

    /** @return array<string, mixed> */
    private static function row_for_access_token(string $token): array
    {
        $db = rcmail::get_instance()->get_dbh();
        $tokens = $db->table_name('mcpcube_oauth_tokens', true);
        $agents = $db->table_name('mcpcube_agents', true);
        $users = $db->table_name('users', true);
        $result = $db->query(
            "SELECT a.`id`, a.`user_id`, a.`credential_key`, a.`encrypted_password`, a.`imap_host`,"
                . ' a.`label`, t.`scope` AS `scopes`, a.`expires`, a.`revoked`, a.`token_hash`, u.`username`'
                . " FROM {$tokens} t"
                . " JOIN {$agents} a ON a.`id` = t.`agent_id`"
                . " JOIN {$users} u ON u.`user_id` = a.`user_id`"
                . ' WHERE t.`access_hash` = ? AND t.`revoked` IS NULL AND t.`access_expires` > ' . $db->now()
                . ' AND a.`revoked` IS NULL AND a.`expires` > ' . $db->now(),
            mcpcube_crypto::hash_token($token)
        );
        if ($db->is_error($result)) {
            throw new mcpcube_auth_error('server_error', 'Agent lookup failed', 500);
        }

        $row = $db->fetch_assoc($result);
        if (!is_array($row)) {
            throw new mcpcube_auth_error('invalid_token', 'This access token is not recognized or has expired. Refresh it, or ask the user to sign in again.');
        }

        return $row;
    }

    /** @param array<string, mixed> $row */
    private static function open_agent_session(array $row): self
    {
        $rcmail = rcmail::get_instance();
        $password = mcpcube_crypto::decrypt_secret(
            (string) $row['encrypted_password'],
            'imap-password:' . $row['credential_key'],
            mcpcube_crypto::config_key()
        );

        if ($password === null || $password === '') {
            throw new mcpcube_auth_error('server_error', 'The stored mailbox credential could not be decrypted. Ask the user to re-pair this agent.', 500);
        }

        $host = is_string($row['imap_host']) && $row['imap_host'] !== '' ? $row['imap_host'] : null;

        $originalSession = $_SESSION;
        if (!$rcmail->login((string) $row['username'], $password, $host)) {
            $_SESSION = $originalSession;
            // Deliberately not auto-revoking here: a transient IMAP outage
            // should not permanently kill a valid pairing. If the stored
            // password itself has gone stale (user changed it outside
            // Roundcube), every call will fail the same way until the user
            // revokes and re-pairs from Settings > MCPcube Agents.
            throw new mcpcube_auth_error('imap_auth_failed', 'The stored mailbox credential was rejected by the mail server. Ask the user to revoke and re-pair this agent from Settings.', 502);
        }

        self::touch_last_used($rcmail->get_dbh(), (int) $row['id']);

        $scopes = array_values(array_filter(array_map('trim', explode(',', (string) $row['scopes']))));

        $context = new self(
            $rcmail,
            (int) $row['id'],
            (int) $row['user_id'],
            (string) $row['credential_key'],
            (string) $row['token_hash'],
            (string) $row['label'],
            $scopes,
            $originalSession
        );
        register_shutdown_function([$context, 'close']);

        return $context;
    }

    private static function touch_last_used(rcube_db $db, int $agentId): void
    {
        $table = $db->table_name('mcpcube_agents', true);
        $db->query("UPDATE {$table} SET `last_used` = " . $db->now() . ' WHERE `id` = ?', $agentId);
    }

    public function has_scope(string $scope): bool
    {
        return in_array($scope, $this->scopes, true);
    }

    /** @return list<string> */
    public function scopes(): array
    {
        return $this->scopes;
    }

    public function rcmail(): rcmail
    {
        return $this->rcmail;
    }

    public function user_id(): int
    {
        return $this->userId;
    }

    public function agent_id(): int
    {
        return $this->agentId;
    }

    public function agent_label(): string
    {
        return $this->label;
    }

    public function token_hash(): string
    {
        return $this->tokenHash;
    }

    /** Prevent a bearer-authenticated MCP call from becoming a browser session. */
    public function close(): void
    {
        if (!$this->closed) {
            $_SESSION = $this->originalSession;
            $this->closed = true;
        }
    }

    /**
     * Reads the raw `Authorization` header, tolerating the handful of ways
     * PHP/Apache/nginx/FPM mangle it depending on SAPI and config.
     */
    public static function bearer_token_from_request(): ?string
    {
        $header = null;

        if (function_exists('getallheaders')) {
            foreach (getallheaders() as $name => $value) {
                if (strcasecmp($name, 'Authorization') === 0) {
                    $header = $value;
                    break;
                }
            }
        }

        if ($header === null) {
            $header = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? null;
        }

        if (!is_string($header) || !preg_match('/^Bearer\s+(\S+)$/i', trim($header), $m)) {
            return null;
        }

        return $m[1];
    }
}

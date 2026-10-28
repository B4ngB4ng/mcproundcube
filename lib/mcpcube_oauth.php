<?php

declare(strict_types=1);

/** OAuth metadata, PKCE authorization-code, refresh-token, and registration support. */
final class mcpcube_oauth
{
    public const PRM_PATH = '/.well-known/oauth-protected-resource';
    public const AS_PATH = '/.well-known/oauth-authorization-server';

    /** A retried refresh inside this window mints a new pair instead of revoking the grant. */
    private const REFRESH_REUSE_GRACE = 60;

    public static function metadata(bool $resource = false): array
    {
        $base = rtrim((string) rcmail::get_instance()->config->get('mcpcube_public_url', ''), '/');
        if ($resource) {
            return [
                'resource' => $base . '/mcp',
                'authorization_servers' => [$base],
                'scopes_supported' => (array) rcmail::get_instance()->config->get('mcpcube_available_scopes', []),
                'bearer_methods_supported' => ['header'],
            ];
        }

        return [
            'issuer' => $base,
            'authorization_endpoint' => $base . '/oauth/authorize',
            'token_endpoint' => $base . '/oauth/token',
            'registration_endpoint' => $base . '/oauth/register',
            'response_types_supported' => ['code'],
            'grant_types_supported' => ['authorization_code', 'refresh_token'],
            'code_challenge_methods_supported' => ['S256'],
            'token_endpoint_auth_methods_supported' => ['none'],
            'scopes_supported' => (array) rcmail::get_instance()->config->get('mcpcube_available_scopes', []),
        ];
    }

    public static function json(array $body, int $status = 200): never
    {
        http_response_code($status);
        header('Content-Type: application/json');
        header('Cache-Control: no-store');
        echo json_encode($body, JSON_UNESCAPED_SLASHES);
        exit;
    }

    public static function register(): void
    {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') self::json(['error' => 'invalid_request'], 405);
        $body = json_decode((string) file_get_contents('php://input'), true);
        if (!is_array($body)) self::json(['error' => 'invalid_client_metadata'], 400);
        $uris = $body['redirect_uris'] ?? [];
        if (!is_array($uris) || $uris === []) self::json(['error' => 'invalid_redirect_uri'], 400);
        foreach ($uris as $uri) {
            if (!is_string($uri) || !self::valid_redirect($uri)) self::json(['error' => 'invalid_redirect_uri'], 400);
        }
        $client = 'mcpcube_' . bin2hex(random_bytes(16));
        $base = rtrim((string) rcmail::get_instance()->config->get('mcpcube_public_url', ''), '/');
        $db = rcmail::get_instance()->get_dbh();
        $table = $db->table_name('mcpcube_oauth_clients', true);
        $result = $db->query("INSERT INTO {$table} (`client_id`, `client_name`, `redirect_uris`, `created`) VALUES (?, ?, ?, " . $db->now() . ')',
            $client, mb_substr((string) ($body['client_name'] ?? 'MCP client'), 0, 120), json_encode(array_values($uris)));
        if ($db->is_error($result)) self::json(['error' => 'invalid_client_metadata'], 400);
        self::json(['client_id' => $client, 'client_name' => (string) ($body['client_name'] ?? 'MCP client'), 'redirect_uris' => array_values($uris), 'token_endpoint_auth_method' => 'none', 'grant_types' => ['authorization_code', 'refresh_token']], 201);
    }

    public static function authorize(): void
    {
        if ($_SERVER['REQUEST_METHOD'] !== 'GET') self::json(['error' => 'invalid_request'], 405);
        $base = rtrim((string) rcmail::get_instance()->config->get('mcpcube_public_url', ''), '/');
        $client = self::client((string) ($_GET['client_id'] ?? ''));
        $redirect = (string) ($_GET['redirect_uri'] ?? '');
        $state = (string) ($_GET['state'] ?? '');
        $challenge = (string) ($_GET['code_challenge'] ?? '');
        if ((string) ($_GET['response_type'] ?? '') !== 'code' || ($_GET['code_challenge_method'] ?? '') !== 'S256'
            || $challenge === '' || !self::valid_redirect($redirect) || !in_array($redirect, $client['redirects'], true)
        ) self::redirect_error($redirect, $state, 'invalid_request');

        $requested = preg_split('/\s+/', trim((string) ($_GET['scope'] ?? '')), -1, PREG_SPLIT_NO_EMPTY) ?: [];
        $available = (array) rcmail::get_instance()->config->get('mcpcube_available_scopes', []);
        if ($requested === []) $requested = (array) rcmail::get_instance()->config->get('mcpcube_default_scopes', []);
        if (array_diff($requested, $available) !== []) self::redirect_error($redirect, $state, 'invalid_scope');

        $db = rcmail::get_instance()->get_dbh();
        $table = $db->table_name('mcpcube_oauth_requests', true);
        $request = bin2hex(random_bytes(24));
        $inserted = $db->query(
            "INSERT INTO {$table} (`request_id`,`client_id`,`redirect_uri`,`state`,`code_challenge`,`scope`,`resource`,`created`,`expires`)"
                . ' VALUES (?, ?, ?, ?, ?, ?, ?, ' . $db->now() . ', ' . $db->now(600) . ')',
            $request, $client['id'], $redirect, $state, $challenge, implode(',', $requested), (string) ($_GET['resource'] ?? ($base . '/mcp'))
        );
        if ($db->is_error($inserted)) {
            self::json(['error' => 'server_error'], 500);
        }
        $devices = $db->table_name('mcpcube_device_codes', true);
        $device = mcpcube_crypto::random_hex(32);
        $userCode = mcpcube_crypto::random_user_code();
        $deviceInsert = $db->query(
            "INSERT INTO {$devices} (`device_code`,`user_code`,`client_label`,`requested_scopes`,`status`,`created`,`expires`,`poll_interval`,`oauth_request_id`)"
                . " VALUES (?, ?, ?, ?, 'pending', " . $db->now() . ', ' . $db->now(600) . ', 5, ?)',
            $device, $userCode, (string) $client['name'], implode(',', $requested), $request
        );
        if ($db->is_error($deviceInsert)) {
            self::json(['error' => 'server_error'], 500);
        }
        while (ob_get_level() > 0) {
            ob_end_clean();
        }
        header('Location: ' . $base . '/?_task=settings&_action=plugin.mcpcube-pair&user_code=' . rawurlencode($userCode), true, 302);
        exit;
    }

    public static function token(): void
    {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') self::json(['error' => 'invalid_request'], 405);
        $input = $_POST;
        if (stripos((string) ($_SERVER['CONTENT_TYPE'] ?? ''), 'application/json') !== false) $input = json_decode((string) file_get_contents('php://input'), true) ?: [];
        $grant = (string) ($input['grant_type'] ?? '');
        $db = rcmail::get_instance()->get_dbh();
        $table = $db->table_name('mcpcube_oauth_codes', true);
        if ($grant === 'authorization_code') {
            $code = (string) ($input['code'] ?? '');
            $row = self::code_row($db, $table, $code);
            if (!$row || (string) $row['client_id'] !== (string) ($input['client_id'] ?? '') || !hash_equals((string) $row['redirect_uri'], (string) ($input['redirect_uri'] ?? ''))
                || !hash_equals((string) $row['code_challenge'], self::challenge((string) ($input['code_verifier'] ?? '')))) self::json(['error' => 'invalid_grant'], 400);
            $marked = $db->query("UPDATE {$table} SET `used` = 1 WHERE `id` = ? AND `used` = 0", $row['id']);
            if ($db->is_error($marked) || $db->affected_rows($marked) !== 1) self::json(['error' => 'invalid_grant'], 400);
            $access = mcpcube_crypto::decrypt_secret((string) $row['access_ciphertext'], 'oauth-access:' . $row['request_id'], mcpcube_crypto::config_key());
            if (!is_string($access)) self::json(['error' => 'server_error'], 500);
            try {
                self::json(self::issue_from_agent_token($db, (string) $row['client_id'], $access, (string) $row['scope']));
            } catch (mcpcube_oauth_error $e) {
                self::json(['error' => $e->getMessage()], $e->httpStatus);
            }
        }
        if ($grant === 'refresh_token') {
            try {
                self::json(self::refresh_grant($db, $input));
            } catch (mcpcube_oauth_error $e) {
                self::json(['error' => $e->getMessage()], $e->httpStatus);
            }
        }
        self::json(['error' => 'unsupported_grant_type'], 400);
    }

    /**
     * Exchange the long-lived agent credential for a short access token and a
     * refresh token. The refresh token stays valid until the agent expires.
     *
     * @return array{access_token: string, token_type: string, expires_in: int, refresh_token: string, scope: string}
     */
    public static function issue_from_agent_token(rcube_db $db, string $clientId, string $agentToken, string $scope): array
    {
        $agents = $db->table_name('mcpcube_agents', true);
        $result = $db->query(
            "SELECT `id`, `expires`, `revoked` FROM {$agents} WHERE `token_hash` = ?",
            mcpcube_crypto::hash_token($agentToken)
        );
        if ($db->is_error($result)) {
            throw new mcpcube_oauth_error('server_error', 500);
        }
        $agent = $db->fetch_assoc($result);
        if (!is_array($agent) || $agent['revoked'] !== null || self::seconds_until($db, (string) $agent['expires']) <= 0) {
            throw new mcpcube_oauth_error('invalid_grant');
        }

        return self::insert_token_pair($db, (int) $agent['id'], $clientId, $scope, null, (string) $agent['expires']);
    }

    /**
     * @param array<string, mixed> $input
     * @return array{access_token: string, token_type: string, expires_in: int, refresh_token: string, scope: string}
     */
    public static function refresh_grant(rcube_db $db, array $input): array
    {
        $refresh = (string) ($input['refresh_token'] ?? '');
        $clientId = (string) ($input['client_id'] ?? '');
        if ($refresh === '' || $clientId === '') {
            throw new mcpcube_oauth_error('invalid_request');
        }
        if (strlen($refresh) > 200 || !str_starts_with($refresh, 'mcpcube_rt_')) {
            throw new mcpcube_oauth_error('invalid_grant');
        }

        $row = self::refresh_row($db, $refresh);
        if ($row === null || (string) $row['client_id'] !== $clientId) {
            throw new mcpcube_oauth_error('invalid_grant');
        }
        if ($row['revoked'] !== null || $row['agent_revoked'] !== null
            || self::seconds_until($db, (string) $row['refresh_expires']) <= 0
            || self::seconds_until($db, (string) $row['agent_expires']) <= 0
        ) {
            throw new mcpcube_oauth_error('invalid_grant');
        }

        $scope = self::narrow_scope((string) $row['scope'], (string) ($input['scope'] ?? ''));
        if ($row['rotated'] !== null) {
            return self::redeem_rotated($db, $row, $clientId, $scope);
        }

        $table = $db->table_name('mcpcube_oauth_tokens', true);
        $claimed = $db->query(
            "UPDATE {$table} SET `rotated` = " . $db->now() . ' WHERE `id` = ? AND `rotated` IS NULL AND `revoked` IS NULL AND `refresh_expires` > ' . $db->now(),
            $row['id']
        );
        if ($db->is_error($claimed)) {
            throw new mcpcube_oauth_error('server_error', 500);
        }
        if ($db->affected_rows($claimed) !== 1) {
            $again = self::refresh_row($db, $refresh);
            if ($again === null) {
                throw new mcpcube_oauth_error('invalid_grant');
            }

            return self::redeem_rotated($db, $again, $clientId, $scope);
        }

        return self::insert_token_pair($db, (int) $row['agent_id'], $clientId, $scope, (string) $row['family_id'], (string) $row['refresh_expires']);
    }

    /**
     * @return array{access_token: string, token_type: string, expires_in: int, refresh_token: string, scope: string}
     */
    public static function insert_token_pair(rcube_db $db, int $agentId, string $clientId, string $scope, ?string $familyId, string $refreshExpires): array
    {
        $remaining = self::seconds_until($db, $refreshExpires);
        if ($remaining < 30) {
            throw new mcpcube_oauth_error('invalid_grant');
        }

        $configured = max(60, (int) rcmail::get_instance()->config->get('mcpcube_oauth_access_ttl', 3600));
        $accessTtl = min($configured, $remaining);
        $familyId ??= bin2hex(random_bytes(16));
        $access = mcpcube_crypto::random_token('mcpcube_at_');
        $refresh = mcpcube_crypto::random_token('mcpcube_rt_');
        $table = $db->table_name('mcpcube_oauth_tokens', true);
        $result = $db->query(
            "INSERT INTO {$table} (`family_id`,`agent_id`,`client_id`,`access_hash`,`refresh_hash`,`scope`,`access_expires`,`refresh_expires`,`created`)"
                . ' VALUES (?, ?, ?, ?, ?, ?, ' . $db->now($accessTtl) . ', ?, ' . $db->now() . ')',
            $familyId,
            $agentId,
            $clientId,
            mcpcube_crypto::hash_token($access),
            mcpcube_crypto::hash_token($refresh),
            $scope,
            $refreshExpires
        );
        if ($db->is_error($result)) {
            throw new mcpcube_oauth_error('server_error', 500);
        }

        return [
            'access_token' => $access,
            'token_type' => 'Bearer',
            'expires_in' => $accessTtl,
            'refresh_token' => $refresh,
            'scope' => str_replace(',', ' ', $scope),
        ];
    }

    /** @param array<string, mixed> $row */
    private static function redeem_rotated(rcube_db $db, array $row, string $clientId, string $scope): array
    {
        if ($row['revoked'] !== null || $row['rotated'] === null) {
            throw new mcpcube_oauth_error('invalid_grant');
        }

        if (self::seconds_since($db, (string) $row['rotated']) > self::REFRESH_REUSE_GRACE) {
            $table = $db->table_name('mcpcube_oauth_tokens', true);
            $db->query(
                "UPDATE {$table} SET `revoked` = " . $db->now() . ', `access_expires` = ' . $db->now() . ' WHERE `family_id` = ? AND `revoked` IS NULL',
                $row['family_id']
            );
            throw new mcpcube_oauth_error('invalid_grant');
        }

        return self::insert_token_pair($db, (int) $row['agent_id'], $clientId, $scope, (string) $row['family_id'], (string) $row['refresh_expires']);
    }

    /** @return array<string, mixed>|null */
    private static function refresh_row(rcube_db $db, string $refresh): ?array
    {
        $table = $db->table_name('mcpcube_oauth_tokens', true);
        $agents = $db->table_name('mcpcube_agents', true);
        $result = $db->query(
            'SELECT t.*, a.`revoked` AS `agent_revoked`, a.`expires` AS `agent_expires`'
                . " FROM {$table} t JOIN {$agents} a ON a.`id` = t.`agent_id`"
                . ' WHERE t.`refresh_hash` = ?',
            mcpcube_crypto::hash_token($refresh)
        );
        if ($db->is_error($result)) {
            throw new mcpcube_oauth_error('server_error', 500);
        }
        $row = $db->fetch_assoc($result);

        return is_array($row) ? $row : null;
    }

    /** Database datetimes are wall-clock values; PHP may be in a different timezone. */
    private static function clock_skew(rcube_db $db): int
    {
        static $skew = null;
        if ($skew !== null) {
            return $skew;
        }

        $result = $db->query('SELECT ' . $db->now() . ' AS n');
        $row = $db->fetch_assoc($result);
        $parsed = strtotime((string) ($row['n'] ?? ''));
        $skew = $parsed === false ? 0 : $parsed - time();

        return $skew;
    }

    private static function seconds_since(rcube_db $db, string $datetime): int
    {
        $parsed = strtotime($datetime);
        if ($parsed === false) {
            return PHP_INT_MAX;
        }

        return time() - ($parsed - self::clock_skew($db));
    }

    private static function seconds_until(rcube_db $db, string $datetime): int
    {
        return -self::seconds_since($db, $datetime);
    }

    private static function narrow_scope(string $storedComma, string $requestedSpace): string
    {
        $granted = array_values(array_filter(array_map('trim', explode(',', $storedComma))));
        $requested = preg_split('/\s+/', trim($requestedSpace), -1, PREG_SPLIT_NO_EMPTY) ?: [];
        if ($requested === []) {
            return implode(',', $granted);
        }
        if (array_diff($requested, $granted) !== []) {
            throw new mcpcube_oauth_error('invalid_scope');
        }

        return implode(',', $requested);
    }

    public static function challenge(string $verifier): string
    {
        return rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
    }

    private static function code_row(rcube_db $db, string $table, string $code): ?array
    {
        if ($code === '' || strlen($code) > 200) return null;
        $hash = hash('sha256', $code);
        $result = $db->query("SELECT * FROM {$table} WHERE `code_hash` = ? AND `used` = 0 AND `expires` > " . $db->now(), $hash);
        $row = $db->fetch_assoc($result);
        return is_array($row) ? $row : null;
    }

    private static function client(string $id): array
    {
        $db = rcmail::get_instance()->get_dbh(); $table = $db->table_name('mcpcube_oauth_clients', true);
        $result = $db->query("SELECT * FROM {$table} WHERE `client_id` = ?", $id); $row = $db->fetch_assoc($result);
        if (!is_array($row)) self::json(['error' => 'unauthorized_client'], 400);
        $redirects = json_decode((string) $row['redirect_uris'], true);
        return ['id' => (string) $row['client_id'], 'name' => (string) $row['client_name'], 'redirects' => is_array($redirects) ? $redirects : []];
    }

    public static function valid_redirect(string $uri): bool
    {
        $p = parse_url($uri); return is_array($p) && in_array(strtolower((string) ($p['scheme'] ?? '')), ['https', 'http'], true)
            && (($p['scheme'] === 'http' && in_array(strtolower((string) ($p['host'] ?? '')), ['localhost', '127.0.0.1', '[::1]'], true)) || strtolower((string) ($p['scheme'] ?? '')) === 'https')
            && !isset($p['fragment']);
    }

    private static function redirect_error(string $redirect, string $state, string $error): never
    {
        if (!self::valid_redirect($redirect)) self::json(['error' => $error], 400);
        self::redirect_to_client($redirect, ['error' => $error, 'state' => $state]);
    }

    /** @param array<string, scalar|null> $params */
    public static function redirect_to_client(string $uri, array $params): never
    {
        $query = http_build_query($params, '', '&', PHP_QUERY_RFC3986);
        $location = $uri . (str_contains($uri, '?') ? '&' : '?') . $query;
        $ipv4 = self::loopback_ipv4($location);

        while (ob_get_level() > 0) {
            ob_end_clean();
        }

        $scheme = strtolower((string) (parse_url($location, PHP_URL_SCHEME) ?: ''));
        $host = strtolower((string) (parse_url($location, PHP_URL_HOST) ?: ''));
        $isLoopback = in_array($host, ['localhost', '127.0.0.1', '[::1]'], true);

        // HTTPS→HTTP Location on HTTP/2 was landing Chrome on bare "localhost"
        // without the callback path or ?code=&state=. Bounce in HTML/JS instead.
        if ($isLoopback && $scheme === 'http') {
            self::loopback_bounce_page($location, $ipv4);
        }

        header('Cache-Control: no-store, no-cache, must-revalidate');
        header('Location: ' . $location, true, 303);
        header('Content-Type: text/html; charset=UTF-8');
        echo self::bounce_html($location, $ipv4 !== $location ? $ipv4 : null);
        exit;
    }

    public static function loopback_ipv4(string $url): string
    {
        $parts = parse_url($url);
        if (!is_array($parts) || strtolower((string) ($parts['host'] ?? '')) !== 'localhost') {
            return $url;
        }
        $parts['host'] = '127.0.0.1';
        return self::unparse_url($parts);
    }

    /** @param array<string, mixed> $parts */
    private static function unparse_url(array $parts): string
    {
        $scheme = (string) ($parts['scheme'] ?? 'http');
        $host = (string) ($parts['host'] ?? '');
        $port = isset($parts['port']) ? ':' . (int) $parts['port'] : '';
        $path = (string) ($parts['path'] ?? '');
        $query = isset($parts['query']) && $parts['query'] !== '' ? '?' . $parts['query'] : '';
        $fragment = isset($parts['fragment']) && $parts['fragment'] !== '' ? '#' . $parts['fragment'] : '';
        return $scheme . '://' . $host . $port . $path . $query . $fragment;
    }

    private static function loopback_bounce_page(string $localhostUrl, string $ipv4Url): never
    {
        header('Cache-Control: no-store, no-cache, must-revalidate');
        header('Content-Type: text/html; charset=UTF-8');
        http_response_code(200);
        echo self::bounce_html($localhostUrl, $ipv4Url !== $localhostUrl ? $ipv4Url : null);
        exit;
    }

    private static function bounce_html(string $primary, ?string $alternate = null): string
    {
        $primaryAttr = htmlspecialchars($primary, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $primaryJs = json_encode($primary, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        $altBlock = '';
        if (is_string($alternate) && $alternate !== '') {
            $altAttr = htmlspecialchars($alternate, ENT_QUOTES | ENT_HTML5, 'UTF-8');
            $altBlock = '<p>If that does not open Cursor, try '
                . '<a href="' . $altAttr . '">' . $altAttr . '</a></p>';
        }

        return '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
            . '<meta http-equiv="refresh" content="0;url=' . $primaryAttr . '">'
            . '<title>Return to Cursor</title>'
            . '<style>body{font-family:sans-serif;max-width:52rem;margin:2rem auto;padding:0 1rem;word-break:break-all}</style>'
            . '</head><body>'
            . '<p>Returning to Cursor…</p>'
            . '<p><a id="cb" href="' . $primaryAttr . '">' . $primaryAttr . '</a></p>'
            . $altBlock
            . '<script>window.location.replace(' . $primaryJs . ');</script>'
            . '</body></html>';
    }
}

final class mcpcube_oauth_error extends RuntimeException
{
    public function __construct(string $error, public readonly int $httpStatus = 400)
    {
        parent::__construct($error);
    }
}

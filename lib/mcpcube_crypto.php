<?php

declare(strict_types=1);

/**
 * Symmetric crypto and token-generation helpers shared by every MCPcube
 * component. The encrypt/decrypt scheme (AES-256-GCM, random 96-bit nonce,
 * context-bound AAD, "\x01" version byte, base64) intentionally matches the
 * one used by the roundcube_oidc plugin so the same operational practices
 * (single independent key in config.inc.php, never in the database, rotate
 * only by re-pairing) apply to both.
 */
final class mcpcube_crypto
{
    /**
     * @throws RuntimeException on any encryption failure
     */
    public static function encrypt_secret(string $cleartext, string $context, string $key): string
    {
        $iv = random_bytes(12);
        $tag = '';
        $ciphertext = openssl_encrypt(
            $cleartext,
            'aes-256-gcm',
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $context,
            16
        );

        if ($ciphertext === false || strlen($tag) !== 16) {
            throw new RuntimeException('AES-256-GCM encryption failed');
        }

        return base64_encode("\x01" . $iv . $tag . $ciphertext);
    }

    /**
     * Returns null (rather than throwing) on any decryption failure so callers
     * can treat "unreadable credential" the same as "no credential" and force
     * re-pairing instead of leaking crypto errors.
     */
    public static function decrypt_secret(string $encoded, string $context, string $key): ?string
    {
        $payload = base64_decode($encoded, true);
        if ($payload === false || strlen($payload) < 29 || $payload[0] !== "\x01") {
            return null;
        }

        $iv = substr($payload, 1, 12);
        $tag = substr($payload, 13, 16);
        $ciphertext = substr($payload, 29);
        $cleartext = openssl_decrypt(
            $ciphertext,
            'aes-256-gcm',
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $context
        );

        return is_string($cleartext) ? $cleartext : null;
    }

    /**
     * Reads and validates config `mcpcube_encryption_key` (base64, exactly 32
     * raw bytes once decoded).
     */
    public static function config_key(): string
    {
        $encoded = (string) rcmail::get_instance()->config->get('mcpcube_encryption_key', '');
        $key = base64_decode($encoded, true);

        if ($key === false || strlen($key) !== 32) {
            throw new RuntimeException('mcpcube_encryption_key must be a base64-encoded 32-byte key');
        }

        return $key;
    }

    /** Lowercase hex of $bytes random bytes. */
    public static function random_hex(int $bytes): string
    {
        return bin2hex(random_bytes($bytes));
    }

    /**
     * A bearer token handed to an agent once, at the moment its
     * device_authorize request is approved. Never persisted in cleartext;
     * only hash_token() of it is stored, in mcpcube_agents.token_hash.
     */
    public static function random_bearer_token(): string
    {
        return self::random_token('mcpcube_pat_');
    }

    public static function random_token(string $prefix): string
    {
        return $prefix . rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    }

    public static function hash_token(string $token): string
    {
        return hash('sha256', $token);
    }

    /**
     * Human-typed device flow user_code, e.g. "K7QX-8MPR". Uses a
     * Crockford-like alphabet with ambiguous characters (0/O, 1/I/L, U)
     * removed so it is easy to read aloud and type without transcription
     * errors.
     */
    public static function random_user_code(): string
    {
        $alphabet = '23456789ABCDEFGHJKMNPQRSTVWXYZ';
        $max = strlen($alphabet) - 1;
        $chars = '';
        for ($i = 0; $i < 8; $i++) {
            $chars .= $alphabet[random_int(0, $max)];
        }

        return substr($chars, 0, 4) . '-' . substr($chars, 4, 4);
    }

    /** Normalizes user-typed codes (case, stray whitespace) before lookup. */
    public static function normalize_user_code(string $code): string
    {
        $code = strtoupper(trim($code));
        $code = preg_replace('/[^A-Z0-9-]/', '', $code) ?? '';

        if (!str_contains($code, '-') && strlen($code) === 8) {
            $code = substr($code, 0, 4) . '-' . substr($code, 4, 4);
        }

        return $code;
    }
}

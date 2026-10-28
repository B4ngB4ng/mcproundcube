-- MCPcube schema (MySQL / MariaDB)
--
-- Apply the same db_prefix used by the rest of Roundcube if one is configured,
-- e.g. `cube_mcpcube_agents` instead of `mcpcube_agents`.

CREATE TABLE `mcpcube_agents` (
    `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id` int(10) UNSIGNED NOT NULL,
    `credential_key` varchar(64) NOT NULL COMMENT 'hex sha256, binds AES-GCM AAD',
    `token_hash` char(64) NOT NULL COMMENT 'hex sha256 of the bearer token, raw token is never stored',
    `encrypted_password` text NOT NULL COMMENT 'AES-256-GCM, base64',
    `imap_host` varchar(255) DEFAULT NULL,
    `label` varchar(255) NOT NULL,
    `scopes` varchar(255) NOT NULL,
    `created` datetime NOT NULL,
    `expires` datetime NOT NULL,
    `last_used` datetime DEFAULT NULL,
    `revoked` datetime DEFAULT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `credential_key` (`credential_key`),
    UNIQUE KEY `token_hash` (`token_hash`),
    KEY `user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

ALTER TABLE `mcpcube_agents`
    ADD CONSTRAINT `mcpcube_agents_user_id_fkey`
    FOREIGN KEY (`user_id`) REFERENCES `users` (`user_id`)
    ON DELETE CASCADE ON UPDATE CASCADE;

CREATE TABLE `mcpcube_device_codes` (
    `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT,
    `device_code` char(64) NOT NULL COMMENT 'hex, held only by the agent',
    `user_code` char(9) NOT NULL COMMENT 'human-typed form XXXX-XXXX',
    `client_label` varchar(255) NOT NULL COMMENT 'what the agent calls itself, shown on the consent page',
    `requested_scopes` varchar(255) NOT NULL,
    `status` varchar(16) NOT NULL DEFAULT 'pending' COMMENT 'pending|approved|denied|expired|consumed',
    `user_id` int(10) UNSIGNED DEFAULT NULL COMMENT 'set once approved',
    `pending_token_ciphertext` text DEFAULT NULL COMMENT 'AES-256-GCM wrapped raw bearer token, single read then cleared',
    `created` datetime NOT NULL,
    `expires` datetime NOT NULL,
    `last_polled` datetime DEFAULT NULL,
    `poll_interval` smallint UNSIGNED NOT NULL DEFAULT 5,
    `oauth_request_id` char(48) DEFAULT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `device_code` (`device_code`),
    UNIQUE KEY `user_code` (`user_code`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE `mcpcube_oauth_clients` (`client_id` varchar(80) NOT NULL PRIMARY KEY, `client_name` varchar(120) NOT NULL, `redirect_uris` text NOT NULL, `created` datetime NOT NULL);
CREATE TABLE `mcpcube_oauth_requests` (`request_id` char(48) NOT NULL PRIMARY KEY, `client_id` varchar(80) NOT NULL, `redirect_uri` text NOT NULL, `state` text NOT NULL, `code_challenge` char(43) NOT NULL, `scope` varchar(255) NOT NULL, `resource` text NOT NULL, `created` datetime NOT NULL, `expires` datetime NOT NULL);
CREATE TABLE `mcpcube_oauth_codes` (`id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY, `code_hash` char(64) NOT NULL UNIQUE, `request_id` char(48) NOT NULL, `client_id` varchar(80) NOT NULL, `redirect_uri` text NOT NULL, `code_challenge` char(43) NOT NULL, `scope` varchar(255) NOT NULL, `access_ciphertext` text NOT NULL, `access_expires` int NOT NULL, `expires` datetime NOT NULL, `used` tinyint NOT NULL DEFAULT 0);
CREATE TABLE `mcpcube_oauth_tokens` (
    `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT,
    `family_id` char(32) NOT NULL,
    `agent_id` int(10) UNSIGNED NOT NULL,
    `client_id` varchar(80) NOT NULL,
    `access_hash` char(64) NOT NULL,
    `refresh_hash` char(64) NOT NULL,
    `scope` varchar(255) NOT NULL,
    `access_expires` datetime NOT NULL,
    `refresh_expires` datetime NOT NULL,
    `created` datetime NOT NULL,
    `rotated` datetime DEFAULT NULL,
    `revoked` datetime DEFAULT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `access_hash` (`access_hash`),
    UNIQUE KEY `refresh_hash` (`refresh_hash`),
    KEY `family_id` (`family_id`),
    KEY `agent_id` (`agent_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

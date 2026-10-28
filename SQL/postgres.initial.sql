-- MCPcube schema (PostgreSQL)
--
-- Apply the same db_prefix used by the rest of Roundcube if one is configured.

CREATE TABLE mcpcube_agents (
    id SERIAL PRIMARY KEY,
    user_id integer NOT NULL REFERENCES users(user_id) ON DELETE CASCADE ON UPDATE CASCADE,
    credential_key varchar(64) NOT NULL UNIQUE,
    token_hash char(64) NOT NULL UNIQUE,
    encrypted_password text NOT NULL,
    imap_host varchar(255) DEFAULT NULL,
    label varchar(255) NOT NULL,
    scopes varchar(255) NOT NULL,
    created timestamp without time zone NOT NULL,
    expires timestamp without time zone NOT NULL,
    last_used timestamp without time zone DEFAULT NULL,
    revoked timestamp without time zone DEFAULT NULL
);

CREATE INDEX mcpcube_agents_user_id_idx ON mcpcube_agents (user_id);

CREATE TABLE mcpcube_device_codes (
    id SERIAL PRIMARY KEY,
    device_code char(64) NOT NULL UNIQUE,
    user_code char(9) NOT NULL UNIQUE,
    client_label varchar(255) NOT NULL,
    requested_scopes varchar(255) NOT NULL,
    status varchar(16) NOT NULL DEFAULT 'pending',
    user_id integer DEFAULT NULL,
    pending_token_ciphertext text DEFAULT NULL,
    created timestamp without time zone NOT NULL,
    expires timestamp without time zone NOT NULL,
    last_polled timestamp without time zone DEFAULT NULL,
    poll_interval smallint NOT NULL DEFAULT 5
    ,oauth_request_id char(48) DEFAULT NULL
);

CREATE TABLE mcpcube_oauth_clients (client_id varchar(80) PRIMARY KEY, client_name varchar(120) NOT NULL, redirect_uris text NOT NULL, created timestamp without time zone NOT NULL);
CREATE TABLE mcpcube_oauth_requests (request_id char(48) PRIMARY KEY, client_id varchar(80) NOT NULL, redirect_uri text NOT NULL, state text NOT NULL, code_challenge char(43) NOT NULL, scope varchar(255) NOT NULL, resource text NOT NULL, created timestamp without time zone NOT NULL, expires timestamp without time zone NOT NULL);
CREATE TABLE mcpcube_oauth_codes (id SERIAL PRIMARY KEY, code_hash char(64) NOT NULL UNIQUE, request_id char(48) NOT NULL, client_id varchar(80) NOT NULL, redirect_uri text NOT NULL, code_challenge char(43) NOT NULL, scope varchar(255) NOT NULL, access_ciphertext text NOT NULL, access_expires integer NOT NULL, expires timestamp without time zone NOT NULL, used smallint NOT NULL DEFAULT 0);
CREATE TABLE mcpcube_oauth_tokens (id SERIAL PRIMARY KEY, family_id char(32) NOT NULL, agent_id integer NOT NULL, client_id varchar(80) NOT NULL, access_hash char(64) NOT NULL UNIQUE, refresh_hash char(64) NOT NULL UNIQUE, scope varchar(255) NOT NULL, access_expires timestamp without time zone NOT NULL, refresh_expires timestamp without time zone NOT NULL, created timestamp without time zone NOT NULL, rotated timestamp without time zone DEFAULT NULL, revoked timestamp without time zone DEFAULT NULL);
CREATE INDEX mcpcube_oauth_tokens_family_id_idx ON mcpcube_oauth_tokens (family_id);
CREATE INDEX mcpcube_oauth_tokens_agent_id_idx ON mcpcube_oauth_tokens (agent_id);

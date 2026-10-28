-- MCPcube schema (SQLite)

CREATE TABLE mcpcube_agents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE ON UPDATE CASCADE,
    credential_key varchar(64) NOT NULL UNIQUE,
    token_hash char(64) NOT NULL UNIQUE,
    encrypted_password text NOT NULL,
    imap_host varchar(255) DEFAULT NULL,
    label varchar(255) NOT NULL,
    scopes varchar(255) NOT NULL,
    created datetime NOT NULL,
    expires datetime NOT NULL,
    last_used datetime DEFAULT NULL,
    revoked datetime DEFAULT NULL
);

CREATE INDEX ix_mcpcube_agents_user_id ON mcpcube_agents(user_id);

CREATE TABLE mcpcube_device_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_code char(64) NOT NULL UNIQUE,
    user_code char(9) NOT NULL UNIQUE,
    client_label varchar(255) NOT NULL,
    requested_scopes varchar(255) NOT NULL,
    status varchar(16) NOT NULL DEFAULT 'pending',
    user_id INTEGER DEFAULT NULL,
    pending_token_ciphertext text DEFAULT NULL,
    created datetime NOT NULL,
    expires datetime NOT NULL,
    last_polled datetime DEFAULT NULL,
    poll_interval smallint NOT NULL DEFAULT 5
    ,oauth_request_id char(48) DEFAULT NULL
);

CREATE TABLE mcpcube_oauth_clients (
    client_id varchar(80) PRIMARY KEY,
    client_name varchar(120) NOT NULL,
    redirect_uris text NOT NULL,
    created datetime NOT NULL
);

CREATE TABLE mcpcube_oauth_requests (
    request_id char(48) PRIMARY KEY,
    client_id varchar(80) NOT NULL,
    redirect_uri text NOT NULL,
    state text NOT NULL,
    code_challenge char(43) NOT NULL,
    scope varchar(255) NOT NULL,
    resource text NOT NULL,
    created datetime NOT NULL,
    expires datetime NOT NULL
);

CREATE TABLE mcpcube_oauth_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code_hash char(64) NOT NULL UNIQUE,
    request_id char(48) NOT NULL,
    client_id varchar(80) NOT NULL,
    redirect_uri text NOT NULL,
    code_challenge char(43) NOT NULL,
    scope varchar(255) NOT NULL,
    access_ciphertext text NOT NULL,
    access_expires integer NOT NULL,
    expires datetime NOT NULL,
    used smallint NOT NULL DEFAULT 0
);

CREATE TABLE mcpcube_oauth_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    family_id char(32) NOT NULL,
    agent_id integer NOT NULL,
    client_id varchar(80) NOT NULL,
    access_hash char(64) NOT NULL UNIQUE,
    refresh_hash char(64) NOT NULL UNIQUE,
    scope varchar(255) NOT NULL,
    access_expires datetime NOT NULL,
    refresh_expires datetime NOT NULL,
    created datetime NOT NULL,
    rotated datetime DEFAULT NULL,
    revoked datetime DEFAULT NULL
);
CREATE INDEX mcpcube_oauth_tokens_family_id_idx ON mcpcube_oauth_tokens (family_id);
CREATE INDEX mcpcube_oauth_tokens_agent_id_idx ON mcpcube_oauth_tokens (agent_id);

--# sqlite
--# {xauthconnect}

--# !init
CREATE TABLE IF NOT EXISTS xauth_oauth_codes (
    code TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    username TEXT NOT NULL,
    expires INTEGER NOT NULL,
    scopes TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    code_challenge_method TEXT NOT NULL,
    state TEXT NULL
);

CREATE TABLE IF NOT EXISTS xauth_oauth_tokens (
    token TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    expires INTEGER NOT NULL,
    scopes TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS xauth_oauth_refresh_tokens (
    refresh_token TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    username TEXT NOT NULL,
    expires INTEGER NOT NULL,
    scopes TEXT NOT NULL,
    revoked INTEGER DEFAULT 0
);
--#

--# {xauth_oauth_codes}

--# !insert
INSERT INTO xauth_oauth_codes (code, client_id, username, expires, scopes) VALUES (:code, :client_id, :username, :expires, :scopes);
--#

--# !fetch
SELECT * FROM xauth_oauth_codes WHERE code = :code;
--#

--# !delete
DELETE FROM xauth_oauth_codes WHERE code = :code;
--#

--# {xauth_oauth_tokens}

--# !insert
INSERT INTO xauth_oauth_tokens (token, username, expires, scopes) VALUES (:token, :username, :expires, :scopes);
--#

--# !fetch
SELECT * FROM xauth_oauth_tokens WHERE token = :token;
--#

--# {xauth_oauth_refresh_tokens}

--# !insert
INSERT INTO xauth_oauth_refresh_tokens (refresh_token, client_id, username, expires, scopes) VALUES (:refresh_token, :client_id, :username, :expires, :scopes);
--#

--# !fetch
SELECT * FROM xauth_oauth_refresh_tokens WHERE refresh_token = :refresh_token;
--#

--# !revoke
UPDATE xauth_oauth_refresh_tokens SET revoked = 1 WHERE refresh_token = :refresh_token;
--#

--# {xauth_oauth_tokens}

--# !delete
DELETE FROM xauth_oauth_tokens WHERE token = :token;
--#

--# mysql
--# {xauthconnect}

--# !init
CREATE TABLE IF NOT EXISTS xauth_oauth_codes (
    code VARCHAR(128) PRIMARY KEY,
    client_id VARCHAR(64) NOT NULL,
    username VARCHAR(100) NOT NULL,
    expires TIMESTAMP NOT NULL,
    scopes TEXT NOT NULL,
    code_challenge VARCHAR(128) NOT NULL,
    code_challenge_method VARCHAR(10) NOT NULL,
    state VARCHAR(128) NULL
);

CREATE TABLE IF NOT EXISTS xauth_oauth_tokens (
    token VARCHAR(128) PRIMARY KEY,
    username VARCHAR(100) NOT NULL,
    expires TIMESTAMP NOT NULL,
    scopes TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS xauth_oauth_refresh_tokens (
    refresh_token VARCHAR(128) PRIMARY KEY,
    client_id VARCHAR(64) NOT NULL,
    username VARCHAR(100) NOT NULL,
    expires TIMESTAMP NOT NULL,
    scopes TEXT NOT NULL,
    revoked BOOLEAN DEFAULT FALSE
);
--#

--# {xauth_oauth_codes}

--# !insert
INSERT INTO xauth_oauth_codes (code, client_id, username, expires, scopes) VALUES (:code, :client_id, :username, FROM_UNIXTIME(:expires), :scopes);
--#

--# !fetch
SELECT code, client_id, username, UNIX_TIMESTAMP(expires) as expires, scopes FROM xauth_oauth_codes WHERE code = :code;
--#

--# !delete
DELETE FROM xauth_oauth_codes WHERE code = :code;
--#

--# {xauth_oauth_tokens}

--# !insert
INSERT INTO xauth_oauth_tokens (token, username, expires, scopes) VALUES (:token, :username, FROM_UNIXTIME(:expires), :scopes);
--#

--# !fetch
SELECT token, username, UNIX_TIMESTAMP(expires) as expires, scopes FROM xauth_oauth_tokens WHERE token = :token;
--#

--# {xauth_oauth_refresh_tokens}

--# !insert
INSERT INTO xauth_oauth_refresh_tokens (refresh_token, client_id, username, expires, scopes) VALUES (:refresh_token, :client_id, :username, FROM_UNIXTIME(:expires), :scopes);
--#

--# !fetch
SELECT refresh_token, client_id, username, UNIX_TIMESTAMP(expires) as expires, scopes, revoked FROM xauth_oauth_refresh_tokens WHERE refresh_token = :refresh_token;
--#

--# !revoke
UPDATE xauth_oauth_refresh_tokens SET revoked = TRUE WHERE refresh_token = :refresh_token;
--#

--# {xauth_oauth_tokens}

--# !delete
DELETE FROM xauth_oauth_tokens WHERE token = :token;
--#

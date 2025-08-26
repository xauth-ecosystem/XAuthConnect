<?php

/*
 *
 * __  __    _         _   _      ____                            _
 * \ \/ /   / \  _   _| |_| |__  / ___|___  _ __  _ __   ___  ___| |_
 *  \  /   / _ \| | | | __| '_ \| |   / _ \| '_ \| '_ \ / _ \/ __| __|
 *  /  \  / ___ \ |_| | |_| | | | |__| (_) | | | | | | |  __/ (__| |_
 * /_/\_\/_/   \_\__,_|\__|_| |_|\____\___/|_| |_|_| |_|\___|\___|\__|
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the CSSM Unlimited License v2.0.
 *
 * This license permits unlimited use, modification, and distribution
 * for any purpose while maintaining authorship attribution.
 *
 * The software is provided "as is" without warranty of any kind.
 *
 * @author Sergiy Chernega
 * @link https://chernega.eu.org/
 *
 *
 */

declare(strict_types=1);

namespace ChernegaSergiy\XAuthConnect\provider;

use Closure;
use pocketmine\plugin\Plugin;
use poggit\libasynql\libasynql;
use poggit\libasynql\DataConnector;

class DatabaseProvider {

    private DataConnector $db;

    public function __construct(Plugin $plugin) {
        $this->db = libasynql::create($plugin, $plugin->getConfig()->get("database"), [
            "sqlite" => "sql/sqlite.sql",
            "mysql" => "sql/mysql.sql"
        ]);
    }

    public function close(): void {
        $this->db->close();
    }

    public function insertCode(string $code, string $clientId, string $username, int $expires, array $scopes, string $codeChallenge, string $codeChallengeMethod, ?string $state, Closure $onSuccess): void {
        $this->db->executeInsert("xauth_oauth_codes.insert", [
            "code" => $code,
            "client_id" => $clientId,
            "username" => $username,
            "expires" => $expires,
            "scopes" => json_encode($scopes),
            "code_challenge" => $codeChallenge,
            "code_challenge_method" => $codeChallengeMethod,
            "state" => $state
        ], $onSuccess);
    }

    public function fetchCode(string $code, Closure $onSuccess): void {
        $this->db->executeSelect("xauth_oauth_codes.fetch", ["code" => $code], $onSuccess);
    }

    public function deleteCode(string $code, Closure $onSuccess = null): void {
        $this->db->executeChange("xauth_oauth_codes.delete", ["code" => $code], $onSuccess);
    }

    public function insertToken(string $token, string $username, int $expires, array $scopes, Closure $onSuccess): void {
        $this->db->executeInsert("xauth_oauth_tokens.insert", [
            "token" => $token,
            "username" => $username,
            "expires" => $expires,
            "scopes" => json_encode($scopes)
        ], $onSuccess);
    }

    public function fetchToken(string $token, Closure $onSuccess): void {
        $this->db->executeSelect("xauth_oauth_tokens.fetch", ["token" => $token], $onSuccess);
    }

    public function insertRefreshToken(string $refreshToken, string $username, int $expires, array $scopes, Closure $onSuccess): void {
        $this->db->executeInsert("xauth_oauth_refresh_tokens.insert", [
            "refresh_token" => $refreshToken,
            "username" => $username,
            "expires" => $expires,
            "scopes" => json_encode($scopes)
        ], $onSuccess);
    }

    public function fetchRefreshToken(string $refreshToken, Closure $onSuccess): void {
        $this->db->executeSelect("xauth_oauth_refresh_tokens.fetch", ["refresh_token" => $refreshToken], $onSuccess);
    }

    public function revokeRefreshToken(string $refreshToken, Closure $onSuccess): void {
        $this->db->executeChange("xauth_oauth_refresh_tokens.revoke", ["refresh_token" => $refreshToken], $onSuccess);
    }

    public function deleteToken(string $token, Closure $onSuccess): void {
        $this->db->executeChange("xauth_oauth_tokens.delete", ["token" => $token], $onSuccess);
    }
}

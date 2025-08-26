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

class TokenProvider {

    private DatabaseProvider $db;

    public function __construct(DatabaseProvider $db) {
        $this->db = $db;
    }

    public function createToken(string $username, array $scopes, Closure $onSuccess): void {
        $accessToken = "xat-" . bin2hex(random_bytes(32));
        $expires = time() + 3600; // 1-hour expiry for access token

        // Create a refresh token with a longer expiry
        $refreshToken = "xrt-" . bin2hex(random_bytes(64));
        $refreshTokenExpires = time() + (30 * 24 * 3600); // 30 days expiry for refresh token

        $this->db->insertToken($accessToken, $username, $expires, $scopes, function() use ($accessToken, $refreshToken, $username, $refreshTokenExpires, $scopes, $onSuccess, $expires) {
            // Only create refresh token if access token insertion was successful
            $this->db->insertRefreshToken($refreshToken, $username, $refreshTokenExpires, $scopes, function() use ($accessToken, $refreshToken, $expires, $onSuccess) {
                $onSuccess($accessToken, $refreshToken, $expires); // Pass access, refresh, and expiry
            });
        });
    }

    public function validateToken(string $token, Closure $onSuccess): void {
        $this->db->fetchToken($token, function(array $rows) use ($onSuccess) {
            if (empty($rows)) {
                $onSuccess(null);
                return;
            }

            $tokenData = $rows[0];
            if ($tokenData['expires'] < time()) {
                $onSuccess(null);
                return;
            }

            $onSuccess([
                "username" => $tokenData['username'],
                "scopes" => json_decode($tokenData['scopes'], true),
                "client_id" => $tokenData['client_id'] ?? null,
                "expires" => $tokenData['expires']
            ]);
        });
    }

    public function validateRefreshToken(string $refreshToken, Closure $onSuccess): void {
        $this->db->fetchRefreshToken($refreshToken, function(array $rows) use ($onSuccess) {
            if (empty($rows)) {
                $onSuccess(null);
                return;
            }

            $tokenData = $rows[0];
            if ($tokenData['expires'] < time() || (isset($tokenData['revoked']) && $tokenData['revoked'] == 1)) { // Check for expiry and revoked status
                $onSuccess(null);
                return;
            }

            $onSuccess([
                "username" => $tokenData['username'],
                "scopes" => json_decode($tokenData['scopes'], true),
                "client_id" => $tokenData['client_id'] ?? null,
                "expires" => $tokenData['expires']
            ]);
        });
    }

    public function revokeToken(string $token, Closure $onSuccess): void {
        // Try to revoke as access token
        $this->db->deleteToken($token, function($success) use ($token, $onSuccess) {
            if ($success) {
                $onSuccess(true);
                return;
            }
            // If not an access token, try to revoke as refresh token
            $this->db->revokeRefreshToken($token, $onSuccess);
        });
    }
}

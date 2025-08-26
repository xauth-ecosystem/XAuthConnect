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

class CodeProvider {

    private DatabaseProvider $db;
    private int $timeout;

    public function __construct(DatabaseProvider $db, int $timeout = 300) {
        $this->db = $db;
        $this->timeout = $timeout;
    }

    public function createCode(string $clientId, string $username, array $scopes, string $codeChallenge, string $codeChallengeMethod, ?string $state, Closure $onSuccess): void {
        $authCode = bin2hex(random_bytes(20));
        $expires = time() + $this->timeout;
        $this->db->insertCode($authCode, $clientId, $username, $expires, $scopes, $codeChallenge, $codeChallengeMethod, $state, fn() => $onSuccess($authCode));
    }

    public function validateCode(string $code, string $clientId, string $codeVerifier, ?string $expectedState, Closure $onSuccess): void {
        $this->db->fetchCode($code, function(array $rows) use ($clientId, $codeVerifier, $expectedState, $onSuccess) {
            if (empty($rows)) {
                $onSuccess(null);
                return;
            }

            $authCodeData = $rows[0];
            if ($authCodeData['client_id'] !== $clientId || $authCodeData['expires'] < time()) {
                $onSuccess(null);
                return;
            }

            // PKCE validation
            $storedCodeChallenge = $authCodeData['code_challenge'] ?? null;
            $storedCodeChallengeMethod = $authCodeData['code_challenge_method'] ?? null;

            if ($storedCodeChallenge === null || $storedCodeChallengeMethod === null) {
                // PKCE not used for this code, or data missing. Treat as invalid for security.
                $onSuccess(null);
                return;
            }

            $calculatedCodeChallenge = $this->generateCodeChallenge($codeVerifier, $storedCodeChallengeMethod);

            if ($calculatedCodeChallenge !== $storedCodeChallenge) {
                // Code verifier does not match code challenge
                $onSuccess(null);
                return;
            }

            // State validation
            $storedState = $authCodeData['state'] ?? null;
            if ($expectedState !== null && $storedState !== $expectedState) {
                // State mismatch
                $onSuccess(null);
                return;
            }

            // Invalidate code after use
            $this->db->deleteCode($code);

            $onSuccess([
                "username" => $authCodeData['username'],
                "scopes" => json_decode($authCodeData['scopes'], true),
                "state" => $storedState // Return the stored state
            ]);
        });
    }

    private function generateCodeChallenge(string $codeVerifier, string $method): ?string {
        switch ($method) {
            case "S256":
                // BASE64URL-encode(SHA256(ASCII(code_verifier)))
                $hash = hash("sha256", $codeVerifier, true);
                return rtrim(strtr(base64_encode($hash), '+/', '-_'), '=');
            case "plain": // Not recommended for production
                return $codeVerifier;
            default:
                return null; // Unsupported method
        }
    }
}

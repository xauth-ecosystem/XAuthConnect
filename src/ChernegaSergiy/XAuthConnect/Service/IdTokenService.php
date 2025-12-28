<?php

declare(strict_types=1);

namespace ChernegaSergiy\XAuthConnect\Service;

use Firebase\JWT\JWT;

class IdTokenService
{
    private KeyService $keyService;
    private string $issuerUrl;

    public function __construct(KeyService $keyService, string $issuerUrl)
    {
        $this->keyService = $keyService;
        $this->issuerUrl = $issuerUrl;
    }

    public function createIdToken(string $username, string $clientId, int $authTime, ?string $nonce, int $expiry = 3600): string
    {
        $privateKey = $this->keyService->getPrivateKey();
        $publicKeyJwk = $this->keyService->getPublicKeyAsJwk();
        $kid = $publicKeyJwk['kid'];

        $currentTime = time();

        $payload = [
            'iss' => $this->issuerUrl,
            'sub' => $username, // Subject - the user's identifier
            'aud' => $clientId, // Audience - the client ID
            'exp' => $currentTime + $expiry, // Expiration Time
            'iat' => $currentTime, // Issued At
            'auth_time' => $authTime, // Time when the authentication occurred
        ];

        if ($nonce !== null) {
            $payload['nonce'] = $nonce;
        }

        return JWT::encode($payload, $privateKey, 'RS256', $kid);
    }
}

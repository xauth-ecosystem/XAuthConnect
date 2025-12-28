<?php

declare(strict_types=1);

namespace ChernegaSergiy\XAuthConnect\Pkce;

class S256MethodHandler implements CodeChallengeMethodHandlerInterface
{
    public function validate(string $codeVerifier, string $codeChallenge): bool
    {
        $hashedVerifier = hash('sha256', $codeVerifier, true);
        $base64UrlEncodedHashedVerifier = rtrim(strtr(base64_encode($hashedVerifier), '+/', '-_'), '=');
        return $base64UrlEncodedHashedVerifier === $codeChallenge;
    }

    public function getName(): string
    {
        return 'S256';
    }
}

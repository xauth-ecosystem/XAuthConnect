<?php

declare(strict_types=1);

namespace ChernegaSergiy\XAuthConnect\Pkce;

class PlainMethodHandler implements CodeChallengeMethodHandlerInterface
{
    public function validate(string $codeVerifier, string $codeChallenge): bool
    {
        return $codeVerifier === $codeChallenge;
    }

    public function getName(): string
    {
        return 'plain';
    }
}

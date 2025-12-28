<?php

declare(strict_types=1);

namespace ChernegaSergiy\XAuthConnect\Pkce;

interface CodeChallengeMethodHandlerInterface
{
    public function validate(string $codeVerifier, string $codeChallenge): bool;
    
    public function getName(): string;
}

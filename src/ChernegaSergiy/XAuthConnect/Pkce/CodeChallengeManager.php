<?php

declare(strict_types=1);

namespace ChernegaSergiy\XAuthConnect\Pkce;

use InvalidArgumentException;

class CodeChallengeManager
{
    /** @var CodeChallengeMethodHandlerInterface[] */
    private array $handlers = [];

    public function __construct()
    {
        $this->registerHandler(new PlainMethodHandler());
        $this->registerHandler(new S256MethodHandler());
    }

    public function registerHandler(CodeChallengeMethodHandlerInterface $handler): void
    {
        $this->handlers[$handler->getName()] = $handler;
    }

    public function validate(string $method, string $codeVerifier, string $codeChallenge): bool
    {
        if (!isset($this->handlers[$method])) {
            // Or log a warning, depending on desired strictness.
            // According to RFC 7636, the server MUST support 'plain' and 'S256'.
            // If the client requests another, it should be handled earlier,
            // but as a safeguard, we return false.
            return false;
        }

        return $this->handlers[$method]->validate($codeVerifier, $codeChallenge);
    }
    
    public function isMethodSupported(string $method): bool
    {
        return isset($this->handlers[$method]);
    }
}

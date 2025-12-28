<?php

declare(strict_types=1);

namespace ChernegaSergiy\XAuthConnect\ScopeProvider;

use pocketmine\Server;

interface ScopeProviderInterface
{
    public function getProvidedScopes(): array;

    public function retrieveScopeData(Server $server, string $username, array $scopes): array;
}

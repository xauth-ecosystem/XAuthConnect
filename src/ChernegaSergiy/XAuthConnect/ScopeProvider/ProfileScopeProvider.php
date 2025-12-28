<?php

declare(strict_types=1);

namespace ChernegaSergiy\XAuthConnect\ScopeProvider;

use ChernegaSergiy\XAuthConnect\ScopeProvider\ScopeProviderInterface;
use pocketmine\Server;
use pmmp\thread\ThreadSafe;

class ProfileScopeProvider extends ThreadSafe implements ScopeProviderInterface
{
    public function getProvidedScopes(): array
    {
        return ["openid", "profile:nickname", "profile:uuid"];
    }

    public function retrieveScopeData(Server $server, string $username, array $scopes): array
    {
        $data = [];
        $player = $server->getOfflinePlayer($username);

        if ($player === null) {
            return $data;
        }

        $scopeSet = array_flip($scopes);

        // Always add 'sub' if 'openid' scope is present, as per OIDC spec.
        if (isset($scopeSet['openid'])) {
            $data['sub'] = $player->getName();
        }

        if (isset($scopeSet['profile:nickname'])) {
            $data['nickname'] = $player->getName();
        }

        if (isset($scopeSet['profile:uuid'])) {
            // The getUniqueId() method does not exist on OfflinePlayer in this server version.
            $data['uuid'] = 'UUID not available';
        }

        return $data;
    }
}
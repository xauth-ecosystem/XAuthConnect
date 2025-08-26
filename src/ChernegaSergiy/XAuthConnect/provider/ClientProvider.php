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

use pocketmine\utils\Config;

class ClientProvider {

    private array $registeredClients = [];

    public function __construct(Config $config) {
        $webIntegrationConfig = $config->get("web-integration", []);
        $this->registeredClients = $webIntegrationConfig["registered-clients"] ?? [];
    }

    public function getClient(string $clientId): ?array {
        return $this->registeredClients[$clientId] ?? null;
    }

    public function isClientValid(string $clientId, ?string $redirectUri = null, ?string $clientSecret = null): bool {
        $client = $this->getClient($clientId);
        if ($client === null) {
            return false;
        }

        if ($redirectUri !== null && !in_array($redirectUri, $client["redirect-uris"] ?? [], true)) {
            return false;
        }

        if ($clientSecret !== null && ($client["client-secret"] ?? null) !== $clientSecret) {
            return false;
        }

        return true;
    }
}

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

use ChernegaSergiy\XAuthConnect\api\ScopeProvider;
use Luthfi\XAuth\Main as XAuth;

class ScopeManager {

    /** @var ScopeProvider[] */
    private array $scopeProviders = [];
    private XAuth $xauthApi;

    public function __construct(XAuth $xauthApi) {
        $this->xauthApi = $xauthApi;
    }

    public function registerProvider(ScopeProvider $provider): void {
        foreach ($provider->getProvidedScopes() as $scope) {
            $this->scopeProviders[$scope] = $provider;
        }
    }

    public function getAvailableScopes(): array {
        $internalScopes = ["profile:nickname", "profile:uuid", "profile:registration_date"];
        $providerScopes = array_keys($this->scopeProviders);
        return array_merge($internalScopes, $providerScopes);
    }

    public function retrieveDataForScopes(string $username, array $scopes): array {
        $data = [];
        $providerQueue = [];

        foreach ($scopes as $scope) {
            // Handle internal scopes
            if (str_starts_with($scope, "profile:")) {
                $playerData = $this->xauthApi->getDataProvider()->getPlayer($username);
                if ($playerData !== null) {
                    switch ($scope) {
                        case "profile:nickname":
                            $data[$scope] = $playerData->getUsername();
                            break;
                        case "profile:uuid":
                            $data[$scope] = $playerData->getUniqueId()->toString();
                            break;
                        case "profile:registration_date":
                            $data[$scope] = date(DATE_ISO8601, (int)($playerData->getRegistrationDate() / 1000));
                            break;
                    }
                }
                continue;
            }

            // Queue scopes for external providers
            if (isset($this->scopeProviders[$scope])) {
                $provider = $this->scopeProviders[$scope];
                $providerQueue[spl_object_hash($provider)][] = $scope;
            }
        }

        // Process external providers
        foreach ($providerQueue as $hash => $providerScopes) {
            $provider = $this->scopeProviders[$providerScopes[0]]; // Get provider from the first scope in the list
            $providerData = $provider->retrieveScopeData($username, $providerScopes);
            $data = array_merge($data, $providerData);
        }

        return $data;
    }
}

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

class RateLimitProvider {

    /** @var array<string, int> */
    private array $limits;

    /** @var array<string, list<int>> */
    private array $requests = [];

    public function __construct(array $clientConfigs) {
        $this->limits = [];
        foreach ($clientConfigs as $clientId => $config) {
            $this->limits[$clientId] = (int)($config['rate-limits']['requests-per-minute'] ?? 60);
        }
    }

    public function recordRequest(string $clientId): void {
        $this->requests[$clientId][] = time();
    }

    public function isRateLimited(string $clientId): bool {
        if (!isset($this->limits[$clientId])) {
            // No limit configured for this client, so not limited.
            return false;
        }

        if (!isset($this->requests[$clientId])) {
            $this->requests[$clientId] = [];
            return false;
        }

        $limit = $this->limits[$clientId];
        $currentTime = time();
        $window = 60; // 60 seconds for per-minute limit

        // Remove requests older than the time window
        $this->requests[$clientId] = array_filter(
            $this->requests[$clientId],
            fn($timestamp) => ($currentTime - $timestamp) < $window
        );

        // Check if the request count exceeds the limit
        if (count($this->requests[$clientId]) > $limit) {
            return true; // Rate limited
        }

        return false;
    }
}

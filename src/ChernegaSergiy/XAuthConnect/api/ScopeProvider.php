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

namespace ChernegaSergiy\XAuthConnect\api;

/**
 * Interface for other plugins to implement to provide their own custom scopes to XAuthConnect.
 */
interface ScopeProvider {

    /**
     * Returns an array of scope names this provider can handle.
     * The scopes should be unique, e.g., "economy:balance", "stats:kills".
     *
     * @return string[]
     */
    public function getProvidedScopes(): array;

    /**
     * Retrieves the data for the given scopes for a specific user.
     *
     * @param string $username The user for whom to fetch data.
     * @param string[] $scopes An array of scopes this provider is responsible for, which were requested by the client.
     * @return array A key-value array where keys are the scope names and values are the corresponding data.
     *               Example: ["economy:balance" => 1500.50, "economy:rank" => "Gold"]
     */
    public function retrieveScopeData(string $username, array $scopes): array;
}

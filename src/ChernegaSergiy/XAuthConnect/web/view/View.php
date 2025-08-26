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

namespace ChernegaSergiy\XAuthConnect\web\view;

use pocketmine\plugin\Plugin;

class View {

    private Plugin $plugin;
    private string $dataPath;

    public function __construct(Plugin $plugin) {
        $this->plugin = $plugin;
        $this->dataPath = $plugin->getDataFolder() . "web/";
    }

    public function renderLoginPage(array $oauthParams, string $clientName, ?string $error = null): string {
        $templatePath = $this->dataPath . "login.html";

        $loginPage = @file_get_contents($templatePath);
        if ($loginPage === false) {
            return "Login page template not found.";
        }

        $hiddenFields = "";
        foreach ($oauthParams as $key => $value) {
            $hiddenFields .= sprintf("<input type=\"hidden\" name=\"%s\" value=\"%s\" />\n", htmlspecialchars((string)$key), htmlspecialchars((string)$value));
        }

        $errorMessageHtml = $error ? "<div class=\"alert alert-danger\">" . htmlspecialchars($error) . "</div>" : "";

        $loginPage = str_replace("{{oauth_params}}", $hiddenFields, $loginPage);
        $loginPage = str_replace("{{client_name}}", htmlspecialchars($clientName), $loginPage);
        $loginPage = str_replace("{{error_message}}", $errorMessageHtml, $loginPage);

        return $loginPage;
    }

    public function renderConsentPage(array $oauthParams, string $clientName, array $requestedScopes): string {
        $templatePath = $this->dataPath . "consent.html";

        $consentPage = @file_get_contents($templatePath);
        if ($consentPage === false) {
            return "Consent page template not found.";
        }

        $hiddenFields = "";
        foreach ($oauthParams as $key => $value) {
            // Exclude username from hidden fields as it's handled separately
            if ($key === "username") {
                continue;
            }
            $hiddenFields .= sprintf("<input type=\"hidden\" name=\"%s\" value=\"%s\" />\n", htmlspecialchars((string)$key), htmlspecialchars((string)$value));
        }

        $scopesListHtml = "";
        foreach ($requestedScopes as $scope) {
            $scopesListHtml .= sprintf("<li class=\"list-group-item\">%s</li>\n", htmlspecialchars($scope));
        }

        $consentPage = str_replace("{{oauth_params}}", $hiddenFields, $consentPage);
        $consentPage = str_replace("{{client_name}}", htmlspecialchars($clientName), $consentPage);
        $consentPage = str_replace("{{scopes_list}}", $scopesListHtml, $consentPage);
        $consentPage = str_replace("{{username}}", htmlspecialchars($oauthParams["username"] ?? ""), $consentPage);

        return $consentPage;
    }
}

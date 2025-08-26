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

namespace ChernegaSergiy\XAuthConnect;

use ChernegaSergiy\XAuthConnect\api\ScopeProvider;
use ChernegaSergiy\XAuthConnect\provider\ClientProvider;
use ChernegaSergiy\XAuthConnect\provider\CodeProvider;
use ChernegaSergiy\XAuthConnect\provider\DatabaseProvider;
use ChernegaSergiy\XAuthConnect\provider\RateLimitProvider;
use ChernegaSergiy\XAuthConnect\provider\ScopeManager;
use ChernegaSergiy\XAuthConnect\provider\TokenProvider;
use ChernegaSergiy\XAuthConnect\web\controller\WebController;
use ChernegaSergiy\XAuthConnect\web\view\View;
use Hebbinkpro\WebServer\http\server\HttpServerInfo;
use Hebbinkpro\WebServer\router\Router;
use Hebbinkpro\WebServer\WebServer;
use Luthfi\XAuth\Main as XAuth;
use pocketmine\plugin\PluginBase;

class Main extends PluginBase {

    private ?WebServer $webServer = null;
    private ?ScopeManager $scopeManager = null;
    private ?DatabaseProvider $databaseProvider = null;

    public function onEnable(): void {
        $this->getLogger()->info("Starting XAuthConnect...");

        $xauthApi = $this->getServer()->getPluginManager()->getPlugin("XAuth");
        if (!$xauthApi instanceof XAuth) {
            $this->getLogger()->critical("XAuth plugin not found. Disabling XAuthConnect.");
            $this->getServer()->getPluginManager()->disablePlugin($this);
            return;
        }

        $this->saveDefaultConfig();
        $this->saveResource("web/login.html");
        $this->saveResource("web/consent.html");
        $config = $this->getConfig();
        $webIntegrationConfig = $config->get("web-integration", []);
        if (!($webIntegrationConfig["enabled"] ?? false)) {
            $this->getLogger()->notice("Web integration is disabled. The web server will not be started.");
            return;
        }

        // Initialize Database and other providers
        $this->databaseProvider = new DatabaseProvider($this);
        $this->scopeManager = new ScopeManager($xauthApi);
        $clientConfigs = $webIntegrationConfig["registered-clients"] ?? [];
        $codeTimeout = (int)($webIntegrationConfig["code-timeout"] ?? 300);

        $clientProvider = new ClientProvider($config);
        $codeProvider = new CodeProvider($this->databaseProvider, $codeTimeout);
        $rateLimitProvider = new RateLimitProvider($clientConfigs);
        $tokenProvider = new TokenProvider($this->databaseProvider);
        $view = new View($this);
        $baseUrl = (string)($webIntegrationConfig["base-url"] ?? "http://127.0.0.1:8010");
        $webController = new WebController($clientProvider, $codeProvider, $rateLimitProvider, $tokenProvider, $this->scopeManager, $view, $baseUrl);

        // Setup and start the web server
        $port = (int)($webIntegrationConfig["server-port"] ?? 8010);
        $router = new Router();
        $router->get("/xauth/authorize", [$webController, 'handleAuthorize']);
        $router->post("/xauth/login", [$webController, 'handleLogin']);
        $router->get("/xauth/consent", [$webController, 'handleConsent']);
        $router->post("/xauth/token", [$webController, 'handleToken']);
        $router->post("/xauth/token/refresh", [$webController, 'handleRefreshToken']);
        $router->post("/xauth/introspect", [$webController, 'handleIntrospectToken']);
        $router->post("/xauth/revoke", [$webController, 'handleRevokeToken']);
        $router->get("/xauth/user", [$webController, 'handleUser']);

        $router->getStatic("/xauth/assets/", $this->getDataFolder() . "web/static/");

        $serverInfo = new HttpServerInfo("0.0.0.0", $port, $router);
        $this->webServer = new WebServer($this, $serverInfo);

        $sslConfig = $webIntegrationConfig["ssl"] ?? [];
        $certFolder = (string)($sslConfig["cert-folder"] ?? "cert");
        $passphrase = is_string($sslConfig["passphrase"]) ? $sslConfig["passphrase"] : null;

        if ($this->webServer->detectSSL(null, $certFolder, $passphrase)) {
            $this->getLogger()->info("SSL enabled (folder: {$certFolder}).");
        } else {
            $this->getLogger()->warning("SSL not found in '{$certFolder}'. Running on HTTP.");
        }

        $this->webServer->start();
        $this->getLogger()->info("XAuthConnect web server started at: " . $this->webServer->getServerInfo()->getAddress());
    }

    public function onDisable(): void {
        if ($this->webServer !== null && $this->webServer->isStarted()) {
            $this->getLogger()->info("Stopping XAuthConnect web server...");
            $this->webServer->close();
        }
        if ($this->databaseProvider !== null) {
            $this->databaseProvider->close();
        }
    }

    /**
     * API method for other plugins to register their scope providers.
     * @param ScopeProvider $provider
     */
    public function registerScopeProvider(ScopeProvider $provider): void {
        if ($this->scopeManager !== null) {
            $this->scopeManager->registerProvider($provider);
            $this->getLogger()->info("Registered new scope provider: " . get_class($provider));
        } else {
            $this->getLogger()->warning("Could not register scope provider because the ScopeManager is not initialized.");
        }
    }
}

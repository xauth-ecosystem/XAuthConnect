<?php

declare(strict_types=1);

namespace ChernegaSergiy\XAuthConnect;

spl_autoload_register(function ($class) {
    $prefix = 'Firebase\\JWT\\';
    $base_dir = __DIR__ . '/../../lib/php-jwt/';

    $len = strlen($prefix);
    if (strncmp($prefix, $class, $len) !== 0) {
        return;
    }

    $relative_class = substr($class, $len);
    $file = $base_dir . str_replace('\\', '/', $relative_class) . '.php';

    if (file_exists($file)) {
        require $file;
    }
});

use ChernegaSergiy\AsyncHttp\Server\HttpServer;
use ChernegaSergiy\AsyncHttp\Server\Router;
use ChernegaSergiy\XAuthConnect\Pkce\CodeChallengeManager;
use ChernegaSergiy\XAuthConnect\ScopeProvider\ScopeProviderInterface;
use ChernegaSergiy\XAuthConnect\ScopeProvider\ProfileScopeProvider;
use ChernegaSergiy\XAuthConnect\Service\IdTokenService;
use ChernegaSergiy\XAuthConnect\Service\KeyService;
use ChernegaSergiy\XAuthConnect\Storage\InMemoryStore;
use Luthfi\XAuth\Main as XAuth;
use pocketmine\plugin\PluginBase;
use pocketmine\scheduler\ClosureTask;
use SOFe\AwaitGenerator\Await;
use Throwable;

class Main extends PluginBase
{
    private ?HttpServer $webServer = null;
    private ?XAuth $xauth = null;
    private ?WebController $webController = null;
    private ?InMemoryStore $store = null;
    private array $scopeProviders = [];
    private ?IdTokenService $idTokenService = null;

    public function getHttpServer(): ?HttpServer
    {
        return $this->webServer;
    }

    public function registerScopeProvider(ScopeProviderInterface $provider): void
    {
        $this->scopeProviders[] = $provider;
    }

    public function onEnable(): void
    {
        $this->saveDefaultConfig();

        @mkdir($this->getDataFolder() . "web");
        $this->saveResource("web/login.html", true);
        $this->saveResource("web/consent.html", true);

        $keyPath = $this->getDataFolder() . $this->getConfig()->getNested('oidc.private_key_path', 'private.key');
        $this->getLogger()->info("Initializing KeyService with key path: " . $keyPath);
        $keyService = new KeyService($keyPath, $this->getLogger());
        $issuerUrl = $this->getConfig()->getNested('oidc.issuer_url', 'http://127.0.0.1:8081');
        $this->idTokenService = new IdTokenService($keyService, $issuerUrl);

        $this->store = new InMemoryStore();

        $this->registerScopeProvider(new ProfileScopeProvider());

        $this->xauth = $this->getServer()->getPluginManager()->getPlugin("XAuth");
        if (!$this->xauth instanceof XAuth) {
            $this->getLogger()->error("XAuth plugin not found. Please install XAuth to use this plugin.");
            $this->getServer()->getPluginManager()->disablePlugin($this);
            return;
        }

        $codeChallengeManager = new CodeChallengeManager();

        $this->webController = new WebController(
            $this->store,
            $this->getConfig(),
            $keyService,
            $this->idTokenService,
            $this->getLogger(),
            $this->getDataFolder(),
            $this->getScheduler(),
            $this->getServer(),
            $this->scopeProviders,
            $codeChallengeManager
        );

        $port = (int)$this->getConfig()->getNested("web-integration.server-port", 8081);
        $sslConfig = $this->getConfig()->getNested("web-integration.ssl", ['enabled' => false]);

        $this->webServer = new HttpServer($this, '0.0.0.0', $port, $sslConfig);
        $router = $this->webServer->getRouter();
        $this->registerRoutes($router);

        $this->getScheduler()->scheduleRepeatingTask(new ClosureTask(
            fn() => $this->processLoginQueue()
        ), 10);

        $this->webServer->start();
    }

    private function registerRoutes(Router $router): void
    {
        $router->get("/.well-known/openid-configuration", [$this->webController, "handleDiscovery"]);
        $router->get("/xauth/jwks", [$this->webController, "handleJwks"]);
        $router->get("/xauth/authorize", [$this->webController, "handleAuthorizeGet"]);
        $router->post("/xauth/login", [$this->webController, "handleLoginPost"]);
        $router->get("/xauth/login-events", [$this->webController, "handleLoginEvents"]);
        $router->get("/xauth/consent", [$this->webController, "handleConsentGet"]);
        $router->post("/xauth/consent", [$this->webController, "handleConsentPost"]);
        $router->post("/xauth/token", [$this->webController, "handleTokenPost"]);

        $router->post("/xauth/introspect", [$this->webController, "handleIntrospectPost"]);
        $router->post("/xauth/revoke", [$this->webController, "handleRevokePost"]);
        $router->get("/xauth/user", [$this->webController, "handleUserRequest"]);
    }

    public function processLoginQueue(): void
    {
        if ($this->store === null) {
            return;
        }

        foreach ($this->store->requestQueue as $requestId => $requestData) {
            $data = unserialize($requestData);
            $username = $data['username'];
            $password = $data['password'];
            $oauthParams = $data['oauth_params'];

            unset($this->store->requestQueue[$requestId]);

            $xauth = $this->xauth;
            $loginResults = $this->store->loginResults;
            $logger = $this->getLogger();
            Await::f2c(
                function () use ($requestId, $username, $password, $oauthParams, $xauth, $loginResults, $logger) {
                    try {
                        $authService = $xauth->getAuthenticationService();
                        if ($authService === null) {
                            $loginResults[$requestId] = serialize(['success' => false, 'username' => $username, 'oauth_params' => $oauthParams]);
                            return;
                        }
                        $result = yield from $authService->checkPlayerPassword($username, $password);
                        $logger->info("Login check result for {" . $username . ": " . ($result ? "SUCCESS" : "FAILURE"));
                        $loginResults[$requestId] = serialize(['success' => $result, 'username' => $username, 'oauth_params' => $oauthParams]);
                    } catch (Throwable $e) {
                        $logger->error("Error while checking password: " . $e->getMessage());
                        $loginResults[$requestId] = serialize(['success' => false, 'username' => $username, 'oauth_params' => $oauthParams]);
                    }
                }
            );
        }
    }

    public function onDisable(): void
    {
        if (isset($this->webServer)) {
            $this->webServer->stop();
        }
    }
}

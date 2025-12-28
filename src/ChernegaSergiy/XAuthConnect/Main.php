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
use ChernegaSergiy\AsyncHttp\Server\Request;
use ChernegaSergiy\AsyncHttp\Server\Response;
use ChernegaSergiy\AsyncHttp\Server\Router;
use ChernegaSergiy\AsyncHttp\Util\HttpStatus;
use ChernegaSergiy\XAuthConnect\ScopeProvider\ProfileScopeProvider;
use ChernegaSergiy\XAuthConnect\Service\IdTokenService;
use ChernegaSergiy\XAuthConnect\Service\KeyService;
use Generator;
use Luthfi\XAuth\Main as XAuth;
use pocketmine\plugin\PluginBase;
use pocketmine\scheduler\ClosureTask;
use pocketmine\scheduler\TaskScheduler;
use pocketmine\Server;
use pmmp\thread\ThreadSafe;
use pmmp\thread\ThreadSafeArray;
use SOFe\AwaitGenerator\Await;
use Throwable;

class Main extends PluginBase
{
    private ?HttpServer $webServer = null;
    private ?XAuth $xauth = null;
    private ThreadSafeArray $requestQueue;
    private ThreadSafeArray $loginResults;
    private ThreadSafeArray $authorizationCodes;
    private ThreadSafeArray $accessTokens;
    private ThreadSafeArray $refreshTokens;
    private ThreadSafeArray $debugMessages;
    private array $scopeProviders = [];

    private ?KeyService $keyService = null;
    private ?IdTokenService $idTokenService = null;

    public function getHttpServer(): ?HttpServer
    {
        return $this->webServer;
    }

    public function registerScopeProvider(ScopeProvider $provider): void
    {
        $this->scopeProviders[] = $provider;
    }

    private static function retrieveUserData(TaskScheduler $scheduler, Server $server, array $scopeProviders, string $username, array $scopes): Generator
    {
        $server->getLogger()->info("[XAuthConnect-Debug] Starting retrieveUserData for {$username}");
        $userData = [];
        $promises = [];

        foreach ($scopeProviders as $provider) {
            /** @var ScopeProvider $provider */
            $providedScopes = $provider->getProvidedScopes();
            $intersectingScopes = array_intersect($scopes, $providedScopes);

            if (empty($intersectingScopes)) {
                continue;
            }

            if ($provider instanceof ThreadSafe) {
                try {
                    $data = $provider->retrieveScopeData($server, $username, $intersectingScopes);
                    $server->getLogger()->info("[XAuthConnect-Debug] ThreadSafe provider returned: " . json_encode($data));
                    $userData = array_merge($userData, $data);
                } catch (Throwable $e) {
                    $server->getLogger()->logException($e);
                }
            } else {
                $promises[] = Await::promise(function ($resolve) use ($scheduler, $server, $provider, $username, $intersectingScopes) {
                    $scheduler->scheduleTask(new ClosureTask(function () use ($provider, $server, $username, $intersectingScopes, $resolve) {
                        try {
                            $data = $provider->retrieveScopeData($server, $username, $intersectingScopes);
                            $server->getLogger()->info("[XAuthConnect-Debug] Non-ThreadSafe provider task returned: " . json_encode($data));
                            $resolve($data);
                        } catch (Throwable $e) {
                            $server->getLogger()->logException($e);
                            $resolve([]);
                        }
                    }));
                });
            }
        }

        if (!empty($promises)) {
            $results = yield from Await::all($promises);
            $server->getLogger()->info("[XAuthConnect-Debug] Await::all results: " . json_encode($results));
            foreach ($results as $result) {
                if (!empty($result)) {
                    $userData = array_merge($userData, $result);
                }
            }
        }

        $server->getLogger()->info("[XAuthConnect-Debug] Final userData: " . json_encode($userData));
        return $userData;
    }

    public function onEnable(): void
    {
        $this->saveDefaultConfig();

        @mkdir($this->getDataFolder() . "web");
        $this->saveResource("web/login.html", true);
        $this->saveResource("web/consent.html", true);

        $keyPath = $this->getDataFolder() . $this->getConfig()->getNested('oidc.private_key_path', 'private.key');
        $this->getLogger()->info("Initializing KeyService with key path: " . $keyPath);
        $this->keyService = new KeyService($keyPath, $this->getLogger());
        $issuerUrl = $this->getConfig()->getNested('oidc.issuer_url', 'http://127.0.0.1:8081');
        $this->idTokenService = new IdTokenService($this->keyService, $issuerUrl);

        $this->requestQueue = new ThreadSafeArray();
        $this->loginResults = new ThreadSafeArray();
        $this->authorizationCodes = new ThreadSafeArray();
        $this->accessTokens = new ThreadSafeArray();
        $this->refreshTokens = new ThreadSafeArray();
        $this->debugMessages = new ThreadSafeArray();

        $this->registerScopeProvider(new ProfileScopeProvider());

        $this->xauth = $this->getServer()->getPluginManager()->getPlugin("XAuth");
        if (!$this->xauth instanceof XAuth) {
            $this->getLogger()->error("XAuth plugin not found. Please install XAuth to use this plugin.");
            $this->getServer()->getPluginManager()->disablePlugin($this);
            return;
        }

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
        $router->get("/.well-known/openid-configuration", [$this, "handleDiscovery"]);
        $router->get("/xauth/jwks", [$this, "handleJwks"]);
        $router->get("/xauth/authorize", [$this, "handleAuthorizeGet"]);
        $router->post("/xauth/login", [$this, "handleLoginPost"]);
        $router->get("/xauth/login-events", [$this, "handleLoginEvents"]);
        $router->get("/xauth/consent", [$this, "handleConsentGet"]);
        $router->post("/xauth/consent", [$this, "handleConsentPost"]);
        $router->post("/xauth/token", [$this, "handleTokenPost"]);

        $router->post("/xauth/introspect", [$this, "handleIntrospectPost"]);
        $router->post("/xauth/revoke", [$this, "handleRevokePost"]);
        $router->get("/xauth/user", [$this, "handleUserRequest"]);
    }

    public function handleDiscovery(Request $request, Response $response): void
    {
        $issuerUrl = $this->getConfig()->getNested('oidc.issuer_url', 'http://127.0.0.1:8081');
        $discoveryData = [
            'issuer' => $issuerUrl,
            'authorization_endpoint' => $issuerUrl . '/xauth/authorize',
            'token_endpoint' => $issuerUrl . '/xauth/token',
            'userinfo_endpoint' => $issuerUrl . '/xauth/user',
            'jwks_uri' => $issuerUrl . '/xauth/jwks',
            'revocation_endpoint' => $issuerUrl . '/xauth/revoke',
            'introspection_endpoint' => $issuerUrl . '/xauth/introspect',
            'scopes_supported' => ['openid', 'profile:nickname', 'profile:uuid'],
            'response_types_supported' => ['code'],
            'grant_types_supported' => ['authorization_code', 'refresh_token'],
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => ['RS256'],
            'token_endpoint_auth_methods_supported' => ['client_secret_post'],
        ];
        $response->json($discoveryData);
    }

    public function handleJwks(Request $request, Response $response): void
    {
        $jwk = $this->keyService->getPublicKeyAsJwk();
        $response->json(['keys' => [$jwk]]);
    }

    public function handleAuthorizeGet(Request $request, Response $response): void
    {
        $configObject = $this->getConfig();
        $dataFolder = $this->getDataFolder();
        $queryParams = $request->getQueryParams();
        $clientId = $queryParams["client_id"] ?? null;
        $redirectUri = $queryParams["redirect_uri"] ?? null;
        $scope = $queryParams["scope"] ?? null;
        $codeChallenge = $queryParams["code_challenge"] ?? null;
        $codeChallengeMethod = $queryParams["code_challenge_method"] ?? null;
        $state = $queryParams["state"] ?? null;
        $nonce = $queryParams["nonce"] ?? null; // Capture nonce
        $errorParam = $queryParams["error"] ?? null;

        if ($clientId === null || $redirectUri === null || $scope === null || $codeChallenge === null || $codeChallengeMethod === null) {
            $response->errorPage($request->getHeader('Accept'), HttpStatus::BAD_REQUEST, "Missing one or more required OAuth 2.0 parameters.");
            return;
        }

        $registeredClients = $configObject->getNested("web-integration.registered-clients") ?? [];
        $clientConfig = null;
        foreach ($registeredClients as $client) {
            if (isset($client["client-id"]) && $client["client-id"] === $clientId) {
                $clientConfig = $client;
                break;
            }
        }

        if ($clientConfig === null) {
            $response->errorPage($request->getHeader('Accept'), HttpStatus::BAD_REQUEST, "The provided client_id is not registered.");
            return;
        }
        $clientName = $clientConfig["name"] ?? $clientId;

        $allowedRedirectUris = $clientConfig["redirect-uris"] ?? [];
        if (!in_array($redirectUri, $allowedRedirectUris)) {
            $response->errorPage($request->getHeader('Accept'), HttpStatus::BAD_REQUEST, "The provided redirect_uri is not allowed for this client.");
            return;
        }

        $scope = urldecode($scope);
        $requestedScopes = explode(" ", $scope);
        $allowedScopes = array_merge($clientConfig["allowed-scopes"] ?? [], ['openid']); // Always allow openid

        foreach ($requestedScopes as $reqScope) {
            if (!in_array($reqScope, $allowedScopes)) {
                $errorRedirectUri = $redirectUri . (str_contains($redirectUri, '?') ? '&' : '?') . "error=invalid_scope" . ($state !== null ? "&state=" . urlencode($state) : "");
                $response->setStatus(HttpStatus::FOUND)->setHeader("Location", $errorRedirectUri)->send('');
                return;
            }
        }

        if (in_array('openid', $requestedScopes) && $nonce === null) {
            $response->errorPage($request->getHeader('Accept'), HttpStatus::BAD_REQUEST, "Nonce parameter is required for OpenID Connect requests.");
            return;
        }

        if (!in_array($codeChallengeMethod, ["S256", "plain"])) {
            $errorRedirectUri = $redirectUri . (str_contains($redirectUri, '?') ? '&' : '?') . "error=invalid_request" . ($state !== null ? "&state=" . urlencode($state) : "");
            $response->setStatus(HttpStatus::FOUND)->setHeader("Location", $errorRedirectUri)->send('');
            return;
        }

        $loginHtmlPath = $dataFolder . "web/login.html";
        $loginHtml = file_get_contents($loginHtmlPath);
        if ($loginHtml === false) {
            $response->errorPage($request->getHeader('Accept'), HttpStatus::INTERNAL_SERVER_ERROR, "Login template not found.");
            return;
        }

        $oauthParamsHtml = "";
        $oauthParams = [
            "client_id" => $clientId,
            "redirect_uri" => $redirectUri,
            "scope" => $scope,
            "code_challenge" => $codeChallenge,
            "code_challenge_method" => $codeChallengeMethod,
        ];
        if ($state !== null) {
            $oauthParams["state"] = $state;
        }
        if ($nonce !== null) {
            $oauthParams["nonce"] = $nonce;
        }

        foreach ($oauthParams as $key => $value) {
            $oauthParamsHtml .= "<input type=\"hidden\" name=\"" . htmlspecialchars($key) . "\" value=\"" . htmlspecialchars($value) . "\">
";
        }

        $errorMessageHtml = "";
        if ($errorParam === "login_failed") {
            $errorMessageHtml = "<div class=\"alert alert-danger mt-3\">Login failed. Incorrect username or password.</div>";
        }

        $loginHtml = str_replace("{{client_name}}", htmlspecialchars($clientName), $loginHtml);
        $loginHtml = str_replace("{{error_message}}", $errorMessageHtml, $loginHtml);
        $loginHtml = str_replace("{{oauth_params}}", $oauthParamsHtml, $loginHtml);

        $response->html($loginHtml);
    }

    public function handleLoginPost(Request $request, Response $response): void
    {
        parse_str($request->getBody(), $body);

        $username = $body["username"] ?? null;
        $password = $body["password"] ?? null;

        unset($body['username'], $body['password']);

        if ($username === null || $password === null) {
            $response->setStatus(HttpStatus::BAD_REQUEST)->json(['error' => 'Missing username or password']);
            return;
        }

        $requestId = uniqid("login_");
        $this->requestQueue[$requestId] = serialize(['username' => $username, 'password' => $password, 'oauth_params' => $body]);

        $response->json(['request_id' => $requestId]);
    }

    public function handleLoginEvents(Request $request, Response $response, $socket): \Generator
    {
        $queryParams = $request->getQueryParams();
        $requestId = $queryParams["request_id"] ?? null;

        $response->startStreaming();

        $headers = [
            "HTTP/1.1 200 OK",
            "Content-Type: text/event-stream",
            "Cache-Control: no-cache",
            "Connection: keep-alive",
            "Access-Control-Allow-Origin: *"
        ];
        @fwrite($socket, implode("\r\n", $headers) . "\r\n\r\n");

        $loginResult = yield from Await::promise(function($resolve) use ($requestId) {
            $startTime = time();
            $timeout = 30; // 30 seconds timeout

            $task = new ClosureTask(function() use ($requestId, $resolve, $startTime, $timeout, &$task) {
                if ((time() - $startTime) > $timeout) {
                    if(isset($this->loginResults[$requestId])) unset($this->loginResults[$requestId]);
                    if(isset($this->requestQueue[$requestId])) unset($this->requestQueue[$requestId]);
                    $resolve(null); // Resolve with null on timeout
                    if ($task !== null) $task->getHandler()->cancel();
                    return;
                }

                if (isset($this->loginResults[$requestId])) {
                    $result = unserialize($this->loginResults[$requestId]);
                    unset($this->loginResults[$requestId]);
                    $resolve($result);
                    if ($task !== null) $task->getHandler()->cancel();
                }
            });

            $this->getScheduler()->scheduleRepeatingTask($task, 10);
        });

        if (!is_resource($socket) || feof($socket)) {
            $this->getLogger()->warning("SSE socket was closed by the client before login result was ready for request $requestId.");
            return;
        }

        if ($loginResult === null) {
            $this->getLogger()->warning("SSE request $requestId timed out.");
            @fwrite($socket, "event: login_timeout\ndata: {\"error\": \"timeout\"}\n\n");
            return;
        }

        $oauthParams = $loginResult['oauth_params'];
        $finalRedirectUrl = "";

        if ($loginResult['success']) {
            $authCode = bin2hex(random_bytes(16));
            $codeTimeout = (int)$this->getConfig()->getNested("web-integration.code-timeout", 300);

            $authCodeData = [
                "client_id" => $oauthParams["client_id"],
                "redirect_uri" => $oauthParams["redirect_uri"],
                "scope" => $oauthParams["scope"],
                "code_challenge" => $oauthParams["code_challenge"],
                "code_challenge_method" => $oauthParams["code_challenge_method"],
                "username" => $loginResult["username"],
                "auth_time" => time(),
                "expires_at" => time() + $codeTimeout,
            ];
            if (isset($oauthParams["nonce"])) {
                $authCodeData["nonce"] = $oauthParams["nonce"];
            }

            $this->authorizationCodes[$authCode] = serialize($authCodeData);

            $oauthParams['code'] = $authCode;
            $oauthParams['username'] = $loginResult['username'];
            $finalRedirectUrl = "/xauth/consent?" . http_build_query($oauthParams);
        } else {
            $oauthParams['error'] = 'login_failed';
            $finalRedirectUrl = "/xauth/authorize?" . http_build_query($oauthParams);
        }

        $data = json_encode(["redirect_url" => $finalRedirectUrl]);
        @fwrite($socket, "event: login_result\ndata: $data\n\n");
    }

    public function handleConsentGet(Request $request, Response $response): void
    {
        $configObject = $this->getConfig();
        $dataFolder = $this->getDataFolder();
        $queryParams = $request->getQueryParams();
        $clientId = $queryParams["client_id"] ?? null;
        $redirectUri = $queryParams["redirect_uri"] ?? null;
        $scope = $queryParams["scope"] ?? null;
        $code = $queryParams["code"] ?? null;
        $codeChallenge = $queryParams["code_challenge"] ?? null;
        $codeChallengeMethod = $queryParams["code_challenge_method"] ?? null;
        $username = $queryParams["username"] ?? null;
        $state = $queryParams["state"] ?? null;
        $nonce = $queryParams["nonce"] ?? null;

        if ($clientId === null || $redirectUri === null || $scope === null || $code === null || $codeChallenge === null || $codeChallengeMethod === null || $username === null) {
            $response->errorPage($request->getHeader('Accept'), HttpStatus::BAD_REQUEST, "Missing one or more required OAuth 2.0 parameters.");
            return;
        }

        $registeredClients = $configObject->getNested("web-integration.registered-clients") ?? [];
        $clientConfig = null;
        foreach ($registeredClients as $client) {
            if (isset($client["client-id"]) && $client["client-id"] === $clientId) {
                $clientConfig = $client;
                break;
            }
        }
        if ($clientConfig === null) {
            $response->errorPage($request->getHeader('Accept'), HttpStatus::BAD_REQUEST, "The provided client_id is not registered.");
            return;
        }
        $clientName = $clientConfig["name"] ?? $clientId;

        $scope = str_replace("+ ", " ", $scope);
        $requestedScopes = explode(" ", $scope);
        $allowedScopes = array_merge($clientConfig["allowed-scopes"] ?? [], ['openid']);

        foreach ($requestedScopes as $reqScope) {
            if (!in_array($reqScope, $allowedScopes)) {
                $response->errorPage($request->getHeader('Accept'), HttpStatus::BAD_REQUEST, "One or more requested scopes are not allowed for this client.");
                return;
            }
        }

        if (!in_array($codeChallengeMethod, ["S256", "plain"])) {
            $errorRedirectUri = $redirectUri . (str_contains($redirectUri, '?') ? '&' : '?') . "error=invalid_request" . ($state !== null ? "&state=" . urlencode($state) : "");
            $response->setStatus(HttpStatus::FOUND)->setHeader("Location", $errorRedirectUri)->send('');
            return;
        }

        if (!isset($this->authorizationCodes[$code])) {
            $response->errorPage($request->getHeader('Accept'), HttpStatus::BAD_REQUEST, "Authorization code not found, expired, or already used.");
            return;
        }
        $authCodeData = unserialize($this->authorizationCodes[$code]);

        if ($authCodeData["expires_at"] < time()) {
            unset($this->authorizationCodes[$code]);
            $response->errorPage($request->getHeader('Accept'), HttpStatus::BAD_REQUEST, "Authorization code has expired.");
            return;
        }

        if ($authCodeData["client_id"] !== $clientId || $authCodeData["redirect_uri"] !== $redirectUri || $authCodeData["scope"] !== $scope || $authCodeData["code_challenge"] !== $codeChallenge || $authCodeData["code_challenge_method"] !== $codeChallengeMethod || $authCodeData["username"] !== $username) {
            unset($this->authorizationCodes[$code]);
            $response->errorPage($request->getHeader('Accept'), HttpStatus::BAD_REQUEST, "Authorization code parameter mismatch.");
            return;
        }

        $consentHtmlPath = $dataFolder . "web/consent.html";
        $consentHtml = file_get_contents($consentHtmlPath);
        if ($consentHtml === false) {
            $response->errorPage($request->getHeader('Accept'), HttpStatus::INTERNAL_SERVER_ERROR, "Consent template not found.");
            return;
        }

        $oauthParamsHtml = "";
        $oauthParams = [
            "client_id" => $clientId,
            "redirect_uri" => $redirectUri,
            "scope" => $scope,
            "code" => $code,
            "code_challenge" => $codeChallenge,
            "code_challenge_method" => $codeChallengeMethod,
            "username" => $username,
        ];
        if ($state !== null) {
            $oauthParams["state"] = $state;
        }
        if ($nonce !== null) {
            $oauthParams["nonce"] = $nonce;
        }

        foreach ($oauthParams as $key => $value) {
            $oauthParamsHtml .= "<input type=\"hidden\" name=\"" . htmlspecialchars($key) . "\" value=\"" . htmlspecialchars($value) . "\">
";
        }

        $consentHtml = str_replace("{{client_name}}", htmlspecialchars($clientName), $consentHtml);
        $consentHtml = str_replace("{{scopes_list}}", htmlspecialchars(str_replace(" ", ", ", $scope)), $consentHtml);
        $consentHtml = str_replace("{{username}}", htmlspecialchars($username), $consentHtml);
        $consentHtml = str_replace("{{oauth_params}}", $oauthParamsHtml, $consentHtml);

        $response->html($consentHtml);
    }

    public function handleConsentPost(Request $request, Response $response): void
    {
        $configObject = $this->getConfig();
        parse_str($request->getBody(), $body);

        $clientId = $body["client_id"] ?? null;
        $redirectUri = $body["redirect_uri"] ?? null;
        $scope = $body["scope"] ?? null;
        $code = $body["code"] ?? null;
        $codeChallenge = $body["code_challenge"] ?? null;
        $codeChallengeMethod = $body["code_challenge_method"] ?? null;
        $username = $body["username"] ?? null;
        $state = $body["state"] ?? null;
        $consentAction = $body["consent_action"] ?? null;

        if ($clientId === null || $redirectUri === null || $scope === null || $code === null || $codeChallenge === null || $codeChallengeMethod === null || $username === null || $consentAction === null) {
            $response->errorPage($request->getHeader('Accept'), HttpStatus::BAD_REQUEST, "Missing one or more required OAuth 2.0 parameters.");
            return;
        }

        $registeredClients = $configObject->getNested("web-integration.registered-clients") ?? [];
        $clientConfig = null;
        foreach ($registeredClients as $client) {
            if (isset($client["client-id"]) && $client["client-id"] === $clientId) {
                $clientConfig = $client;
                break;
            }
        }
        if ($clientConfig === null) {
            $response->errorPage($request->getHeader('Accept'), HttpStatus::BAD_REQUEST, "The provided client_id is not registered.");
            return;
        }

        $allowedRedirectUris = $clientConfig["redirect-uris"] ?? [];
        if (!in_array($redirectUri, $allowedRedirectUris)) {
            $response->errorPage($request->getHeader('Accept'), HttpStatus::BAD_REQUEST, "The provided redirect_uri is not allowed for this client.");
            return;
        }

        $scope = urldecode($scope);
        $requestedScopes = explode(" ", $scope);
        $allowedScopes = array_merge($clientConfig["allowed-scopes"] ?? [], ['openid']);
        foreach ($requestedScopes as $reqScope) {
            if (!in_array($reqScope, $allowedScopes)) {
                $errorRedirectUri = $redirectUri . (str_contains($redirectUri, '?') ? '&' : '?') . "error=invalid_scope" . ($state !== null ? "&state=" . urlencode($state) : "");
                $response->setStatus(HttpStatus::FOUND)->setHeader("Location", $errorRedirectUri)->send('');
                return;
            }
        }

        if (!in_array($codeChallengeMethod, ["S256", "plain"])) {
            $errorRedirectUri = $redirectUri . (str_contains($redirectUri, '?') ? '&' : '?') . "error=invalid_request" . ($state !== null ? "&state=" . urlencode($state) : "");
            $response->setStatus(HttpStatus::FOUND)->setHeader("Location", $errorRedirectUri)->send('');
            return;
        }

        if (!isset($this->authorizationCodes[$code])) {
            $response->errorPage($request->getHeader('Accept'), HttpStatus::BAD_REQUEST, "Authorization code not found.");
            return;
        }
        $authCodeData = unserialize($this->authorizationCodes[$code]);

        if ($authCodeData["expires_at"] < time()) {
            unset($this->authorizationCodes[$code]);
            $response->errorPage($request->getHeader('Accept'), HttpStatus::BAD_REQUEST, "Authorization code expired.");
            return;
        }

        if ($authCodeData["client_id"] !== $clientId || $authCodeData["redirect_uri"] !== $redirectUri || $authCodeData["scope"] !== $scope || $authCodeData["code_challenge"] !== $codeChallenge || $authCodeData["code_challenge_method"] !== $codeChallengeMethod || $authCodeData["username"] !== $username) {
            unset($this->authorizationCodes[$code]);
            $response->errorPage($request->getHeader('Accept'), HttpStatus::BAD_REQUEST, "Authorization code mismatch or tampering detected.");
            return;
        }

        if ($consentAction === "approve") {
            $finalRedirectUri = $redirectUri . (str_contains($redirectUri, '?') ? '&' : '?') . "code=" . urlencode($code) . ($state !== null ? "&state=" . urlencode($state) : "");
            $response->setStatus(HttpStatus::FOUND)->setHeader("Location", $finalRedirectUri)->send('');
        } elseif ($consentAction === "deny") {
            unset($this->authorizationCodes[$code]);
            $finalRedirectUri = $redirectUri . (str_contains($redirectUri, '?') ? '&' : '?') . "error=access_denied" . ($state !== null ? "&state=" . urlencode($state) : "");
            $response->setStatus(HttpStatus::FOUND)->setHeader("Location", $finalRedirectUri)->send('');
        } else {
            $response->errorPage($request->getHeader('Accept'), HttpStatus::BAD_REQUEST, "Invalid consent action.");
        }
    }

    public function handleTokenPost(Request $request, Response $response): void
    {
        $this->getLogger()->info("handleTokenPost: Body: " . $request->getBody());
        $configObject = $this->getConfig();
        parse_str($request->getBody(), $body);

        $clientId = $body["client_id"] ?? null;
        $clientSecret = $body["client_secret"] ?? null;
        $code = $body["code"] ?? null;
        $codeVerifier = $body["code_verifier"] ?? null;
        $grantType = $body["grant_type"] ?? null;

        if ($grantType === "authorization_code") {
            // Existing authorization_code logic

            if ($clientId === null || $clientSecret === null || $code === null || $codeVerifier === null) {
                $response->json(["error" => "invalid_request", "error_description" => "Missing one or more required parameters."]);
                return;
            }

            $registeredClients = $configObject->getNested("web-integration.registered-clients") ?? [];
            $clientConfig = null;
            foreach ($registeredClients as $client) {
                if (isset($client["client-id"]) && $client["client-id"] === $clientId) {
                    $clientConfig = $client;
                    break;
                }
            }

            if ($clientConfig === null || !isset($clientConfig["client-secret"]) || $clientConfig["client-secret"] !== $clientSecret) {
                $response->setStatus(HttpStatus::UNAUTHORIZED)->json(["error" => "invalid_client", "error_description" => "Client authentication failed."]);
                return;
            }

            if (!isset($this->authorizationCodes[$code])) {
                $response->json(["error" => "invalid_grant", "error_description" => "Authorization code is invalid or has expired."]);
                return;
            }

            $authCodeData = unserialize($this->authorizationCodes[$code]);
            unset($this->authorizationCodes[$code]);

            if ($authCodeData["expires_at"] < time()) {
                $response->json(["error" => "invalid_grant", "error_description" => "Authorization code has expired."]);
                return;
            }

            if ($authCodeData["client_id"] !== $clientId) {
                $response->json(["error" => "invalid_grant", "error_description" => "Authorization code was issued to another client."]);
                return;
            }

            if (!self::validateCodeChallenge($codeVerifier, $authCodeData["code_challenge"], $authCodeData["code_challenge_method"])) {
                $response->json(["error" => "invalid_grant", "error_description" => "PKCE code_verifier mismatch."]);
                return;
            }

            $accessToken = bin2hex(random_bytes(32));
            $refreshToken = bin2hex(random_bytes(32));
            $accessTokenExpiry = time() + 3600;
            $refreshTokenExpiry = time() + (7 * 24 * 3600);

            $this->accessTokens[$accessToken] = serialize([
                "client_id" => $clientId,
                "username" => $authCodeData["username"],
                "scope" => $authCodeData["scope"],
                "expires_at" => $accessTokenExpiry,
            ]);

            $this->refreshTokens[$refreshToken] = serialize([
                "client_id" => $clientId,
                "username" => $authCodeData["username"],
                "scope" => $authCodeData["scope"],
                "expires_at" => $refreshTokenExpiry,
            ]);

            $responsePayload = [
                "access_token" => $accessToken,
                "token_type" => "Bearer",
                "expires_in" => 3600,
                "refresh_token" => $refreshToken,
            ];

            $scopes = explode(' ', $authCodeData['scope']);
            if (in_array('openid', $scopes)) {
                $nonce = $authCodeData['nonce'] ?? null;
                $responsePayload['id_token'] = $this->idTokenService->createIdToken(
                    $authCodeData['username'],
                    $clientId,
                    $authCodeData['auth_time'],
                    $nonce
                );
            }

            $response->json($responsePayload);
        } elseif ($grantType === "refresh_token") {
            // Delegate to handleTokenRefreshPost
            $this->handleTokenRefreshPost($request, $response);
            return;
        } else {
            $response->json(["error" => "unsupported_grant_type", "error_description" => "The grant type is not supported."]);
            return;
        }
    }

    public function handleTokenRefreshPost(Request $request, Response $response): void
    {
        $configObject = $this->getConfig();
        parse_str($request->getBody(), $body);

        $clientId = $body["client_id"] ?? null;
        $clientSecret = $body["client_secret"] ?? null;
        $refreshToken = $body["refresh_token"] ?? null;

        if ($clientId === null || $clientSecret === null || $refreshToken === null) {
            $response->json(["error" => "invalid_request", "error_description" => "Missing required parameters."]);
            return;
        }

        $registeredClients = $configObject->getNested("web-integration.registered-clients") ?? [];
        $clientConfig = null;
        foreach ($registeredClients as $client) {
            if (isset($client["client-id"]) && $client["client-id"] === $clientId) {
                $clientConfig = $client;
                break;
            }
        }

        if ($clientConfig === null || !isset($clientConfig["client-secret"]) || $clientConfig["client-secret"] !== $clientSecret) {
            $response->setStatus(HttpStatus::UNAUTHORIZED)->json(["error" => "invalid_client", "error_description" => "Client authentication failed."]);
            return;
        }

        if (!isset($this->refreshTokens[$refreshToken])) {
            $response->json(["error" => "invalid_grant", "error_description" => "Refresh token is invalid or has expired."]);
            return;
        }

        $refreshTokenData = unserialize($this->refreshTokens[$refreshToken]);
        unset($this->refreshTokens[$refreshToken]);

        if ($refreshTokenData["expires_at"] < time()) {
            $response->json(["error" => "invalid_grant", "error_description" => "Refresh token has expired."]);
            return;
        }

        if ($refreshTokenData["client_id"] !== $clientId) {
            $response->json(["error" => "invalid_grant", "error_description" => "Refresh token was issued to another client."]);
            return;
        }

        $newAccessToken = bin2hex(random_bytes(32));
        $newRefreshToken = bin2hex(random_bytes(32));
        $accessTokenExpiry = time() + 3600;
        $refreshTokenExpiry = time() + (7 * 24 * 3600);

        $this->accessTokens[$newAccessToken] = serialize([
            "client_id" => $clientId,
            "username" => $refreshTokenData["username"],
            "scope" => $refreshTokenData["scope"],
            "expires_at" => $accessTokenExpiry,
        ]);

        $this->refreshTokens[$newRefreshToken] = serialize([
            "client_id" => $clientId,
            "username" => $refreshTokenData["username"],
            "scope" => $refreshTokenData["scope"],
            "expires_at" => $refreshTokenExpiry,
        ]);

        $responsePayload = [
            "access_token" => $newAccessToken,
            "token_type" => "Bearer",
            "expires_in" => 3600,
            "refresh_token" => $newRefreshToken,
        ];

        $scopes = explode(' ', $refreshTokenData['scope']);
        if (in_array('openid', $scopes)) {
            // For refresh token, we don't have a nonce from the original request
            // The OIDC spec says: "If the ID Token is issued without a nonce, its validation is weaker."
            // We will generate a new ID Token without a nonce for refresh.
            $responsePayload['id_token'] = $this->idTokenService->createIdToken(
                $refreshTokenData['username'],
                $clientId,
                time(), // auth_time for refresh is current time
                null // No nonce for refresh token ID token
            );
        }

        $response->json($responsePayload);
    }

    public function handleIntrospectPost(Request $request, Response $response): void
    {
        $configObject = $this->getConfig();
        parse_str($request->getBody(), $body);

        $clientId = $body["client_id"] ?? null;
        $clientSecret = $body["client_secret"] ?? null;
        $token = $body["token"] ?? null;
        $tokenTypeHint = $body["token_type_hint"] ?? null;

        if ($clientId === null || $clientSecret === null || $token === null) {
            $response->json(["error" => "invalid_request", "error_description" => "Missing required parameters."]);
            return;
        }

        $registeredClients = $configObject->getNested("web-integration.registered-clients") ?? [];
        $clientConfig = null;
        foreach ($registeredClients as $client) {
            if (isset($client["client-id"]) && $client["client-id"] === $clientId) {
                $clientConfig = $client;
                break;
            }
        }

        if ($clientConfig === null || !isset($clientConfig["client-secret"]) || $clientConfig["client-secret"] !== $clientSecret) {
            $response->setStatus(HttpStatus::UNAUTHORIZED)->json(["error" => "invalid_client", "error_description" => "Client authentication failed."]);
            return;
        }

        $tokenData = null;
        $tokenIsActive = false;
        $tokenType = null;

        if ($tokenTypeHint === 'access_token' || ($tokenTypeHint === null && isset($this->accessTokens[$token]))) {
            if (isset($this->accessTokens[$token])) {
                $tokenData = unserialize($this->accessTokens[$token]);
                $tokenType = 'access_token';
            }
        }

        if ($tokenData === null && ($tokenTypeHint === 'refresh_token' || ($tokenTypeHint === null && isset($this->refreshTokens[$token])))) {
            if (isset($this->refreshTokens[$token])) {
                $tokenData = unserialize($this->refreshTokens[$token]);
                $tokenType = 'refresh_token';
            }
        }

        if ($tokenData !== null && $tokenData["expires_at"] > time() && $tokenData["client_id"] === $clientId) {
            $tokenIsActive = true;
        }

        if ($tokenIsActive) {
            $response->json([
                "active" => true,
                "scope" => $tokenData["scope"],
                "client_id" => $tokenData["client_id"],
                "username" => $tokenData["username"],
                "exp" => $tokenData["expires_at"],
                "token_type" => $tokenType
            ]);
        } else {
            $response->json(["active" => false]);
        }
    }

    public function handleRevokePost(Request $request, Response $response): void
    {
        $configObject = $this->getConfig();
        parse_str($request->getBody(), $body);

        $clientId = $body["client_id"] ?? null;
        $clientSecret = $body["client_secret"] ?? null;
        $token = $body["token"] ?? null;
        $tokenTypeHint = $body["token_type_hint"] ?? null;

        if ($clientId === null || $clientSecret === null || $token === null) {
            $response->json(["error" => "invalid_request", "error_description" => "Missing required parameters."]);
            return;
        }

        $registeredClients = $configObject->getNested("web-integration.registered-clients") ?? [];
        $clientConfig = null;
        foreach ($registeredClients as $client) {
            if (isset($client["client-id"]) && $client["client-id"] === $clientId) {
                $clientConfig = $client;
                break;
            }
        }

        if ($clientConfig === null || !isset($clientConfig["client-secret"]) || $clientConfig["client-secret"] !== $clientSecret) {
            $response->setStatus(HttpStatus::UNAUTHORIZED)->json(["error" => "invalid_client", "error_description" => "Client authentication failed."]);
            return;
        }

        if ($tokenTypeHint === 'access_token' || ($tokenTypeHint === null && isset($this->accessTokens[$token]))) {
            if (isset($this->accessTokens[$token])) {
                $tokenData = unserialize($this->accessTokens[$token]);
                if ($tokenData["client_id"] === $clientId) {
                    unset($this->accessTokens[$token]);
                }
            }
        }

        if ($tokenTypeHint === 'refresh_token' || ($tokenTypeHint === null && isset($this->refreshTokens[$token]))) {
            if (isset($this->refreshTokens[$token])) {
                $tokenData = unserialize($this->refreshTokens[$token]);
                if ($tokenData["client_id"] === $clientId) {
                    unset($this->refreshTokens[$token]);
                }
            }
        }

        $response->setStatus(HttpStatus::OK)->send('');
    }

    public function handleUserRequest(Request $request, Response $response): \Generator
    {
        try {
            $this->getLogger()->info("handleUserRequest: Headers: " . json_encode($request->getHeaders()));
            $this->getLogger()->info("handleUserRequest: Body: " . $request->getBody());
            $authHeader = $request->getHeader('Authorization');
            if ($authHeader === null || !str_starts_with($authHeader, 'Bearer ')) {
                $response->setStatus(HttpStatus::UNAUTHORIZED)->json(["error" => "unauthorized", "error_description" => "Missing or invalid Authorization header."]);
                return;
            }

            $accessToken = substr($authHeader, 7);

            if (!isset($this->accessTokens[$accessToken])) {
                $response->setStatus(HttpStatus::UNAUTHORIZED)->json(["error" => "unauthorized", "error_description" => "The access token provided is invalid."]);
                return;
            }

            $tokenData = unserialize($this->accessTokens[$accessToken]);

            if ($tokenData["expires_at"] < time()) {
                $response->setStatus(HttpStatus::UNAUTHORIZED)->json(["error" => "unauthorized", "error_description" => "The access token provided has expired."]);
                return;
            }

            $username = $tokenData["username"];
            $scopeString = $tokenData["scope"];
            $scopes = $scopeString === '' ? [] : explode(" ", $scopeString);

            $userData = yield from self::retrieveUserData($this->getScheduler(), $this->getServer(), $this->scopeProviders, $username, $scopes);

            $this->getLogger()->info("Data right before json(): " . json_encode($userData));
            $response->json($userData);
            $this->getLogger()->info("Response body after json(): " . $response->buildResponse());

        } catch (\Throwable $e) {
            $this->getLogger()->logException($e);
            $response->errorPage($request->getHeader('Accept'), 500, 'An internal error occurred in handleUserRequest.');
        }
    }

    public function processLoginQueue(): void
    {
        foreach ($this->requestQueue as $requestId => $requestData) {
            $data = unserialize($requestData);
            $username = $data['username'];
            $password = $data['password'];
            $oauthParams = $data['oauth_params'];

            unset($this->requestQueue[$requestId]);

            $xauth = $this->xauth;
            $loginResults = $this->loginResults;
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

    private static function validateCodeChallenge(string $codeVerifier, string $codeChallenge, string $codeChallengeMethod): bool
    {
        if ($codeChallengeMethod === "plain") {
            return $codeVerifier === $codeChallenge;
        } elseif ($codeChallengeMethod === "S256") {
            $hashedVerifier = hash('sha256', $codeVerifier, true);
            $base64UrlEncodedHashedVerifier = rtrim(strtr(base64_encode($hashedVerifier), '+/', '-_'), '=');
            return $base64UrlEncodedHashedVerifier === $codeChallenge;
        }
        return false;
    }

    public function onDisable(): void
    {
        if (isset($this->webServer)) {
            $this->webServer->stop();
        }
    }
}

interface ScopeProvider
{
    public function getProvidedScopes(): array;

    public function retrieveScopeData(Server $server, string $username, array $scopes): array;
}

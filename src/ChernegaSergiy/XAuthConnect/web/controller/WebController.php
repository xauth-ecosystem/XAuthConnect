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

namespace ChernegaSergiy\XAuthConnect\web\controller;

use ChernegaSergiy\XAuthConnect\provider\ClientProvider;
use ChernegaSergiy\XAuthConnect\provider\CodeProvider;
use ChernegaSergiy\XAuthConnect\provider\RateLimitProvider;
use ChernegaSergiy\XAuthConnect\provider\ScopeManager;
use ChernegaSergiy\XAuthConnect\provider\TokenProvider;
use ChernegaSergiy\XAuthConnect\web\view\View;
use Hebbinkpro\WebServer\http\message\HttpRequest;
use Hebbinkpro\WebServer\http\message\HttpResponse;

class WebController {

    private ClientProvider $clientProvider;
    private CodeProvider $codeProvider;
    private RateLimitProvider $rateLimitProvider;
    private TokenProvider $tokenProvider;
    private ScopeManager $scopeManager;
    private View $view;
    private string $baseUrl;

    public function __construct(ClientProvider $clientProvider, CodeProvider $codeProvider, RateLimitProvider $rateLimitProvider, TokenProvider $tokenProvider, ScopeManager $scopeManager, View $view, string $baseUrl) {
        $this->clientProvider = $clientProvider;
        $this->codeProvider = $codeProvider;
        $this->rateLimitProvider = $rateLimitProvider;
        $this->tokenProvider = $tokenProvider;
        $this->scopeManager = $scopeManager;
        $this->view = $view;
        $this->baseUrl = $baseUrl;
    }

    private function redirectToError(HttpResponse $res, ?string $redirectUri, string $error, string $errorDescription, ?string $state = null): void {
        if ($redirectUri === null) {
            // If redirect_uri is missing or invalid, we cannot redirect.
            // Display a generic error to the user directly.
            $res->setStatus(400);
$res->text("Error: " . $error . " - " . $errorDescription);
            return;
        }

        $query = http_build_query([
            "error" => $error,
            "error_description" => $errorDescription,
            "state" => $state
        ]);
        $location = $redirectUri . (strpos($redirectUri, '?') === false ? '?' : '&') . $query;
        $res->setStatus(302);
        $res->getHeaders()->setHeader("Location", $location);
        $res->end();
    }

    private function checkRateLimit(string $clientId, HttpResponse $res): bool {
        if ($this->rateLimitProvider->isRateLimited($clientId)) {
            $res->setStatus(429);
            $res->text("Too Many Requests");
            return true;
        }
        $this->rateLimitProvider->recordRequest($clientId);
        return false;
    }

    public function handleAuthorize(HttpRequest $req, HttpResponse $res): void {
        parse_str($req->getURL()->getQuery(), $params);
        $clientId = $params["client_id"] ?? null;
        $codeChallenge = $params["code_challenge"] ?? null;
        $codeChallengeMethod = $params["code_challenge_method"] ?? null;
        $state = $params["state"] ?? null; // Extract state

        if ($clientId === null || $this->checkRateLimit($clientId, $res)) {
            return;
        }

        $client = $this->clientProvider->getClient($clientId);
        $redirectUri = $params["redirect_uri"] ?? null; // Get redirect_uri early

        if ($client === null || !$this->clientProvider->isClientValid($clientId, $redirectUri)) {
            // If redirect_uri is invalid, we cannot redirect. Display error directly.
            $res->setStatus(400);
            $res->json(["error" => "invalid_client", "error_description" => "Invalid client_id or redirect_uri"]);
            return;
        }

        // PKCE validation for authorization request
        if ($codeChallenge === null || $codeChallengeMethod === null) {
            $this->redirectToError($res, $redirectUri, "invalid_request", "Missing code_challenge or code_challenge_method for PKCE", $state);
            return;
        }

        if ($codeChallengeMethod !== "S256" && $codeChallengeMethod !== "plain") { // Only S256 and plain are supported
            $this->redirectToError($res, $redirectUri, "invalid_request", "Unsupported code_challenge_method. Only S256 and plain are supported.", $state);
            return;
        }

        $requestedScopes = explode(" ", $params["scope"] ?? "");
        $availableScopes = $this->scopeManager->getAvailableScopes();
        $allowedScopes = $client['allowed-scopes'] ?? [];

        foreach ($requestedScopes as $scope) {
            if (!in_array($scope, $availableScopes, true) || !in_array($scope, $allowedScopes, true)) {
                $this->redirectToError($res, $redirectUri, "invalid_scope", "Invalid scope: " . htmlspecialchars($scope), $state);
                return;
            }
        }

        // Pass PKCE and state parameters to the login page for later use in handleLogin
        $params["code_challenge"] = $codeChallenge;
        $params["code_challenge_method"] = $codeChallengeMethod;
        $params["state"] = $state; // Pass state to login page

        $html = $this->view->renderLoginPage($params, $client['name'] ?? 'Application');
        $res->send($html);
    }

    public function handleLogin(HttpRequest $req, HttpResponse $res): void {
        parse_str($req->getBody(), $postParams);
        $clientId = $postParams['client_id'] ?? null;
        $codeChallenge = $postParams["code_challenge"] ?? null;
        $codeChallengeMethod = $postParams["code_challenge_method"] ?? null;
        $state = $postParams["state"] ?? null; // Extract state

        if ($clientId === null || $this->checkRateLimit($clientId, $res)) {
            return;
        }

        $username = $postParams['username'] ?? null;
        $password = $postParams['password'] ?? null;

        // The user authentication logic is now part of the ScopeManager
        $playerData = $this->scopeManager->retrieveDataForScopes($username, ["profile:nickname"]);
        if (empty($playerData)) {
            $client = $this->clientProvider->getClient($clientId);
            $html = $this->view->renderLoginPage($postParams, $client['name'] ?? 'Application', "Invalid username or password.");
            $res->setStatus(401);
            $res->send($html);
            return;
        }

        $requestedScopes = explode(" ", $postParams["scope"] ?? "");
        // Instead of directly creating the code and redirecting, redirect to consent page
        // Pass all necessary parameters to the consent page
        $consentParams = [
            "client_id" => $clientId,
            "redirect_uri" => $postParams['redirect_uri'],
            "scope" => $postParams["scope"] ?? "",
            "state" => $state,
            "code_challenge" => $codeChallenge,
            "code_challenge_method" => $codeChallengeMethod,
            "username" => $username // Pass username to consent page
        ];
        $query = http_build_query($consentParams);
        $location = $this->baseUrl . "/xauth/consent?" . $query;
        $res->setStatus(302);
        $res->getHeaders()->setHeader("Location", $location);
        $res->end();
    }

    public function handleConsent(HttpRequest $req, HttpResponse $res): void {
        parse_str($req->getURL()->getQuery(), $params); // For GET request
        parse_str($req->getBody(), $postParams); // For POST request

        // Use parameters from GET or POST depending on the request method
        $requestParams = $req->getMethod()->value === "GET" ? $params : $postParams;

        $clientId = $requestParams["client_id"] ?? null;
        $redirectUri = $requestParams["redirect_uri"] ?? null;
        $scope = $requestParams["scope"] ?? "";
        $state = $requestParams["state"] ?? null;
        $codeChallenge = $requestParams["code_challenge"] ?? null;
        $codeChallengeMethod = $requestParams["code_challenge_method"] ?? null;
        $username = $requestParams["username"] ?? null; // Username from successful login

        // Basic validation (more robust validation should happen earlier in handleAuthorize)
        if ($clientId === null || $redirectUri === null || $username === null) {
            $res->setStatus(400);
            $res->json(["error" => "invalid_request", "error_description" => "Missing required parameters for consent."]);
            return;
        }

        $client = $this->clientProvider->getClient($clientId);
        if ($client === null || !$this->clientProvider->isClientValid($clientId, $redirectUri)) {
            $this->redirectToError($res, $redirectUri, "invalid_client", "Invalid client_id or redirect_uri", $state);
            return;
        }

        $requestedScopes = explode(" ", $scope);
        $availableScopes = $this->scopeManager->getAvailableScopes();
        $allowedScopes = $client['allowed-scopes'] ?? [];

        foreach ($requestedScopes as $s) {
            if (!in_array($s, $availableScopes, true) || !in_array($s, $allowedScopes, true)) {
                $this->redirectToError($res, $redirectUri, "invalid_scope", "Invalid scope: " . htmlspecialchars($s), $state);
                return;
            }
        }

        if ($req->getMethod()->value === "GET") {
            // Display consent page
            $html = $this->view->renderConsentPage($requestParams, $client['name'] ?? 'Application', $requestedScopes);
            $res->send($html);
        } elseif ($req->getMethod()->value === "POST") {
            $consentAction = $postParams["consent_action"] ?? null;

            if ($consentAction === "approve") {
                // User approved, generate authorization code and redirect
                $this->codeProvider->createCode($clientId, $username, $requestedScopes, $codeChallenge, $codeChallengeMethod, $state, function(string $authCode) use ($res, $redirectUri, $state) {
                    $location = $redirectUri . "?code=" . $authCode . ($state ? "&state=" . $state : "");
                    $res->setStatus(302);
                    $res->getHeaders()->setHeader("Location", $location);
                    $res->end();
                });
            } elseif ($consentAction === "deny") {
                // User denied, redirect with access_denied error
                $this->redirectToError($res, $redirectUri, "access_denied", "User denied access.", $state);
            } else {
                // Invalid consent action
                $this->redirectToError($res, $redirectUri, "invalid_request", "Invalid consent action.", $state);
            }
        }
    }

    public function handleToken(HttpRequest $req, HttpResponse $res): void {
        parse_str($req->getBody(), $params);
        $clientId = $params["client_id"] ?? null;

        if ($clientId === null || $this->checkRateLimit($clientId, $res)) {
            return;
        }

        $clientSecret = $params["client_secret"] ?? null;
        $code = $params["code"] ?? null;
        $codeVerifier = $params["code_verifier"] ?? null;
        $state = $params["state"] ?? null; // Extract state for validation

        if (!$this->clientProvider->isClientValid($clientId, null, $clientSecret)) {
            $res->setStatus(400);
            $res->json(["error" => "invalid_client"]);
            return;
        }

        // Pass codeVerifier and state to validateCode for PKCE and state validation
        $this->codeProvider->validateCode($code, $clientId, $codeVerifier, $state, function(?array $codeData) use ($res, $state) {
            if ($codeData === null) {
                $res->setStatus(400);
                $res->json(["error" => "invalid_grant", "error_description" => "Invalid or expired authorization code, or PKCE/state validation failed."]);
                return;
            }

            // Additional state validation (though CodeProvider already checks if expectedState is provided)
            // This check ensures that the state returned by CodeProvider matches the state sent in the token request.
            if (($state !== null) && ($codeData['state'] !== $state)) {
                $res->setStatus(400);
                $res->json(["error" => "invalid_grant", "error_description" => "State mismatch."]);
                return;
            }

            $this->tokenProvider->createToken($codeData['username'], $codeData['scopes'], function(string $accessToken) use ($res) {
                $res->json(["access_token" => $accessToken, "token_type" => "Bearer", "expires_in" => 3600]);
            });
        });
    }

    public function handleUser(HttpRequest $req, HttpResponse $res): void {
        $authHeader = $req->getHeaders()->getHeader("Authorization");
        if ($authHeader === null || !str_starts_with($authHeader, "Bearer ")) {
            $res->setStatus(401);
            $res->json(["error" => "invalid_token", "error_description" => "Authorization header missing or invalid"]);
            return;
        }

        $token = substr($authHeader, 7);
        $this->tokenProvider->validateToken($token, function(?array $tokenData) use ($res) {
            if ($tokenData === null) {
                $res->setStatus(401);
                $res->json(["error" => "invalid_token", "error_description" => "Invalid or expired token"]);
                return;
            }

            $userData = $this->scopeManager->retrieveDataForScopes($tokenData['username'], $tokenData['scopes']);
            $res->json($userData);
        });
    }

    public function handleRefreshToken(HttpRequest $req, HttpResponse $res): void {
        parse_str($req->getBody(), $params);
        $clientId = $params["client_id"] ?? null;

        if ($clientId === null || $this->checkRateLimit($clientId, $res)) {
            return;
        }

        $clientSecret = $params["client_secret"] ?? null;
        $refreshToken = $params["refresh_token"] ?? null;

        if (!$this->clientProvider->isClientValid($clientId, null, $clientSecret)) {
            $res->setStatus(400);
            $res->json(["error" => "invalid_client"]);
            return;
        }

        $this->tokenProvider->validateRefreshToken($refreshToken, function(?array $tokenData) use ($res, $clientId, $refreshToken) {
            if ($tokenData === null) {
                $res->setStatus(400);
                $res->json(["error" => "invalid_grant"]);
                return;
            }

            // Ensure the refresh token belongs to the requesting client
            // (This check is not directly in TokenProvider, so we do it here)
            // This requires client_id to be stored with refresh token, which it is.
            if ($tokenData['client_id'] !== $clientId) { // Assuming client_id is returned by validateRefreshToken
                 $res->setStatus(400);
                 $res->json(["error" => "invalid_grant", "error_description" => "Refresh token not issued to this client"]);
                 return;
            }

            // Revoke the old refresh token (optional, but good practice for rotation)
            $this->tokenProvider->revokeToken($refreshToken, function($success) use ($res, $tokenData) {
                // Issue new access and refresh tokens
                $this->tokenProvider->createToken($tokenData['username'], $tokenData['scopes'], function(string $newAccessToken, string $newRefreshToken, int $expiresIn) use ($res) {
                    $res->json([
                        "access_token" => $newAccessToken,
                        "token_type" => "Bearer",
                        "expires_in" => $expiresIn,
                        "refresh_token" => $newRefreshToken
                    ]);
                });
            });
        });
    }

    public function handleIntrospectToken(HttpRequest $req, HttpResponse $res): void {
        parse_str($req->getBody(), $params);
        $token = $params["token"] ?? null;
        $tokenTypeHint = $params["token_type_hint"] ?? null; // access_token or refresh_token

        // Client authentication for introspection endpoint (optional, but good practice)
        $clientId = $params["client_id"] ?? null;
        $clientSecret = $params["client_secret"] ?? null;
        if ($clientId === null || !$this->clientProvider->isClientValid($clientId, null, $clientSecret)) {
            $res->setStatus(401);
            $res->json(["error" => "invalid_client", "active" => false]); // OAuth 2.0 spec says return active:false for invalid client
            return;
        }

        if ($token === null) {
            $res->setStatus(400);
            $res->json(["error" => "invalid_request"]);
            return;
        }

        // Introspect access token
        if ($tokenTypeHint === 'access_token' || $tokenTypeHint === null) {
            $this->tokenProvider->validateToken($token, function(?array $tokenData) use ($res) {
                if ($tokenData === null) {
                    $res->setStatus(401);
                    $res->json(["error" => "invalid_token", "active" => false]);
                    return;
                }
                $res->json([
                    "active" => true,
                    "scope" => implode(" ", $tokenData['scopes']),
                    "client_id" => $tokenData['client_id'] ?? null, // Assuming client_id is returned by validateToken
                    "username" => $tokenData['username'],
                    "exp" => $tokenData['expires'] ?? null // Assuming expires is returned by validateToken
                ]);
            });
            return;
        }

        // Introspect refresh token
        if ($tokenTypeHint === 'refresh_token') {
            $this->tokenProvider->validateRefreshToken($token, function(?array $tokenData) use ($res) {
                if ($tokenData === null) {
                    $res->setStatus(401);
                    $res->json(["error" => "invalid_token", "active" => false]);
                    return;
                }
                $res->json([
                    "active" => true,
                    "scope" => implode(" ", $tokenData['scopes']),
                    "client_id" => $tokenData['client_id'] ?? null, // Assuming client_id is returned by validateRefreshToken
                    "username" => $tokenData['username'],
                    "exp" => $tokenData['expires'] ?? null // Assuming expires is returned by validateRefreshToken
                ]);
            });
            return;
        }

        $res->setStatus(400);
        $res->json(["error" => "unsupported_token_type"]);
    }

    public function handleRevokeToken(HttpRequest $req, HttpResponse $res): void {
        parse_str($req->getBody(), $params);
        $token = $params["token"] ?? null;
        $tokenTypeHint = $params["token_type_hint"] ?? null; // access_token or refresh_token

        // Client authentication for revocation endpoint
        $clientId = $params["client_id"] ?? null;
        $clientSecret = $params["client_secret"] ?? null;
        if ($clientId === null || !$this->clientProvider->isClientValid($clientId, null, $clientSecret)) {
            $res->setStatus(401);
            $res->json(["error" => "invalid_client", "error_description" => "Unauthorized"]);
            return;
        }

        if ($token === null) {
            $res->setStatus(400);
            $res->json(["error" => "invalid_request"]);
            return;
        }

        $this->tokenProvider->revokeToken($token, function($success) use ($res) {
            if ($success) {
                $res->setStatus(200);
                $res->end(); // Success, even if token didn't exist
            } else {
                $res->setStatus(500);
                $res->json(["error" => "server_error", "error_description" => "Internal Server Error"]); // Should not happen if logic is correct
            }
        });
    }
}

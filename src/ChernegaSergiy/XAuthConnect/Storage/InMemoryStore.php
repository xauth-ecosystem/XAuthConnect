<?php
declare(strict_types=1);

namespace ChernegaSergiy\XAuthConnect\Storage;

use pmmp\thread\ThreadSafeArray;

class InMemoryStore
{
    public ThreadSafeArray $requestQueue;
    public ThreadSafeArray $loginResults;
    public ThreadSafeArray $authorizationCodes;
    public ThreadSafeArray $accessTokens;
    public ThreadSafeArray $refreshTokens;

    public function __construct()
    {
        $this->requestQueue = new ThreadSafeArray();
        $this->loginResults = new ThreadSafeArray();
        $this->authorizationCodes = new ThreadSafeArray();
        $this->accessTokens = new ThreadSafeArray();
        $this->refreshTokens = new ThreadSafeArray();
    }
}

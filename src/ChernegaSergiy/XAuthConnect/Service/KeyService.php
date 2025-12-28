<?php

declare(strict_types=1);

namespace ChernegaSergiy\XAuthConnect\Service;

use OpenSSLAsymmetricKey;
use pocketmine\plugin\PluginLogger;
use RuntimeException;

class KeyService
{
    private string $privateKeyPath;
    private ?OpenSSLAsymmetricKey $privateKey = null;
    private PluginLogger $logger;

    public function __construct(string $privateKeyPath, PluginLogger $logger)
    {
        $this->privateKeyPath = $privateKeyPath;
        $this->logger = $logger;
    }

    public function getPrivateKey(): OpenSSLAsymmetricKey
    {
        if ($this->privateKey !== null) {
            return $this->privateKey;
        }

        $this->logger->info("Checking for private key at: " . $this->privateKeyPath);

        if (file_exists($this->privateKeyPath)) {
            $this->logger->info("Private key file found. Reading...");
            $keyContents = file_get_contents($this->privateKeyPath);
            if ($keyContents === false) {
                throw new RuntimeException("Could not read private key file.");
            }
            $key = openssl_pkey_get_private($keyContents);
            if ($key === false) {
                throw new RuntimeException("Failed to parse private key.");
            }
            $this->privateKey = $key;
            return $this->privateKey;
        }

        $this->logger->info("Private key file not found. Generating new key...");
        $config = [
            'config' => '/etc/ssl/openssl.cnf',
            'private_key_bits' => 4096,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ];
        $newKey = openssl_pkey_new($config);

        if ($newKey === false) {
            $this->logger->error("openssl_pkey_new() failed.");
            throw new RuntimeException("Failed to generate new private key.");
        }
        $this->logger->info("openssl_pkey_new() successful.");

        $success = openssl_pkey_export($newKey, $privateKeyPem, null, ['config' => '/etc/ssl/openssl.cnf']);
        if (!$success) {
            $this->logger->error("openssl_pkey_export() failed.");
            throw new RuntimeException("Failed to export new private key.");
        }
        $this->logger->info("openssl_pkey_export() successful.");

        $bytesWritten = file_put_contents($this->privateKeyPath, $privateKeyPem);
        if ($bytesWritten === false) {
            $error = error_get_last();
            $this->logger->error("file_put_contents() failed. Error: " . ($error['message'] ?? 'Unknown error'));
            throw new RuntimeException("Failed to write private key to file: " . ($error['message'] ?? 'Unknown error'));
        } else {
            $this->logger->info("Successfully wrote new private key to file (" . $bytesWritten . " bytes).");
        }

        $this->privateKey = $newKey;

        return $this->privateKey;
    }

    public function getPublicKeyAsJwk(): array
    {
        $privateKey = $this->getPrivateKey();
        $details = openssl_pkey_get_details($privateKey);

        if ($details === false || !isset($details['rsa'])) {
            throw new RuntimeException("Failed to get RSA key details.");
        }

        $n = rtrim(strtr(base64_encode($details['rsa']['n']), '+/', '-_'), '=');
        $e = rtrim(strtr(base64_encode($details['rsa']['e']), '+/', '-_'), '=');

        return [
            'kty' => 'RSA',
            'alg' => 'RS256',
            'kid' => $this->generateKid($n),
            'use' => 'sig',
            'n' => $n,
            'e' => $e,
        ];
    }

    private function generateKid(string $n): string
    {
        return substr(hash('sha256', $n), 0, 16);
    }
}
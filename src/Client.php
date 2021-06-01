<?php

namespace Dvsa\Authentication\Cognito;

use ArrayAccess;
use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Dvsa\Contracts\Auth\ClientInterface;
use Dvsa\Contracts\Auth\TokenInterface;
use Firebase\JWT\JWK;
use RuntimeException;

class Client implements ClientInterface, TokenInterface
{
    /**
     * @var CognitoIdentityProviderClient
     */
    protected $client;

    /**
     * @var string
     */
    protected $clientId;

    /**
     * @var string
     */
    protected $clientSecret;

    /**
     * @var string
     */
    protected $poolId;

    /**
     * @var JWK
     */
    private $jwtWebKeys;

    /**
     * CognitoClient constructor.
     *
     * @param  CognitoIdentityProviderClient  $client
     * @param  string                         $clientId
     * @param  string                         $clientSecret
     * @param  string                         $poolId
     */
    public function __construct(
        CognitoIdentityProviderClient $client,
        string $clientId,
        string $clientSecret,
        string $poolId
    ) {
        $this->client = $client;
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->poolId = $poolId;
    }

    public function register(string $identifier, string $password, array $attributes = []): ArrayAccess
    {
        // TODO: Implement register() method.
    }

    public function authenticate(string $identifier, string $password): string
    {
        // TODO: Implement authenticate() method.
    }

    public function changePassword(string $identifier, string $newPassword): bool
    {
        // TODO: Implement changePassword() method.
    }

    public function changeAttribute(string $identifier, string $key, string $value): bool
    {
        // TODO: Implement changeAttribute() method.
    }

    public function changeAttributes(string $identifier, array $attributes): bool
    {
        // TODO: Implement changeAttributes() method.
    }

    public function enableUser(string $identifier): bool
    {
        // TODO: Implement enableUser() method.
    }

    public function disableUser(string $identifier): bool
    {
        // TODO: Implement disableUser() method.
    }

    public function getUserByIdentifier(string $identifier): ArrayAccess
    {
        // TODO: Implement getUserByIdentifier() method.
    }

    public function isValidToken(string $token): bool
    {
        // TODO: Implement isValidToken() method.
    }

    public function refreshToken(string $token, string $identifier): string
    {
        // TODO: Implement refreshToken() method.
    }

    public function getUserByToken(string $token): ArrayAccess
    {
        // TODO: Implement getUserByToken() method.
    }

    /**
     * @param  string  $identifier
     *
     * @return string
     */
    protected function cognitoSecretHash(string $identifier): string
    {
        return $this->hash($identifier . $this->clientId);
    }

    /**
     * @return JWK
     */
    protected function getJwtWebKeys()
    {
        if (!$this->jwtWebKeys) {
            $this->jwtWebKeys = $this->downloadJwtWebKeys();
        }

        return $this->jwtWebKeys;
    }

    /**
     * @throws RuntimeException - On invalid JSON response from the endpoint.
     *
     * @return array
     */
    protected function downloadJwtWebKeys(): array
    {
        $url = sprintf(
            'https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json',
            $this->client->getRegion(),
            $this->poolId
        );

        $json = file_get_contents($url);

        $keys = json_decode($json, true); // PHP >=7.3: use JSON_THROW_ON_ERROR flag.

        if (JSON_ERROR_NONE !== json_last_error()) {
            throw new RuntimeException(sprintf('Invalid JSON rules input: "%s".', json_last_error_msg()));
        }

        return $keys;
    }

    /**
     * Creates a HMAC from a string.
     *
     * @param  string  $message
     *
     * @return string
     */
    protected function hash(string $message): string
    {
        $hash = hash_hmac(
            'sha256',
            $message,
            $this->clientSecret,
            true
        );

        return base64_encode($hash);
    }

    /**
     * Format attributes in Name/Value array.
     *
     * @param array $attributes
     *
     * @return array
     */
    protected function formatAttributes(array $attributes): array
    {
        $userAttributes = [];

        foreach ($attributes as $key => $value) {
            $userAttributes[] = [
                'Name' => $key,
                'Value' => $value,
            ];
        }

        return $userAttributes;
    }
}
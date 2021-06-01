<?php

namespace Dvsa\Authentication\Cognito;

use ArrayAccess;
use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Dvsa\Contracts\Auth\ClientInterface;
use Dvsa\Contracts\Auth\TokenInterface;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
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

    /**
     * @param  string  $identifier
     * @param  string  $password
     * @param  array   $attributes
     *
     * @return ArrayAccess
     */
    public function register(string $identifier, string $password, array $attributes = []): ArrayAccess
    {
        $response = $this->client->signUp([
            'ClientId' => $this->clientId,
            'Password' => $password,
            'SecretHash' => $this->cognitoSecretHash($identifier),
            'UserAttributes' => $this->formatAttributes($attributes),
            'Username' => $identifier,
        ]);

        return $response;
    }

    /**
     * @param  string  $identifier
     * @param  string  $password
     *
     * @return string
     */
    public function authenticate(string $identifier, string $password): string
    {
        $response = $this->client->adminInitiateAuth([
            'AuthFlow' => 'ADMIN_NO_SRP_AUTH',
            'AuthParameters' => [
                'USERNAME' => $identifier,
                'PASSWORD' => $password,
                'SECRET_HASH' => $this->cognitoSecretHash($identifier),
            ],
            'ClientId' => $this->clientId,
            'UserPoolId' => $this->poolId,
        ]);

        return $response;
    }

    /**
     * @param  string  $identifier
     * @param  string  $newPassword
     *
     * @return bool
     */
    public function changePassword(string $identifier, string $newPassword, bool $permanent = true): bool
    {
        $response = $this->client->adminUpdateUserAttributes([
            'Username' => $identifier,
            'UserPoolId' => $this->poolId,
            'Password' => $newPassword,
            'Permanent' => true
        ]);

        return true;
    }

    /**
     * @param  string  $identifier
     * @param  string  $key
     * @param  string  $value
     *
     * @return bool
     */
    public function changeAttribute(string $identifier, string $key, string $value): bool
    {
        return $this->changeAttributes($identifier, [$key => $value]);
    }

    /**
     * @param  string  $identifier
     * @param  array   $attributes
     *
     * @return bool
     */
    public function changeAttributes(string $identifier, array $attributes): bool
    {
        $response = $this->client->adminUpdateUserAttributes([
            'Username' => $identifier,
            'UserPoolId' => $this->poolId,
            'UserAttributes' => $this->formatAttributes($attributes)
        ]);

        return true;
    }

    /**
     * @param  string  $identifier
     *
     * @return bool
     */
    public function enableUser(string $identifier): bool
    {
        $response = $this->client->adminEnableUser([
            'Username' => $identifier,
            'UserPoolId' => $this->poolId,
        ]);

        return true;
    }

    /**
     * @param  string  $identifier
     *
     * @return bool
     */
    public function disableUser(string $identifier): bool
    {
        $response = $this->client->adminDisableUser([
            'Username' => $identifier,
            'UserPoolId' => $this->poolId,
        ]);

        return true;
    }

    /**
     * @param  string  $identifier
     *
     * @return ArrayAccess
     */
    public function getUserByIdentifier(string $identifier): ArrayAccess
    {
        $response = $this->client->adminGetUser([
            'Username' => $identifier,
            'UserPoolId' => $this->poolId,
        ]);

        return $response;
    }

    /**
     * @param  string  $token
     *
     * @return bool
     */
    public function isValidToken(string $token): bool
    {
        try {
            JWT::decode($token, JWK::parseKeySet($this->getJwtWebKeys()));

            return true;
        } catch (RuntimeException $e) {
            return false;
        }
    }

    /**
     * @param  string  $refreshToken
     * @param  string  $identifier
     *
     * @return string
     */
    public function refreshToken(string $refreshToken, string $identifier): string
    {
        $response = $this->client->adminInitiateAuth([
            'AuthFlow' => 'REFRESH_TOKEN_AUTH',
            'AuthParameters' => [
                'REFRESH_TOKEN' => $refreshToken,
                'SECRET_HASH' => $this->cognitoSecretHash($identifier),
            ],
            'ClientId' => $this->clientId,
            'UserPoolId' => $this->poolId,
        ]);

        return '';
    }

    /**
     * @param  string  $token
     *
     * @return ArrayAccess
     */
    public function getUserByToken(string $token): ArrayAccess
    {
        $response = $this->client->getUser([
            'AccessToken' => $token,
        ]);

        return $response;
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

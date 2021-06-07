<?php

namespace Dvsa\Authentication\Cognito;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Aws\Exception\AwsException;
use Aws\Result;
use Dvsa\Contracts\Auth\ClientException;
use Dvsa\Contracts\Auth\InvalidTokenException;
use Dvsa\Contracts\Auth\OAuthClientInterface;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;

class Client implements OAuthClientInterface
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
     * @var string[]
     */
    protected $jwtWebKeys = [];

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
     * @return Result
     *
     * @throws ClientException when there is an with creating user with the provided credentials.
     */
    public function register(string $identifier, string $password, array $attributes = []): \ArrayAccess
    {
        $attributes = array_merge(['email_verified' => 'true'], $attributes);

        try {
            return $this->client->adminCreateUser([
                'MessageAction' => 'SUPPRESS',
                'TemporaryPassword' => $password,
                'UserAttributes' => $this->formatAttributes($attributes),
                'UserPoolId' => $this->poolId,
                'Username' => $identifier

            ]);
        } catch (AwsException $e) {
            throw new ClientException($e->getMessage(), (int) $e->getCode(), $e);
        }
    }

    /**
     * @see https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminInitiateAuth.html
     *
     * @return Result
     *
     * @throws ClientException when there is an issue with authenticating a user.
     */
    public function authenticate(string $identifier, string $password): \ArrayAccess
    {
        try {
            return $this->client->adminInitiateAuth(
                [
                    'AuthFlow'       => 'ADMIN_USER_PASSWORD_AUTH',
                    'AuthParameters' => [
                        'USERNAME'    => $identifier,
                        'PASSWORD'    => $password,
                        'SECRET_HASH' => $this->cognitoSecretHash($identifier),
                    ],
                    'ClientId'       => $this->clientId,
                    'UserPoolId'     => $this->poolId,
                ]
            );
        } catch (AwsException $e) {
            throw new ClientException($e->getMessage(), (int) $e->getCode(), $e);
        }
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

    public function getUserByIdentifier(string $identifier): \ArrayAccess
    {
        // TODO: Implement getUserByIdentifier() method.

    /**
     * @see https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_GetUser.html
     *
     * @return Result
     *
     * @throws ClientException when there is an issue with getting a user.
     */
    public function getUserByAccessToken(string $accessToken): \ArrayAccess
    {
        try {
            return $this->client->getUser([
                'UserPoolId' => $this->poolId,
                'AccessToken' => $accessToken
            ]);
        } catch (AwsException $e) {
            throw new ClientException($e->getMessage(), (int) $e->getCode(), $e);
        }
    }

    /**
     * @throws InvalidTokenException when the token provided is invalid and cannot be decoded.
     */
    public function decodeToken(string $token): object
    {
        try {
            $keySet = $this->getJwtWebKeys();

            $jwt = JWT::decode($token, $keySet, ['RS256']);

            # Additional checks per AWS requirements to verify tokens.
            # https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html
            if (!isset($jwt->token_use) || !in_array($jwt->token_use, ['id', 'access'])) {
                throw new InvalidTokenException('"token_use" invalid');
            }

            $expectedIss = sprintf('https://cognito-idp.%s.amazonaws.com/%s', $this->client->getRegion(), $this->poolId);
            if (!isset($jwt->iss) || $jwt->iss !== $expectedIss) {
                throw new InvalidTokenException('"iss" invalid');
            }

            # Only applied to Id tokens.
            if ($jwt->token_use === 'id') {
                if (!isset($jwt->aud) || $jwt->aud !== $this->clientId) {
                    throw new InvalidTokenException('"aud" invalid');
                }
            }

            return $jwt;
        } catch (\Exception $e) {
            throw new InvalidTokenException($e->getMessage(), (int) $e->getCode(), $e);
        }
    }

    /**
     * @see https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminInitiateAuth.html
     *
     * @return Result
     *
     * @throws ClientException when there was an issue with refreshing the user's token.
     */
    public function refreshTokens(string $refreshToken, string $identifier): \ArrayAccess
    {
        try {
            return $this->client->adminInitiateAuth([
                'AuthFlow' => 'REFRESH_TOKEN_AUTH',
                'AuthParameters' => [
                    'REFRESH_TOKEN' => $refreshToken,
                    'SECRET_HASH' => $this->cognitoSecretHash($identifier),
                ],
                'ClientId' => $this->clientId,
                'UserPoolId' => $this->poolId,
            ]);
        } catch (AwsException $e) {
            throw new ClientException($e->getMessage(), (int) $e->getCode(), $e);
        }
    }

    public function setJwkWebKeys(array $keys): void
    {
        $this->jwtWebKeys = $keys;
    }

    public function getJwtWebKeys(): array
    {
        if (empty($this->jwtWebKeys)) {
            $this->jwtWebKeys = $this->parseJwk($this->downloadJwtWebKeys());
        }

        return $this->jwtWebKeys;
    }

    /**
     * @return string[]
     */
    protected function parseJwk(array $keys): array
    {
        return JWK::parseKeySet($keys);
    }

    /**
     * @throws \JsonException
     */
    protected function downloadJwtWebKeys(): array
    {
        $url = sprintf(
            'https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json',
            $this->client->getRegion(),
            $this->poolId
        );

        $json = file_get_contents($url);

        if (false === $json) {
            return [];
        }

        $keys = json_decode($json, true);

        if (JSON_ERROR_NONE !== json_last_error()) {
            throw new \JsonException(sprintf('Invalid JSON rules input: "%s".', json_last_error_msg()));
        }

        return $keys;
    }

    protected function cognitoSecretHash(string $identifier): string
    {
        return $this->hash($identifier . $this->clientId);
    }

    /**
     * Creates a HMAC from a string using the AWS client secret.
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
     * Format attributes from [Key => Value] to a AWS compatible [['Name', 'Value'], ...] array.
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

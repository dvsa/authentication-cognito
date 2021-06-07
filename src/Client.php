<?php

namespace Dvsa\Authentication\Cognito;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Aws\Exception\AwsException;
use Aws\Result;
use Dvsa\Contracts\Auth\ClientException;
use Dvsa\Contracts\Auth\ClientInterface;
use Dvsa\Contracts\Auth\TokenInterface;
use Firebase\JWT\JWK;

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
     * @return Result See https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminCreateUser.html#API_AdminCreateUser_ResponseSyntax
     *
     * @throws ClientException  Issue with creating user with the provided credentials.
     *                          Use `getPrevious()` to get the AWS exception for more details.
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
            throw new ClientException($e->getMessage(), (int)$e->getCode(), $e);
        }
    }

    public function authenticate(string $identifier, string $password): \ArrayAccess
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

    public function getUserByIdentifier(string $identifier): \ArrayAccess
    {
        // TODO: Implement getUserByIdentifier() method.
    }

    /**
     * @throws \RuntimeException             Malformed JSON from JWK response.
     * @throws \InvalidArgumentException     Used JWK Set is empty
     * @throws \UnexpectedValueException     Used JWK Set was invalid
     * @throws \DomainException              OpenSSL failure
     */
    public function isValidToken(string $token): bool
    {
        // TODO: Implement isValidToken() method.
    }

    public function refreshToken(string $token, string $identifier): string
    {
        // TODO: Implement refreshToken() method.
    }

    public function getUserByToken(string $token): \ArrayAccess
    {
        // TODO: Implement getUserByToken() method.
    }

    protected function getJwtWebKeys(): array
    {
        if (!$this->jwtWebKeys) {
            $this->jwtWebKeys = $this->parseJwk($this->downloadJwtWebKeys());
        }

        return $this->jwtWebKeys;
    }

    protected function parseJwk(array $keys): array
    {
        return JWK::parseKeySet($keys);
    }

    protected function downloadJwtWebKeys(): array
    {
        $url = sprintf(
            'https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json',
            $this->client->getRegion(),
            $this->poolId
        );

        $json = file_get_contents($url);

        // TODO: PHP >=7.3: use JSON_THROW_ON_ERROR flag.
        $keys = json_decode($json, true);

        if (JSON_ERROR_NONE !== json_last_error()) {
            throw new \RuntimeException(sprintf('Invalid JSON rules input: "%s".', json_last_error_msg()));
        }

        return $keys;
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
     * Format attributes from [Key => Value] to a AWS compatible ['Name', 'Value'] array.
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

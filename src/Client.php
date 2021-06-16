<?php

namespace Dvsa\Authentication\Cognito;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Aws\Exception\AwsException;
use Dvsa\Contracts\Auth\AccessTokenInterface;
use Dvsa\Contracts\Auth\Exceptions\ChallengeException;
use Dvsa\Contracts\Auth\Exceptions\ClientException;
use Dvsa\Contracts\Auth\Exceptions\InvalidTokenException;
use Dvsa\Contracts\Auth\OAuthClientInterface;
use Dvsa\Contracts\Auth\ResourceOwnerInterface;
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
     * @see https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminCreateUser.html
     *
     * @throws ClientException when there is an with creating user with the provided credentials.
     */
    public function register(string $identifier, string $password, array $attributes = []): ResourceOwnerInterface
    {
        try {
            $response = $this->client->adminCreateUser([
                'MessageAction' => 'SUPPRESS',
                'TemporaryPassword' => $password,
                'UserAttributes' => $this->formatAttributes($attributes),
                'UserPoolId' => $this->poolId,
                'Username' => $identifier,
            ]);

            return CognitoUser::create(($response->get('User') ?? []));
        } catch (AwsException $e) {
            throw new ClientException((string) $e->getAwsErrorMessage(), (int) $e->getCode(), $e);
        }
    }

    /**
     * @see https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminInitiateAuth.html
     *
     * @throws ChallengeException when a challenge is returned for this user.
     * @throws ClientException when there is an issue with authenticating a user.
     */
    public function authenticate(string $identifier, string $password): AccessTokenInterface
    {
        try {
            $response = $this->client->adminInitiateAuth(
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

            return $this->handleAuthResponse($response->toArray());
        } catch (AwsException $e) {
            throw new ClientException((string) $e->getAwsErrorMessage(), (int) $e->getCode(), $e);
        }
    }

    /**
     * @see https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminRespondToAuthChallenge.html
     *
     * @return \Dvsa\Contracts\Auth\AccessTokenInterface
     *
     * @throws ClientException when there is an issue with authenticating a user.
     * @throws ChallengeException when a challenge is returned for this user.
     */
    public function responseToAuthChallenge(string $challengeName, array $challengeResponses, string $session): AccessTokenInterface
    {
        try {
            $response = $this->client->adminRespondToAuthChallenge(
                [
                    'ChallengeName'      => $challengeName,
                    'ChallengeResponses' => $challengeResponses,
                    'ClientId'           => $this->clientId,
                    'Session'            => $session,
                ]
            );

            return $this->handleAuthResponse($response->toArray());
        } catch (AwsException $e) {
            throw new ClientException((string) $e->getAwsErrorMessage(), (int) $e->getCode(), $e);
        }
    }

    /**
     * @see https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminSetUserPassword.html
     *
     * @throws ClientException when there is an issue with changing a user's password.
     */
    public function changePassword(string $identifier, string $newPassword, bool $permanent = true): bool
    {
        try {
            $this->client->adminSetUserPassword([
                'Username' => $identifier,
                'UserPoolId' => $this->poolId,
                'Password' => $newPassword,
                'Permanent' => $permanent,
            ]);

            return true;
        } catch (AwsException $e) {
            throw new ClientException((string) $e->getAwsErrorMessage(), (int) $e->getCode(), $e);
        }
    }

    /**
     * @throws ClientException when there is an issue with changing a user's attribute.
     */
    public function changeAttribute(string $identifier, string $key, string $value): bool
    {
        return $this->changeAttributes($identifier, [$key => $value]);
    }

    /**
     * @see https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminUpdateUserAttributes.html
     *
     * @throws ClientException when there is an issue with changing a user's attributes.
     */
    public function changeAttributes(string $identifier, array $attributes): bool
    {
        try {
            $this->client->adminUpdateUserAttributes([
                'Username' => $identifier,
                'UserPoolId' => $this->poolId,
                'UserAttributes' => $this->formatAttributes($attributes)
            ]);

            return true;
        } catch (AwsException $e) {
            throw new ClientException((string) $e->getAwsErrorMessage(), (int) $e->getCode(), $e);
        }
    }

    /**
     * @see https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminEnableUser.html
     *
     * @throws ClientException when there is an issue with enabling a user.
     */
    public function enableUser(string $identifier): bool
    {
        try {
            $this->client->adminEnableUser([
                'Username' => $identifier,
                'UserPoolId' => $this->poolId,
            ]);

            return true;
        } catch (AwsException $e) {
            throw new ClientException((string) $e->getAwsErrorMessage(), (int) $e->getCode(), $e);
        }
    }

    /**
     * @see https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminDisableUser.html
     *
     * @throws ClientException when there is an issue with disabling a user.
     */
    public function disableUser(string $identifier): bool
    {
        try {
            $this->client->adminDisableUser([
                'Username' => $identifier,
                'UserPoolId' => $this->poolId,
            ]);

            return true;
        } catch (AwsException $e) {
            throw new ClientException((string) $e->getAwsErrorMessage(), (int) $e->getCode(), $e);
        }
    }

    /**
     * @see https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminGetUser.html
     *
     * @throws ClientException when there is an issue with authenticating a user.
     */
    public function getUserByIdentifier(string $identifier): ResourceOwnerInterface
    {
        try {
            $response = $this->client->adminGetUser([
                'UserPoolId' => $this->poolId,
                'Username' => $identifier
            ]);

            return CognitoUser::create($response->toArray());
        } catch (AwsException $e) {
            throw new ClientException((string) $e->getAwsErrorMessage(), (int) $e->getCode(), $e);
        }
    }

    /**
     * @param  string  $token
     * @param  int     $leeway  When checking nbf, iat or expiration times of tokens,
     *                          we may want to provide some extra leeway time to
     *                          account for clock skew.
     *
     * @return object the decoded token as an object.
     * @throws InvalidTokenException when the token provided is invalid and cannot be decoded.
     */
    public function decodeToken(string $token, int $leeway = 0): object
    {
        try {
            $keySet = $this->getJwtWebKeys();

            JWT::$leeway = $leeway;

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
     * @throws ChallengeException when a challenge is returned for this user.
     * @throws ClientException when there was an issue with refreshing the user's token.
     */
    public function refreshTokens(string $refreshToken, string $identifier): AccessTokenInterface
    {
        try {
            $response = $this->client->adminInitiateAuth([
                'AuthFlow' => 'REFRESH_TOKEN_AUTH',
                'AuthParameters' => [
                    'REFRESH_TOKEN' => $refreshToken,
                    'SECRET_HASH' => $this->cognitoSecretHash($identifier),
                ],
                'ClientId' => $this->clientId,
                'UserPoolId' => $this->poolId,
            ]);

            return $this->handleAuthResponse($response->toArray());
        } catch (AwsException $e) {
            throw new ClientException((string) $e->getAwsErrorMessage(), (int) $e->getCode(), $e);
        }
    }

    public function setJwtWebKeys(array $keys): void
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
                'Name' => (string) $key,
                'Value' => (string) $value,
            ];
        }

        return $userAttributes;
    }

    /**
     * @throws ClientException when an auth response format is malformed.
     * @throws ChallengeException when an auth response returns a challenge.
     */
    protected function handleAuthResponse(array $response): AccessTokenInterface
    {
        if (isset($response['AuthenticationResult'])) {
            return AccessToken::create($response['AuthenticationResult']);
        }

        if (isset($response['ChallengeName'])) {
            throw (new ChallengeException())
                ->setChallengeName($response['ChallengeName'])
                ->setParameters($response['ChallengeParameters'])
                ->setSession($response['Session']);
        }

        throw new ClientException('Invalid AdminInitiateAuth response');
    }
}

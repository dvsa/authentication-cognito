<?php

namespace Dvsa\Authentication\Cognito;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Aws\Exception\AwsException;
use Dvsa\Contracts\Auth\AccessTokenInterface;
use Dvsa\Contracts\Auth\CreatesResourceOwners;
use Dvsa\Contracts\Auth\Exceptions\ChallengeException;
use Dvsa\Contracts\Auth\Exceptions\ClientException;
use Dvsa\Contracts\Auth\Exceptions\InvalidTokenException;
use Dvsa\Contracts\Auth\OAuthClientInterface;
use Dvsa\Contracts\Auth\ResourceOwnerInterface;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Psr7\Response;

class Client implements OAuthClientInterface
{
    use CreatesResourceOwners;

    /**
     * When checking nbf, iat or expiration times on tokens, we want to provide
     * some extra leeway time to account for clock skew.
     *
     * @var int
     */
    public static $leeway = 0;

    /**
     * @var CognitoIdentityProviderClient
     */
    protected $cognitoClient;

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

    /**
     * @var HttpClient
     */
    private $httpClient;

    public function __construct(
        CognitoIdentityProviderClient $cognitoClient,
        string $clientId,
        string $clientSecret,
        string $poolId,
        HttpClient $httpClient
    ) {
        $this->cognitoClient = $cognitoClient;
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->poolId = $poolId;
        $this->httpClient = $httpClient;

        $this->resourceOwnerClass = CognitoUser::class;
    }

    /**
     * @inheritDoc
     *
     * @see https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminCreateUser.html
     */
    public function register(string $identifier, string $password, array $attributes = []): ResourceOwnerInterface
    {
        try {
            $response = $this->cognitoClient->adminCreateUser([
                'MessageAction' => 'SUPPRESS',
                'TemporaryPassword' => $password,
                'UserAttributes' => $this->formatAttributes($attributes),
                'UserPoolId' => $this->poolId,
                'Username' => $identifier,
            ]);

            $attributes = CognitoUser::prepareAwsResponse(($response->get('User') ?? []));

            return $this->createResourceOwner($attributes);
        } catch (AwsException $e) {
            throw new ClientException((string) $e->getAwsErrorMessage(), (int) $e->getCode(), $e);
        }
    }

    /**
     * @inheritDoc
     *
     * @see https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminInitiateAuth.html
     */
    public function authenticate(string $identifier, string $password): AccessTokenInterface
    {
        try {
            $response = $this->cognitoClient->adminInitiateAuth(
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
     * @throws ClientException when there is an issue with authenticating a user.
     * @throws ChallengeException when a challenge is returned for this user.
     */
    public function responseToAuthChallenge(string $challengeName, array $challengeResponses, string $session): AccessTokenInterface
    {
        try {
            $response = $this->cognitoClient->adminRespondToAuthChallenge(
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
     * @inheritDoc
     *
     * @see https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminSetUserPassword.html
     */
    public function changePassword(string $identifier, string $newPassword, bool $permanent = true): bool
    {
        try {
            $this->cognitoClient->adminSetUserPassword([
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
     * @inheritDoc
     */
    public function changeAttribute(string $identifier, string $key, string $value): bool
    {
        return $this->changeAttributes($identifier, [$key => $value]);
    }

    /**
     * @inheritDoc
     *
     * @see https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminUpdateUserAttributes.html
     */
    public function changeAttributes(string $identifier, array $attributes): bool
    {
        try {
            $this->cognitoClient->adminUpdateUserAttributes([
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
     * @inheritDoc
     *
     * @see https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminEnableUser.html
     */
    public function enableUser(string $identifier): bool
    {
        try {
            $this->cognitoClient->adminEnableUser([
                'Username' => $identifier,
                'UserPoolId' => $this->poolId,
            ]);

            return true;
        } catch (AwsException $e) {
            throw new ClientException((string) $e->getAwsErrorMessage(), (int) $e->getCode(), $e);
        }
    }

    /**
     * @inheritDoc
     *
     * @see https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminDisableUser.html
     */
    public function disableUser(string $identifier): bool
    {
        try {
            $this->cognitoClient->adminDisableUser([
                'Username' => $identifier,
                'UserPoolId' => $this->poolId,
            ]);

            return true;
        } catch (AwsException $e) {
            throw new ClientException((string) $e->getAwsErrorMessage(), (int) $e->getCode(), $e);
        }
    }

    /**
     * @inheritDoc
     *
     * @see https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminGetUser.html
     */
    public function getUserByIdentifier(string $identifier): ResourceOwnerInterface
    {
        try {
            $response = $this->cognitoClient->adminGetUser([
                'UserPoolId' => $this->poolId,
                'Username' => $identifier
            ]);

            $attributes = CognitoUser::prepareAwsResponse($response->toArray());

            return $this->createResourceOwner($attributes);
        } catch (AwsException $e) {
            throw new ClientException((string) $e->getAwsErrorMessage(), (int) $e->getCode(), $e);
        }
    }

    /**
     * @inheritDoc
     */
    public function decodeToken(string $token): array
    {
        try {
            $keySet = $this->getJwtWebKeys();

            JWT::$leeway = self::$leeway;

            $tokenClaims = (array) JWT::decode($token, $keySet, ['RS256']);

            $this->validateTokenClaims($tokenClaims);

            return $tokenClaims;
        } catch (\Exception $e) {
            throw new InvalidTokenException($e->getMessage(), (int) $e->getCode(), $e);
        }
    }

    /**
     * @throws InvalidTokenException when claims aren't valid and not to be trusted.
     */
    public function validateTokenClaims(array $tokenClaims): void
    {
        # Additional checks per AWS requirements to verify tokens.
        # https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html
        if (!isset($tokenClaims['token_use']) || !in_array($tokenClaims['token_use'], ['id', 'access'])) {
            throw new InvalidTokenException('"token_use" invalid');
        }

        $expectedIss = sprintf('https://cognito-idp.%s.amazonaws.com/%s', $this->cognitoClient->getRegion(), $this->poolId);
        if (!isset($tokenClaims['iss']) || $tokenClaims['iss'] !== $expectedIss) {
            throw new InvalidTokenException('"iss" invalid');
        }

        # Only applied to Id tokens.
        if ($tokenClaims['token_use'] === 'id') {
            if (!isset($tokenClaims['aud']) || $tokenClaims['aud'] !== $this->clientId) {
                throw new InvalidTokenException('"aud" invalid');
            }
        }
    }

    /**
     * @inheritDoc
     */
    public function getResourceOwner(AccessTokenInterface $token): ResourceOwnerInterface
    {
        // If the ID token is not null, use to build the resource owner.
        // Otherwise, use the claims from the access token.
        if ($idToken = $token->getIdToken()) {
            $tokenClaims = $this->decodeToken($idToken);
        } else {
            $tokenClaims = $this->decodeToken($token->getToken());
        }

        return $this->createResourceOwner($tokenClaims);
    }

    /**
     * @inheritDoc
     *
     * @see https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminInitiateAuth.html
     */
    public function refreshTokens(string $refreshToken, string $identifier): AccessTokenInterface
    {
        try {
            $response = $this->cognitoClient->adminInitiateAuth([
                'AuthFlow' => 'REFRESH_TOKEN_AUTH',
                'AuthParameters' => [
                    'REFRESH_TOKEN' => $refreshToken,
                    'SECRET_HASH' => $this->cognitoSecretHash($identifier),
                ],
                'ClientId' => $this->clientId,
                'UserPoolId' => $this->poolId,
            ]);

            // The response does not contain the refresh token as part of the response.
            // Add the old refresh token here.
            if (isset($response['AuthenticationResult'])) {
                if (!isset($response['AuthenticationResult']['RefreshToken'])) {
                    $response['AuthenticationResult']['RefreshToken'] = $refreshToken;
                }
            }

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
            $this->cognitoClient->getRegion(),
            $this->poolId
        );

        try {
            $response = $this->httpClient->get($url);
        } catch (GuzzleException $e) {
            throw new \Exception(sprintf('Unable to fetch JWT web keys: %s', $e->getMessage()), (int)$e->getCode(), $e);
        }

        if ($response->getStatusCode() !== 200) {
            throw new \Exception(sprintf('Unable to fetch JWT web keys. Status code %d', $response->getStatusCode()));
        }

        $body = $response->getBody()->getContents();
        if (empty($body)) {
            return [];
        }

        $keys = json_decode($body, true);

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
                'Value' => $this->formatAttributeValue($value),
            ];
        }

        return $userAttributes;
    }

    /**
     * @param mixed $value
     *
     * @return string
     */
    protected function formatAttributeValue($value): string
    {
        if (is_bool($value)) {
            return $value ? 'true' : 'false';
        }

        if ($value instanceof \DateTimeInterface) {
            return $value->format('Y-m-d H:i:s e');
        }

        return (string) $value;
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

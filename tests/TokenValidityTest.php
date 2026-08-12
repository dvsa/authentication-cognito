<?php

declare(strict_types=1);

namespace Dvsa\Authentication\Cognito\Tests;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Dvsa\Authentication\Cognito\Client;
use Dvsa\Contracts\Auth\Exceptions\InvalidTokenException;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Handler\MockHandler as MockHttpHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Request;
use ArrayObject;
use PHPUnit\Framework\TestCase;
use RuntimeException;

class TokenValidityTest extends TestCase
{
    protected const KID = '1234example=';

    protected const REGION = 'eu-west-2';

    protected const POOL_ID = 'POOL_ID';

    /**
     * Signing key material is generated per run rather than committed. These tests need a private
     * key to mint tokens with and the matching public key to verify them against, and a real key
     * pair in the repository is both a secret-scanning liability and something that quietly rots.
     * Generating one costs a few hundred milliseconds once per class.
     */
    protected static string $privateKey;

    /**
     * @var array<string, mixed> JWKS built from the public half of {@see self::$privateKey}.
     */
    protected static array $jwks;

    protected Client $client;

    protected MockHttpHandler $mockHttpHandler;

    public static function setUpBeforeClass(): void
    {
        $key = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        if (false === $key) {
            throw new RuntimeException('Unable to generate a test key pair: ' . openssl_error_string());
        }

        openssl_pkey_export($key, $privateKey);

        $details = openssl_pkey_get_details($key);

        if (false === $details) {
            throw new RuntimeException('Unable to read the generated test key: ' . openssl_error_string());
        }

        static::$privateKey = $privateKey;

        static::$jwks = [
            'keys' => [[
                'kid' => static::KID,
                'alg' => 'RS256',
                'kty' => 'RSA',
                'e' => static::base64UrlEncode($details['rsa']['e']),
                'n' => static::base64UrlEncode($details['rsa']['n']),
                'use' => 'sig',
            ]],
        ];
    }

    protected function setUp(): void
    {
        $cognitoIdentityProviderMock = $this->createMock(CognitoIdentityProviderClient::class);

        $cognitoIdentityProviderMock->method('getRegion')->willReturn(static::REGION);
        $cognitoIdentityProviderMock->method('getEndpoint')
            ->willReturn(sprintf('https://cognito-idp.%s.amazonaws.com', static::REGION));

        $this->client = new Client($cognitoIdentityProviderMock, 'CLIENT_ID', 'CLIENT_SECRET', static::POOL_ID);

        $this->client->setJwtWebKeys(new ArrayObject(JWK::parseKeySet(static::$jwks)));
    }

    public function testWillDecodeCompliantJwt(): void
    {
        $payload = [
            "kid" => static::KID,
            "alg" => "RS256",
            "aud" => static::POOL_ID,
            "iss" => $this->issuer(),
            "token_use" => 'access',
        ];

        $encoded = JWT::encode($payload, static::$privateKey, 'RS256', static::KID);

        $jwt = $this->client->decodeToken($encoded);

        $this->assertEquals($payload, (array) $jwt);
    }

    public function testDecodeWillThrowExceptionWhenUnexpectedIss(): void
    {
        $payload = [
            "kid" => static::KID,
            "alg" => "RS256",
            "aud" => static::POOL_ID,
            "iss" => "https://example.org", // Intentionally incorrect "iss".
            "token_use" => 'access',
        ];

        $encoded = JWT::encode($payload, static::$privateKey, 'RS256', static::KID);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('"iss" invalid');

        $this->client->decodeToken($encoded);
    }

    public function testDecodeWillThrowExceptionWhenUnexpectedTokenUse(): void
    {
        $payload = [
            "kid" => static::KID,
            "alg" => "RS256",
            "aud" => static::POOL_ID,
            "iss" => $this->issuer(),
            "token_use" => 'not_expected',
        ];

        $encoded = JWT::encode($payload, static::$privateKey, 'RS256', static::KID);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('"token_use" invalid');

        $this->client->decodeToken($encoded);
    }

    public function testDecodeWillThrowExceptionWhenUnexpectedAud(): void
    {
        $payload = [
            "kid" => static::KID,
            "alg" => "RS256",
            "aud" => "NOT_POOL_ID",
            "iss" => $this->issuer(),
            "token_use" => 'id',
        ];

        $encoded = JWT::encode($payload, static::$privateKey, 'RS256', static::KID);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('"aud" invalid');

        $this->client->decodeToken($encoded);
    }

    public function testDecodeWillThrowExceptionWhenUnableToFetchJwtWebKeys(): void
    {
        $this->client->setJwtWebKeys(null);

        $mockHttpHandler = new MockHttpHandler();
        $exceptionMessage = 'Error Communicating with Server';
        $mockHttpHandler->append(new RequestException($exceptionMessage, new Request('GET', 'test')));
        $handlerStack = HandlerStack::create($mockHttpHandler);
        $httpClient = new HttpClient(['handler' => $handlerStack]);

        $this->client->setHttpClient($httpClient);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage($exceptionMessage);

        $this->client->decodeToken('');
    }

    protected function issuer(): string
    {
        return sprintf('https://cognito-idp.%s.amazonaws.com/%s', static::REGION, static::POOL_ID);
    }

    /**
     * JWKS carries the modulus and exponent base64url encoded, which is not what base64_encode
     * produces.
     */
    protected static function base64UrlEncode(string $binary): string
    {
        return rtrim(strtr(base64_encode($binary), '+/', '-_'), '=');
    }
}

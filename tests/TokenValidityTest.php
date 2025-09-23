<?php

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
use Illuminate\Support\Collection;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

class TokenValidityTest extends TestCase
{
    const PRIVATE_KEY = <<<EOF
-----BEGIN RSA PRIVATE KEY-----
    // load a sample key in from environment 
-----END RSA PRIVATE KEY-----
EOF;

    protected Client $client;

    protected MockHttpHandler $mockHttpHandler;

    protected function setUp(): void
    {
        $cognitoIdentityProviderMock = $this->createMock(CognitoIdentityProviderClient::class);

        $cognitoIdentityProviderMock->method('getRegion')->willReturn('eu-west-2');
        $cognitoIdentityProviderMock->method('getEndpoint')->willReturn('https://cognito-idp.eu-west-2.amazonaws.com');

        $this->client = new Client($cognitoIdentityProviderMock, 'CLIENT_ID', 'CLIENT_SECRET', 'POOL_ID');

        $this->client->setJwtWebKeys(
            new Collection(
                JWK::parseKeySet([
                    'keys' => [[
                        "kid" => "1234example=",
                        "alg" => "RS256",
                        "kty" => "RSA",
                        "e" => "AQAB",
                        "n" => "0Ttga33B1yX4w77NbpKyNYDNSVCo8j-RlZaZ9tI-KfkV1d-tfsvI9ZPAheP11FoN52ceBaY5ltelHW-IKwCfyT0orLdsxLgowaXki9woF1Azvcg2JVxQLv9aVjjAvy3CZFIG_EeN7J3nsyCXGnu1yMEbnvkWxA88__Q6HQ2K9wqfApkQ0LNlsK0YHz_sfjHNvRKxnbAJk7D5fUhZunPZXOPHXFgA5SvLvMaNIXduMKJh4OMfuoLdJowXJAR9j31Mqz_is4FMhm_9Mq7vZZ-uF09htRvIR8tRY28oJuW1gKWyg7cQQpnjHgFyG3XLXWAeXclWqyh_LfjyHQjrYhyeFw",
                        "use" => "sig",
                    ]]
                ])
            )
        );
    }

    public function testWillDecodeCompliantJwt(): void
    {
        $payload = [
            "kid" => "1234example=",
            "alg" => "RS256",
            "aud" => "POOL_ID",
            "iss" => sprintf('https://cognito-idp.%s.amazonaws.com/%s', 'eu-west-2', 'POOL_ID'),
            "token_use" => 'access',
        ];

        $encoded = JWT::encode($payload, self::PRIVATE_KEY, 'RS256', '1234example=');

        $jwt = $this->client->decodeToken($encoded);

        $this->assertEquals($payload, (array) $jwt);
    }

    public function testDecodeWillThrowExceptionWhenUnexpectedIss(): void
    {
        $payload = [
            "kid" => "1234example=",
            "alg" => "RS256",
            "aud" => "POOL_ID",
            "iss" => "https://example.org", // Intentionally incorrect "iss".
            "token_use" => 'access',
        ];

        $encoded = JWT::encode($payload, self::PRIVATE_KEY, 'RS256', '1234example=');

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('"iss" invalid');

        $this->client->decodeToken($encoded);
    }

    public function testDecodeWillThrowExceptionWhenUnexpectedTokenUse(): void
    {
        $payload = [
            "kid" => "1234example=",
            "alg" => "RS256",
            "aud" => "POOL_ID",
            "iss" => sprintf('https://cognito-idp.%s.amazonaws.com/%s', 'eu-west-2', 'POOL_ID'),
            "token_use" => 'not_expected',
        ];

        $encoded = JWT::encode($payload, self::PRIVATE_KEY, 'RS256', '1234example=');

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('"token_use" invalid');

        $this->client->decodeToken($encoded);
    }

    public function testDecodeWillThrowExceptionWhenUnexpectedAud(): void
    {
        $payload = [
            "kid" => "1234example=",
            "alg" => "RS256",
            "aud" => "NOT_POOL_ID",
            "iss" => sprintf('https://cognito-idp.%s.amazonaws.com/%s', 'eu-west-2', 'POOL_ID'),
            "token_use" => 'id',
        ];

        $encoded = JWT::encode($payload, self::PRIVATE_KEY, 'RS256', '1234example=');

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
        $this->expectErrorMessage($exceptionMessage);

        $this->client->decodeToken('');
    }
}

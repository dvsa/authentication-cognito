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
MIIEowIBAAKCAQEA0Ttga33B1yX4w77NbpKyNYDNSVCo8j+RlZaZ9tI+KfkV1d+t
fsvI9ZPAheP11FoN52ceBaY5ltelHW+IKwCfyT0orLdsxLgowaXki9woF1Azvcg2
JVxQLv9aVjjAvy3CZFIG/EeN7J3nsyCXGnu1yMEbnvkWxA88//Q6HQ2K9wqfApkQ
0LNlsK0YHz/sfjHNvRKxnbAJk7D5fUhZunPZXOPHXFgA5SvLvMaNIXduMKJh4OMf
uoLdJowXJAR9j31Mqz/is4FMhm/9Mq7vZZ+uF09htRvIR8tRY28oJuW1gKWyg7cQ
QpnjHgFyG3XLXWAeXclWqyh/LfjyHQjrYhyeFwIDAQABAoIBAHMqdJsWAGEVNIVB
+792HYNXnydQr32PwemNmLeD59WglgU/9jZJoxaROjI4VLKK0wZg+uRvJ1nA3tCB
+Hh7Anh5Im9XExaAq2ZTkqXtC2AxtBktH6iW1EfaI/Y7jNRuMoaXo+Ku3A62p7cw
JBvepiOXL0Xko0RNguz7mBUvxCLPhYhzn7qCbM8uXLcjsXq/YhWQwQmtMqv0sd3W
Hy+8Jb2c18sqDeZIBne4dWD6qPClPEOsrq9gPTkl0DjbT27oVc2u1p4HMNm5BJIh
u3rMSxnZHUd7Axj1FgyLIOHl63UhaiaA1aPe/fLiVIGOA1jBZrpbnjgqDy9Uxyn6
eydbiwECgYEA9mtRydz22idyUOlBCDXk+vdGBvFAucNYaNNUAXUJ2wfPmdGgFCA7
g5eQG8JC6J/FU+2AfIuz6LGr7SxMBYcsWGjFAzGqs/sJib+zzN1dPUSRn4uJNFit
51yQzPgBqHS6S/XBi6YAODeZDl9jiPl3FxxucqLY5NstqZFXbE0SjIECgYEA2V3r
7xnRAK1krY1+zkPof4kcBmjqOXjnl/oRxlXP65lEXmyNJwm/ulOIko9mElWRs8CG
AxSWKaab9Gk6lc8MHjVRbuW52RGLGKq1mp6ENr4d3IBOfrNsTvD3gtNEN1JFLeF1
jIbSsrbi2txr7VZ06Irac0C/ytro0QDOUoXkvpcCgYA8O0EzmToRWsD7e/g0XJAK
s/Q+8CtE/LWYccc/z+7HxeH9lBqPsM07Pgmwb0xRdfQSrqPQTYl9ICiJAWHXnBG/
zmQRgstZ0MulCuGU+qq2thLuL3oq/F4NhjeykhA9r8J1nK1hSAMXuqdDtxcqPOfa
E03/4UQotFY181uuEiytgQKBgHQT+gjHqptH/XnJFCymiySAXdz2bg6fCF5aht95
t/1C7gXWxlJQnHiuX0KVHZcw5wwtBePjPIWlmaceAtE5rmj7ZC9qsqK/AZ78mtql
SEnLoTq9si1rN624dRUCKW25m4Py4MlYvm/9xovGJkSqZOhCLoJZ05JK8QWb/pKH
Oi6lAoGBAOUN6ICpMQvzMGPgIbgS0H/gvRTnpAEs59vdgrkhlCII4tzfgvBQlVae
hRcdM6GTMq5pekBPKu45eanIzwVc88P6coT4qiWYKk2jYoLBa0UV3xEAuqBMymrj
X4nLcSbZtO0tcDGMfMpWF2JGYOEJQNetPozL/ICGVFyIO8yzXm8U
-----END RSA PRIVATE KEY-----
EOF;

    protected Client $client;

    protected MockHttpHandler $mockHttpHandler;

    protected function setUp(): void
    {
        $cognitoIdentityProviderMock = $this->createMock(CognitoIdentityProviderClient::class);

        $cognitoIdentityProviderMock->method('getRegion')->willReturn('eu-west-2');

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

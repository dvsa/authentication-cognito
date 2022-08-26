<?php

namespace Dvsa\Authentication\Cognito\Tests;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Aws\Credentials\Credentials;
use Aws\MockHandler as AwsMockHandler;
use Dvsa\Authentication\Cognito\Client;
use Firebase\JWT\CachedKeySet;
use Firebase\JWT\JWK;
use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Handler\MockHandler as MockHttpHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Illuminate\Support\Collection;
use PHPUnit\Framework\TestCase;
use Psr\Cache\CacheItemPoolInterface;

class CachedJWKUsedWhenProvidedWithPSR6InterfaceTest extends TestCase
{
    protected AwsMockHandler $mockHandler;

    protected Client $client;

    protected function setUp(): void
    {
        $this->mockHandler = new AwsMockHandler();

        $awsCredentials = new Credentials('AWS_ACCESS_KEY', 'AWS_SECRET_KEY');

        $cognitoIdentityProviderClient = new CognitoIdentityProviderClient([
            'credentials' => $awsCredentials,
            'region'  => 'us-west-2',
            'version' => 'latest',
            'handler' => $this->mockHandler
        ]);

        $this->client = new Client($cognitoIdentityProviderClient, 'CLIENT_ID', 'CLIENT_SECRET', 'POOL_ID');

        $handlerStack = HandlerStack::create(new MockHttpHandler());
        $httpClient = new HttpClient(['handler' => $handlerStack]);
        $this->client->setHttpClient($httpClient);
    }

    public function testCachedJwkUsedWhenCacheInterfaceSet(): void
    {
        $cache = $this->createMock(CacheItemPoolInterface::class);

        $this->client->setCache($cache);

        $jwk = $this->client->getJwtWebKeys();

        $this->assertInstanceOf(CachedKeySet::class, $jwk);
    }

    public function testJwkRetrievedEachRequestWhenCacheInterfaceNotSet(): void
    {
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

        $mockHttpHandler = new MockHttpHandler();
        $mockHttpHandler->append(new Response(200, [], json_encode([])));
        $handlerStack = HandlerStack::create($mockHttpHandler);
        $httpClient = new HttpClient(['handler' => $handlerStack]);

        $this->client->setHttpClient($httpClient);

        $jwk = $this->client->getJwtWebKeys();

        $this->assertInstanceOf(Collection::class, $jwk);
    }
}

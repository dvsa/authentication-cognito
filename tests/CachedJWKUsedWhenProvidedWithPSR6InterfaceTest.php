<?php

declare(strict_types=1);

namespace Dvsa\Authentication\Cognito\Tests;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Aws\Credentials\Credentials;
use Aws\MockHandler as AwsMockHandler;
use Dvsa\Authentication\Cognito\Client;
use Firebase\JWT\CachedKeySet;
use Firebase\JWT\JWK;
use Firebase\JWT\Key;
use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Handler\MockHandler as MockHttpHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use ArrayObject;
use PHPUnit\Framework\TestCase;
use Psr\Cache\CacheItemPoolInterface;

class CachedJWKUsedWhenProvidedWithPSR6InterfaceTest extends TestCase
{
    protected const KID = '1234example=';

    protected const JWKS = [
        'keys' => [[
            'kid' => self::KID,
            'alg' => 'RS256',
            'kty' => 'RSA',
            'e' => 'AQAB',
            'n' => '0Ttga33B1yX4w77NbpKyNYDNSVCo8j-RlZaZ9tI-KfkV1d-tfsvI9ZPAheP11FoN52ceBaY5ltelHW-IKwCfyT0orLdsxLgowaXki9woF1Azvcg2JVxQLv9aVjjAvy3CZFIG_EeN7J3nsyCXGnu1yMEbnvkWxA88__Q6HQ2K9wqfApkQ0LNlsK0YHz_sfjHNvRKxnbAJk7D5fUhZunPZXOPHXFgA5SvLvMaNIXduMKJh4OMfuoLdJowXJAR9j31Mqz_is4FMhm_9Mq7vZZ-uF09htRvIR8tRY28oJuW1gKWyg7cQQpnjHgFyG3XLXWAeXclWqyh_LfjyHQjrYhyeFw',
            'use' => 'sig',
        ]],
    ];

    protected AwsMockHandler $mockHandler;

    protected MockHttpHandler $mockHttpHandler;

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

        $this->mockHttpHandler = new MockHttpHandler();
        $handlerStack = HandlerStack::create($this->mockHttpHandler);
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

    /**
     * The branch every consumer without a configured cache takes: fetch the JWKS over HTTP and
     * parse it, on each request.
     *
     * This had no coverage. The test that appeared to cover it pre-populated the keys through
     * setJwtWebKeys() first, so getJwtWebKeys() returned early and no request was ever made —
     * the queued response went unconsumed and the assertion only confirmed the type of the
     * object the test had just handed in.
     */
    public function testJwksIsDownloadedAndParsedWhenNoCacheIsConfigured(): void
    {
        $this->mockHttpHandler->append(new Response(200, [], json_encode(static::JWKS)));

        $keys = $this->client->getJwtWebKeys();

        $request = $this->mockHttpHandler->getLastRequest();

        $this->assertNotNull($request, 'Expected the JWKS to be fetched over HTTP.');
        $this->assertSame('GET', $request->getMethod());
        $this->assertStringEndsWith('/POOL_ID/.well-known/jwks.json', (string) $request->getUri());

        $this->assertInstanceOf(ArrayObject::class, $keys);
        $this->assertArrayHasKey(static::KID, $keys);
        $this->assertInstanceOf(Key::class, $keys[static::KID]);
    }

    /**
     * The counterpart, and what the previous "retrieved each request" test was really
     * exercising. Worth pinning, but the interesting assertion is the absence of a request.
     */
    public function testPreloadedJwtWebKeysAreUsedWithoutDownloading(): void
    {
        $this->client->setJwtWebKeys(new ArrayObject(JWK::parseKeySet(static::JWKS)));

        $this->mockHttpHandler->append(new Response(200, [], json_encode(static::JWKS)));

        $keys = $this->client->getJwtWebKeys();

        $this->assertNull($this->mockHttpHandler->getLastRequest(), 'Expected no JWKS request.');
        $this->assertCount(1, $this->mockHttpHandler, 'Queued response should be unconsumed.');
        $this->assertInstanceOf(ArrayObject::class, $keys);
    }
}

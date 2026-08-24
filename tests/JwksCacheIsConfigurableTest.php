<?php

namespace Dvsa\Authentication\Cognito\Tests;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Dvsa\Authentication\Cognito\Client;
use Firebase\JWT\CachedKeySet;
use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Handler\MockHandler as MockHttpHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Cache\CacheItemPoolInterface;

class JwksCacheIsConfigurableTest extends TestCase
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

    /** @var array<int, array<string, mixed>> */
    protected array $requests = [];

    protected InMemoryCacheItemPool $pool;

    protected function setUp(): void
    {
        $this->requests = [];
        $this->pool = new InMemoryCacheItemPool();
    }

    public function testCacheProvidedViaTheConstructorIsUsed(): void
    {
        $client = $this->makeClient($this->pool);

        $this->assertInstanceOf(CachedKeySet::class, $client->getJwtWebKeys());
    }

    public function testSetCacheContinuesToWork(): void
    {
        $client = $this->makeClient();
        $client->setCache($this->pool);

        $this->assertInstanceOf(CachedKeySet::class, $client->getJwtWebKeys());
    }

    public function testNoCacheStillFallsBackToAnUncachedDownload(): void
    {
        $client = $this->makeClient();

        $this->assertNotInstanceOf(CachedKeySet::class, $client->getJwtWebKeys());
    }

    public function testCachedJwksIsStoredWithTheDefaultTtl(): void
    {
        $client = $this->makeClient($this->pool);

        $this->lookUp($client, static::KID);

        $this->assertSame(Client::DEFAULT_JWKS_CACHE_TTL, $this->jwksItemExpiry());
    }

    public function testTheTtlCanBeOverridden(): void
    {
        $client = $this->makeClient($this->pool);
        $client->setCacheOptions(60);

        $this->lookUp($client, static::KID);

        $this->assertSame(60, $this->jwksItemExpiry());
    }

    /**
     * Opting out is legitimate — it hands the decision to the pool's own default lifetime — but it
     * has to be explicit rather than the default, hence this test pins the null case separately.
     */
    public function testANullTtlDefersToThePoolsOwnLifetime(): void
    {
        $client = $this->makeClient($this->pool);
        $client->setCacheOptions(null);

        $this->lookUp($client, static::KID);

        $this->assertNull($this->jwksItemExpiry());
    }

    public function testRateLimitingIsOnByDefault(): void
    {
        $client = $this->makeClient($this->pool);

        $this->lookUpUnknownKeyIds($client, 15);

        // Firebase\JWT\CachedKeySet caps re-fetches at 10 per minute.
        $this->assertCount(10, $this->requests);
    }

    public function testRateLimitingCanBeDisabled(): void
    {
        $client = $this->makeClient($this->pool);
        $client->setCacheOptions(rateLimit: false);

        $this->lookUpUnknownKeyIds($client, 15);

        $this->assertCount(15, $this->requests);
    }

    protected function makeClient(?CacheItemPoolInterface $cache = null): Client
    {
        $cognitoIdentityProviderMock = $this->createMock(CognitoIdentityProviderClient::class);

        $cognitoIdentityProviderMock->method('getEndpoint')
            ->willReturn('https://cognito-idp.eu-west-2.amazonaws.com');

        $client = new Client($cognitoIdentityProviderMock, 'CLIENT_ID', 'CLIENT_SECRET', 'POOL_ID', $cache);

        $mockHttpHandler = new MockHttpHandler();

        for ($i = 0; $i < 30; $i++) {
            $mockHttpHandler->append(new Response(200, [], json_encode(static::JWKS)));
        }

        $handlerStack = HandlerStack::create($mockHttpHandler);
        $handlerStack->push(Middleware::history($this->requests));

        $client->setHttpClient(new HttpClient(['handler' => $handlerStack]));

        return $client;
    }

    /**
     * CachedKeySet is lazy — building it performs no I/O, so a lookup is what actually drives the
     * download-and-store path under test.
     */
    protected function lookUp(Client $client, string $keyId): bool
    {
        $keySet = $client->getJwtWebKeys();

        return isset($keySet[$keyId]);
    }

    protected function lookUpUnknownKeyIds(Client $client, int $count): void
    {
        for ($i = 0; $i < $count; $i++) {
            $this->lookUp($client, 'unknown-key-id-' . $i);
        }
    }

    /**
     * CachedKeySet derives its own cache keys, so the JWKS entry has to be identified by its
     * contents rather than asked for by name.
     */
    protected function jwksItemExpiry(): ?int
    {
        foreach ($this->pool->items() as $item) {
            $value = $item->get();

            if (is_array($value) && array_key_exists(static::KID, $value)) {
                return $item->getExpiresAfter();
            }
        }

        $this->fail('No cached JWKS entry was written to the pool.');
    }
}

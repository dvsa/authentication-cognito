<?php

namespace Dvsa\Authentication\Cognito\Tests;

use DateInterval;
use DateTimeImmutable;
use Psr\Cache\CacheItemInterface;

/**
 * Parameter types are deliberately omitted throughout. psr/cache ^1.0 declares these methods
 * without types and ^3.0 declares them with types, and this library supports both. Widening a
 * parameter type is legal in PHP while narrowing is not, so untyped parameters paired with typed
 * returns satisfy either version — which matters because CI runs a prefer-lowest matrix.
 */
class InMemoryCacheItem implements CacheItemInterface
{
    protected bool $isHit = false;

    /** @var mixed */
    protected $value = null;

    protected ?int $expiresAfter = null;

    public function __construct(protected string $key)
    {
    }

    public function getKey(): string
    {
        return $this->key;
    }

    public function get(): mixed
    {
        return $this->value;
    }

    public function isHit(): bool
    {
        return $this->isHit;
    }

    public function set($value): static
    {
        $this->value = $value;
        $this->isHit = true;

        return $this;
    }

    public function expiresAt($expiration): static
    {
        return $this;
    }

    public function expiresAfter($time): static
    {
        if ($time instanceof DateInterval) {
            $now = new DateTimeImmutable();
            $time = $now->add($time)->getTimestamp() - $now->getTimestamp();
        }

        $this->expiresAfter = $time;

        return $this;
    }

    /**
     * Not part of PSR-6. The interface offers no way to read a TTL back, so tests need this to
     * assert the expiry the client actually asked for.
     */
    public function getExpiresAfter(): ?int
    {
        return $this->expiresAfter;
    }
}

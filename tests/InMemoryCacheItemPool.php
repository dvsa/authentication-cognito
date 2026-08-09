<?php

namespace Dvsa\Authentication\Cognito\Tests;

use Psr\Cache\CacheItemInterface;
use Psr\Cache\CacheItemPoolInterface;

/**
 * Minimal in-memory PSR-6 pool, enough for the handful of operations Firebase\JWT\CachedKeySet
 * performs. Items are returned by reference rather than as fresh copies, which is not strictly
 * PSR-6 but keeps the double small and models the only thing these tests care about: state
 * surviving between a save and a later read.
 *
 * See {@see InMemoryCacheItem} for why the parameter types are omitted.
 */
class InMemoryCacheItemPool implements CacheItemPoolInterface
{
    /** @var array<string, InMemoryCacheItem> */
    protected array $items = [];

    public function getItem($key): CacheItemInterface
    {
        return $this->items[$key] ??= new InMemoryCacheItem($key);
    }

    public function getItems(array $keys = []): iterable
    {
        $items = [];

        foreach ($keys as $key) {
            $items[$key] = $this->getItem($key);
        }

        return $items;
    }

    public function hasItem($key): bool
    {
        return $this->getItem($key)->isHit();
    }

    public function clear(): bool
    {
        $this->items = [];

        return true;
    }

    public function deleteItem($key): bool
    {
        unset($this->items[$key]);

        return true;
    }

    public function deleteItems(array $keys): bool
    {
        foreach ($keys as $key) {
            $this->deleteItem($key);
        }

        return true;
    }

    public function save(CacheItemInterface $item): bool
    {
        $this->items[$item->getKey()] = $item;

        return true;
    }

    public function saveDeferred(CacheItemInterface $item): bool
    {
        return $this->save($item);
    }

    public function commit(): bool
    {
        return true;
    }

    /**
     * Not part of PSR-6. CachedKeySet derives its own cache keys, so tests cannot ask for the
     * JWKS entry by name — they have to go looking for it.
     *
     * @return array<string, InMemoryCacheItem>
     */
    public function items(): array
    {
        return $this->items;
    }
}

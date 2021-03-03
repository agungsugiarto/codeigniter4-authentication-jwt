<?php

/**
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 * (c) Agung Sugiarto <me.agungsugiarto@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Fluent\JWTAuth\Providers\Storage;

use CodeIgniter\Cache\CacheInterface;
use Fluent\JWTAuth\Contracts\Providers\Storage;

class Illuminate implements Storage
{
    /**
     * The cache repository contract.
     *
     * @var CacheInterface
     */
    protected $cache;

    /**
     * @return void
     */
    public function __construct(CacheInterface $cache)
    {
        $this->cache = $cache;
    }

    /**
     * Add a new item into storage.
     *
     * @param  string  $key
     * @param  mixed  $value
     * @param  int  $minutes
     * @return void
     */
    public function add($key, $value, $minutes)
    {
        $this->cache->save($key, $value, $minutes);
    }

    /**
     * Add a new item into storage forever.
     *
     * @param  string  $key
     * @param  mixed  $value
     * @return void
     */
    public function forever($key, $value)
    {
        $this->cache->save($key, $value, 0);
    }

    /**
     * Get an item from storage.
     *
     * @param  string  $key
     * @return mixed
     */
    public function get($key)
    {
        return $this->cache->get($key);
    }

    /**
     * Remove an item from storage.
     *
     * @param  string  $key
     * @return bool
     */
    public function destroy($key)
    {
        return $this->cache->delete($key);
    }

    /**
     * Remove all items associated with the tag.
     *
     * @return void
     */
    public function flush()
    {
        $this->cache->clean();
    }
}

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

namespace Fluent\JWTAuth\Contracts\Providers;

interface StorageInterface
{
    /**
     * @param  string  $key
     * @param  mixed  $value
     * @param  int  $minutes
     * @return void
     */
    public function add($key, $value, $minutes);

    /**
     * @param  string  $key
     * @param  mixed  $value
     * @return void
     */
    public function forever($key, $value);

    /**
     * @param  string  $key
     * @return mixed
     */
    public function get($key);

    /**
     * @param  string  $key
     * @return bool
     */
    public function destroy($key);

    /**
     * @return void
     */
    public function flush();
}

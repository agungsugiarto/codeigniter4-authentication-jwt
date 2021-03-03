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

namespace Fluent\JWTAuth\Support;

trait CustomClaimsTrait
{
    /**
     * Custom claims.
     *
     * @var array
     */
    protected $customClaims = [];

    /**
     * Set the custom claims.
     *
     * @param  array  $CustomClaims
     * @return $this
     */
    public function customClaims(array $customClaims)
    {
        $this->customClaims = $customClaims;

        return $this;
    }

    /**
     * Alias to set the custom claims.
     *
     * @param  array  $CustomClaims
     * @return $this
     */
    public function claims(array $CustomClaims)
    {
        return $this->customClaims($CustomClaims);
    }

    /**
     * Get the custom claims.
     *
     * @return array
     */
    public function getCustomClaims()
    {
        return $this->customClaims;
    }
}

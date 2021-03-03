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

namespace Fluent\JWTAuth\Validators;

use Fluent\JWTAuth\Contracts\ValidatorInterface;
use Fluent\JWTAuth\Exceptions\JWTException;
use Fluent\JWTAuth\Support\RefreshFlowTrait;

abstract class AbstractValidator implements ValidatorInterface
{
    use RefreshFlowTrait;

    /**
     * Helper function to return a boolean.
     *
     * @param  array  $value
     * @return bool
     */
    public function isValid($value)
    {
        try {
            $this->check($value);
        } catch (JWTException $e) {
            return false;
        }

        return true;
    }

    /**
     * Run the validation.
     *
     * @param  array  $value
     * @return void
     */
    abstract public function check($value);
}

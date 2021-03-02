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

namespace Fluent\JWTAuth\Claims;

use Fluent\JWTAuth\Claims\Claim;
use Tightenco\Collect\Support\Collection as IlluminateCollection;

use function array_shift;
use function call_user_func_array;
use function count;
use function func_get_args;
use function is_string;
use function ucfirst;

class Collection extends IlluminateCollection
{
    /**
     * Create a new collection.
     *
     * @param  mixed  $items
     * @return void
     */
    public function __construct($items = [])
    {
        parent::__construct($this->getArrayableItems($items));
    }

    /**
     * Get a Claim instance by it's unique name.
     *
     * @param  string  $name
     * @param  mixed  $default
     * @return Claim
     */
    public function getByClaimName($name, ?callable $callback = null, $default = null)
    {
        return $this->filter(function (Claim $claim) use ($name) {
            return $claim->getName() === $name;
        })->first($callback, $default);
    }

    /**
     * Validate each claim under a given context.
     *
     * @param  string  $context
     * @return $this
     */
    public function validate($context = 'payload')
    {
        $args = func_get_args();
        array_shift($args);

        $this->each(function ($claim) use ($context, $args) {
            call_user_func_array(
                [$claim, 'validate' . ucfirst($context)],
                $args
            );
        });

        return $this;
    }

    /**
     * Determine if the Collection contains all of the given keys.
     *
     * @param  mixed  $claims
     * @return bool
     */
    public function hasAllClaims($claims)
    {
        return count($claims) && (new static($claims))->diff($this->keys())->isEmpty();
    }

    /**
     * Get the claims as key/val array.
     *
     * @return array
     */
    public function toPlainArray()
    {
        return $this->map(function (Claim $claim) {
            return $claim->getValue();
        })->toArray();
    }

    /**
     * {@inheritdoc}
     */
    protected function getArrayableItems($items)
    {
        return $this->sanitizeClaims($items);
    }

    /**
     * Ensure that the given claims array is keyed by the claim name.
     *
     * @param  mixed  $items
     * @return array
     */
    private function sanitizeClaims($items)
    {
        $claims = [];
        foreach ($items as $key => $value) {
            if (! is_string($key) && $value instanceof Claim) {
                $key = $value->getName();
            }

            $claims[$key] = $value;
        }

        return $claims;
    }
}
